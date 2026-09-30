package main

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/openai"
)

// noResultsAnswer is the plain-text statement that nothing was found. AnswerLoop
// does not stream or return it as an answer; it is what non-interactive callers
// (MCP, --json) report for ErrNoResults.
const noResultsAnswer = "No relevant sources were found in the knowledge base or " +
	"web search for this question, so no grounded answer can be given."

// ErrNoResults is returned by AnswerLoop when retrieval, the optional web
// fallback, and any rewrite produced nothing to answer from. Nothing is
// streamed and no LLM synthesis runs. Callers check it with errors.Is and
// present it as a warning with next steps, not as an answer.
var ErrNoResults = errors.New("no results")

// Stage names passed to AnswerOpts.Stage, in the order AnswerLoop enters them.
const (
	stageRetrieving = "retrieving"
	stageGrading    = "grading"
	stageWeb        = "searching web"
	stageRewriting  = "rewriting query"
	stageAnswering  = "answering"
)

// searcher is the retrieval surface AnswerLoop needs. *retrieval.Client
// satisfies it; tests substitute a fake.
type searcher interface {
	Search(ctx context.Context, query string, topK int, filter map[string]any) ([]retrieval.Result, error)
}

// webSearch is the web fallback, a variable so tests do not touch the network.
var webSearch = tavilySearch

// rag.go is the single bounded RAG answer loop (AnswerLoop): retrieve, grade
// sufficiency, optionally web-search or rewrite-and-re-retrieve, then stream a
// grounded, cited synthesis. It is the only answer path; ask, the TUI, and the
// MCP server all use it.

// cveQueryPattern and pocQueryPattern spot a CVE id and a proof-of-concept or
// exploit request.
var (
	cveQueryPattern = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
	pocQueryPattern = regexp.MustCompile(`(?i)\bpoc\b|proof[- ]of[- ]concept|\bexploit\b`)
)

// looksLikeCVEorPoC reports whether a query names a CVE or asks about a
// proof-of-concept or exploit. Such a query is routed to web search regardless
// of what the grader says, since a local KB snapshot would not contain current
// CVE or PoC information.
func looksLikeCVEorPoC(query string) bool {
	return cveQueryPattern.MatchString(query) || pocQueryPattern.MatchString(query)
}

// nextAction is the pure loop-control decision, extracted so it can be unit
// tested without any LLM or network dependency. The loop wants the web when the
// grader asks for it, the query looks like a CVE or PoC question, or retrieval
// found nothing, and gets it only when a Tavily key is configured;
// grade.Sufficient always wins first.
func nextAction(g grade, hasTavily, looksCVE bool, results int) string {
	if g.Sufficient {
		return "sufficient"
	}
	wantsWeb := g.UseWeb || looksCVE || results == 0
	if wantsWeb && hasTavily {
		return "web"
	}
	return "rewrite"
}

// AnswerOpts carries the per-turn knobs AnswerLoop needs from its caller.
// Model is the chat model for the grade and the answer ("" resolves one, see
// resolveModel). Stage, when set, is called as the loop enters each phase (see
// the stage constants); nil is a no-op. It runs on the AnswerLoop goroutine.
// NoWeb turns the web-search fallback off (the /models web switch): the loop
// then rewrites and re-retrieves where it would have searched the web.
// NoLocal disables local KB retrieval (the /models rag switch off). The loop
// never calls rc.Search; grounding comes from web only. When false (default),
// AnswerLoop behavior is unchanged.
type AnswerOpts struct {
	Model, Preface string
	Stream         func([]byte)
	Stage          func(stage string)
	NoWeb          bool
	NoLocal        bool
	llm            *openai.LLM // reuse this client if set; nil builds one
}

// AnswerLoop is the bounded, code-orchestrated RAG answer loop: retrieval
// always runs in code; the LLM only grades context sufficiency and writes
// the final, source-attributed answer, streamed from oMLX. See nextAction for
// the loop control.
func AnswerLoop(ctx context.Context, rc searcher, cfg ragconfig.Config, question string, opts AnswerOpts) (answer string, cits []citation, usedWeb bool, results []retrieval.Result, tokens int, err error) {
	stage := func(name string) {
		if opts.Stage != nil {
			opts.Stage(name)
		}
	}

	if !opts.NoLocal {
		stage(stageRetrieving)
		results, err = rc.Search(ctx, question, cfg.TopK, nil)
		if err != nil {
			return "", nil, false, nil, 0, err
		}
	}

	l := opts.llm
	if l == nil {
		l, err = newOMLX(cfg, opts.Model)
		if err != nil {
			return "", nil, false, results, 0, err
		}
	}

	searchQuery := question
	hasTavily := tavilyKey() != "" && !opts.NoWeb
	looksCVE := looksLikeCVEorPoC(question)

	for i := 0; i < cfg.MaxLoops; i++ {
		stage(stageGrading)
		g, gerr := gradeContext(ctx, l, cfg, question, results)
		if gerr != nil {
			// Degrade: proceed to synthesis with whatever we already have.
			break
		}

		action := nextAction(g, hasTavily, looksCVE, len(results))
		if action == "sufficient" {
			break
		}

		if action == "web" {
			webQuery := g.Rewrite
			if webQuery == "" {
				webQuery = searchQuery
			}
			domains := cfg.ReputableDomains
			if looksCVE {
				domains = cfg.PocDomains
				webQuery = webQuery + " nomi-sec/PoC-in-GitHub"
			}
			stage(stageWeb)
			webResults, werr := webSearch(ctx, tavilyKey(), webQuery, cfg.TavilyMaxResults, domains)
			if werr == nil && len(webResults) > 0 {
				results = append(results, webResults...)
				usedWeb = true
				continue
			}
			// Empty or failed web search falls through to the rewrite +
			// re-retrieve below.
		}

		if !opts.NoLocal {
			if g.Rewrite != "" {
				searchQuery = g.Rewrite
				stage(stageRewriting)
			} else {
				stage(stageRetrieving)
			}
			retried, rerr := rc.Search(ctx, searchQuery, cfg.TopK, nil)
			if rerr == nil && len(retried) > 0 {
				results = retried
			}
		}
	}

	chunks := boundChunks(cfg, results)
	if len(chunks) == 0 {
		// A canceled or timed-out turn can leave retrieval empty; report that, not
		// "no results", so the caller does not treat it as a completed turn.
		if cerr := ctx.Err(); cerr != nil {
			return "", nil, usedWeb, results, 0, cerr
		}
		return "", nil, usedWeb, results, 0, ErrNoResults
	}

	stage(stageAnswering)

	msgs := buildMessages(question, chunks)
	if strings.TrimSpace(opts.Preface) != "" {
		human := "Additional context:\n" + opts.Preface + "\n\n" + buildUserPrompt(question, chunks)
		msgs = []llms.MessageContent{
			llms.TextParts(llms.ChatMessageTypeSystem, answerSystemPrompt),
			llms.TextParts(llms.ChatMessageTypeHuman, human),
		}
	}

	var full strings.Builder
	stream := func(_ context.Context, chunk []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		full.Write(chunk)
		if opts.Stream != nil {
			opts.Stream(chunk)
		}
		return nil
	}

	callOpts := []llms.CallOption{
		llms.WithStreamingFunc(stream),
		llms.WithTemperature(cfg.SynthTemperature),
		llms.WithMaxTokens(cfg.AnswerMaxTokens),
		llms.WithTopP(cfg.SynthTopP),
		llms.WithTopK(cfg.SynthTopK),
		llms.WithPresencePenalty(cfg.SynthPresencePenalty),
	}

	// The library drops top_p and top_k; llmTransport adds them for this call
	// only, so the grade call stays deterministic.
	cr, genErr := l.GenerateContent(withSampling(ctx, cfg), msgs, callOpts...)
	answer = full.String()
	cits = citationsFromAnswer(answer, chunks)
	return answer, cits, usedWeb, results, completionTokens(cr), mapLLMError(genErr, omlxBaseURL())
}
