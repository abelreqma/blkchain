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

// rag.go is the bounded RAG answer loop (AnswerLoop): retrieve, grade
// sufficiency, optionally web-search or rewrite-and-re-retrieve, then stream a
// grounded, cited synthesis. AnswerLoop is the only path that RETRIEVES and
// grades; its synthesis tail is the shared `synthesize` primitive, which
// SynthesizeFromResults (the /generate entry) also calls to answer over
// caller-supplied results without retrieving or grading. route.go's
// adaptiveAnswer/directAnswer pick between grounding here and a direct answer.

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

	// Clamp MaxLoops to at least one pass: a value <= 0 (a bad rag.json or env)
	// would skip grading, the web fallback, and the guardrails entirely and go
	// straight to synthesis on the raw first retrieval.
	maxLoops := cfg.MaxLoops
	if maxLoops < 1 {
		maxLoops = 1
	}
	for i := 0; i < maxLoops; i++ {
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

	answer, cits, tokens, err = synthesize(ctx, l, cfg, question, results, opts)
	return answer, cits, usedWeb, results, tokens, err
}

// synthesize runs the final grounded, cited synthesis over results: bound the
// chunks, build the prompt, stream the answer with the synth_* sampling, and
// extract citations. It does NOT retrieve or grade. AnswerLoop and
// SynthesizeFromResults share it, so both stream and cite identically.
func synthesize(ctx context.Context, l *openai.LLM, cfg ragconfig.Config, question string, results []retrieval.Result, opts AnswerOpts) (answer string, cits []citation, tokens int, err error) {
	stage := func(name string) {
		if opts.Stage != nil {
			opts.Stage(name)
		}
	}

	chunks := boundChunks(cfg, results)
	if len(chunks) == 0 {
		// A canceled or timed-out turn can leave retrieval empty; report that, not
		// "no results", so the caller does not treat it as a completed turn.
		if cerr := ctx.Err(); cerr != nil {
			return "", nil, 0, cerr
		}
		return "", nil, 0, ErrNoResults
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
		// oMLX streams a keepalive first chunk (empty content) and reasoning-only
		// deltas also arrive empty; drop them so a consumer (the live tokens/sec
		// bar) does not record a false first token. It is a no-op for `full`.
		if len(chunk) == 0 {
			return nil
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
	return answer, cits, completionTokens(cr), mapLLMError(genErr, omlxBaseURL())
}

// SynthesizeFromResults synthesizes a grounded, cited answer over caller-supplied
// results WITHOUT retrieving or grading. It is the /generate entry: the caller
// passes the results from a prior search, and the answer streams and cites
// exactly as AnswerLoop's synthesis does (same synth_* sampling, citation
// extraction, and untrusted-tag behavior). It never calls Search and never
// grades.
func SynthesizeFromResults(ctx context.Context, cfg ragconfig.Config, question string, results []retrieval.Result, opts AnswerOpts) (answer string, cits []citation, tokens int, err error) {
	l := opts.llm
	if l == nil {
		l, err = newOMLX(cfg, opts.Model)
		if err != nil {
			return "", nil, 0, err
		}
	}
	return synthesize(ctx, l, cfg, question, results, opts)
}
