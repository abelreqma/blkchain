package main

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"blkchain/cli/internal/client"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

// noResultsAnswer is the plain-text statement that nothing was found. It
// mirrors Python's _synthesize on an empty results list verbatim. AnswerLoop
// does not stream or return it as an answer; it is the text of ErrNoResults
// and what non-interactive callers (MCP, --json) report.
const noResultsAnswer = "No relevant sources were found in the knowledge base or " +
	"web search for this question, so no grounded answer can be given."

// ErrNoResults is returned by AnswerLoop when retrieval, the optional web
// fallback, and any rewrite produced nothing to answer from. Nothing is
// streamed and no LLM synthesis runs. Callers check it with errors.Is and
// present it as a warning with next steps, not as an answer.
var ErrNoResults = errors.New(noResultsAnswer)

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

// rag.go is the single canonical bounded RAG answer loop (AnswerLoop),
// mirroring blkchain/agent.py's kb_answer: retrieve, grade sufficiency,
// optionally web-search or rewrite-and-re-retrieve, then stream a grounded,
// cited synthesis. The loop control (nextAction) and prompts mirror Python
// exactly; the synthesis temperature (cfg.SynthTemperature, default 0.2) and
// the web fallback's result count (cfg.TavilyMaxResults) are intentional,
// config-driven differences from Python's hardcoded temperature=0.0 and
// TOP_K-based max_results. It is the only RAG answer path `ask` and the TUI
// use; there is no Python /answer fallback.

// cveQueryPattern / pocQueryPattern port Python's _CVE_RE / _POC_RE
// (blkchain/agent.py) verbatim.
var (
	cveQueryPattern = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
	pocQueryPattern = regexp.MustCompile(`(?i)\bpoc\b|proof[- ]of[- ]concept|\bexploit\b`)
)

// looksLikeCVEorPoC mirrors Python's _looks_like_cve_or_poc: a query that
// names a CVE or asks about a proof-of-concept/exploit is routed to web
// search regardless of what the grader says, since a local KB snapshot
// would not contain current CVE/PoC information.
func looksLikeCVEorPoC(query string) bool {
	return cveQueryPattern.MatchString(query) || pocQueryPattern.MatchString(query)
}

// nextAction is the pure loop-control decision, extracted so it can be unit
// tested without any LLM or network dependency. It mirrors Python's
// wants_web = grade["use_web"] or _looks_like_cve_or_poc(query) or not
// results, gated on a Tavily key being configured; grade.Sufficient always
// wins first.
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
// Reasoning is display-only (tracked for the status line / session record)
// and is never sent to oMLX: langchaingo v0.1.13 exposes no reasoning_effort
// call option. Stage, when set, is called as the loop enters each phase (see
// the stage constants); nil is a no-op. It runs on the AnswerLoop goroutine.
// NoWeb turns the web-search fallback off (the /models web switch): the loop
// then rewrites and re-retrieves where it would have searched the web.
type AnswerOpts struct {
	Model, Preface, Reasoning string
	Stream                    func([]byte)
	Stage                     func(stage string)
	NoWeb                     bool
}

// AnswerLoop is the bounded, code-orchestrated RAG answer loop: retrieval
// always runs in code; the LLM only grades context sufficiency and writes
// the final, source-attributed answer. It mirrors blkchain/agent.py's
// kb_answer loop control exactly (see nextAction), then streams the
// synthesis from oMLX.
func AnswerLoop(ctx context.Context, rc searcher, cfg ragconfig.Config, question string, opts AnswerOpts) (answer string, cits []client.Citation, usedWeb bool, results []retrieval.Result, tokens int, err error) {
	_ = opts.Reasoning // display-only (see AnswerOpts doc comment)
	stage := func(name string) {
		if opts.Stage != nil {
			opts.Stage(name)
		}
	}

	stage(stageRetrieving)
	results, err = rc.Search(ctx, question, cfg.TopK, nil)
	if err != nil {
		return "", nil, false, nil, 0, err
	}

	l, err := newOMLX()
	if err != nil {
		return "", nil, false, results, 0, err
	}

	searchQuery := question
	hasTavily := tavilyKey() != "" && !opts.NoWeb
	looksCVE := looksLikeCVEorPoC(question)

	for i := 0; i < cfg.MaxLoops; i++ {
		stage(stageGrading)
		g, gerr := gradeContext(ctx, l, cfg, question, results)
		if gerr != nil {
			// Degrade: proceed to synthesis with whatever we already have,
			// matching Python's best-effort behavior on a grading failure.
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
			stage(stageWeb)
			webResults, werr := webSearch(ctx, tavilyKey(), webQuery, cfg.TavilyMaxResults, cfg.ReputableDomains)
			if werr == nil && len(webResults) > 0 {
				results = append(results, webResults...)
				usedWeb = true
				continue
			}
			// Empty or failed web search falls through to the rewrite +
			// re-retrieve below, matching Python's kb_answer.
		}

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
	}
	if strings.TrimSpace(opts.Model) != "" {
		callOpts = append(callOpts, llms.WithModel(opts.Model))
	}

	cr, genErr := l.GenerateContent(ctx, msgs, callOpts...)
	answer = full.String()
	cits = citationsFromAnswer(answer, chunks)
	return answer, cits, usedWeb, results, completionTokens(cr), mapLLMError(genErr, omlxBaseURL())
}
