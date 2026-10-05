package main

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
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
	stageNVD        = "searching NVD"
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
// It selects the configured provider and applies the automatic fallback.
var webSearch = dispatchWebSearch

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
	cveQueryPattern = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,55}\b`)
	pocQueryPattern = regexp.MustCompile(`(?i)\bpoc\b|proof[- ]of[- ]concept|\bexploit\b`)
)

// looksLikeCVEorPoC reports whether a query names a CVE or asks about a
// proof-of-concept or exploit. Such a query is routed to web search regardless
// of what the grader says, since a local KB snapshot would not contain current
// CVE or PoC information.
func looksLikeCVEorPoC(query string) bool {
	return cveQueryPattern.MatchString(query) || pocQueryPattern.MatchString(query)
}

func specificPoCLead(result retrieval.Result, id string, domains []string) bool {
	if !allowedSearchURL(result.Payload.Path, domains) {
		return false
	}
	text := result.Payload.Path + " " + result.Payload.Section
	if !strings.Contains(strings.ToUpper(text), id) {
		return false
	}
	u, _ := url.Parse(result.Payload.Path)
	if strings.EqualFold(u.Hostname(), "github.com") {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) < 2 || parts[0] == "topics" || parts[0] == "search" || parts[0] == "collections" {
			return false
		}
	}
	return true
}

func cveResearch(ctx context.Context, cfg ragconfig.Config, question string, stage func(string)) ([]retrieval.Result, error) {
	id := strings.ToUpper(cveQueryPattern.FindString(question))
	if id == "" {
		return nil, nil
	}
	stage(stageNVD)
	nvdResults, err := nvdLookup(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(nvdResults) == 0 {
		return nil, errors.New("nvd: empty CVE result")
	}
	stage(stageWeb)
	query := id + " proof of concept exploit Exploit-DB Sploitus GitHub nomi-sec/PoC-in-GitHub"
	webResults, webErr := webSearch(ctx, tavilyKey(), query, min(cfg.TavilyMaxResults, 3), cfg.PocDomains)
	matching := webResults[:0]
	for _, result := range webResults {
		if specificPoCLead(result, id, cfg.PocDomains) {
			matching = append(matching, result)
		}
	}
	webResults = matching
	if webErr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		nvdResults[len(nvdResults)-1].Payload.Text = "Public PoC search was unavailable; no PoC availability conclusion can be drawn.\n" + nvdResults[len(nvdResults)-1].Payload.Text
	} else if len(webResults) == 0 {
		nvdResults[len(nvdResults)-1].Payload.Text = "Public PoC search returned no matching leads; this does not prove none exist.\n" + nvdResults[len(nvdResults)-1].Payload.Text
	}
	nvdResults[len(nvdResults)-1].Payload.Text = nvdCapText(nvdResults[len(nvdResults)-1].Payload.Text)
	return append(nvdResults, webResults...), nil
}

// nextAction is the pure loop-control decision, extracted so it can be unit
// tested without any LLM or network dependency. The loop wants the web when the
// grader asks for it, the query looks like a CVE or PoC question, or retrieval
// found nothing, and gets it only when web search is enabled (the web provider
// is Tavily, or the opted-in keyless DuckDuckGo fallback, see webProvider);
// An enabled web request takes precedence over sufficiency.
func nextAction(g grade, hasWeb, looksCVE bool, results int) string {
	if hasWeb && g.UseWeb {
		return "web"
	}
	if g.Sufficient {
		return "sufficient"
	}
	wantsWeb := g.UseWeb || looksCVE || results == 0
	if wantsWeb && hasWeb {
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
	// Persona, when set, is called once with the chosen domain KEY (e.g. "ad")
	// before the answer streams, so the UI can show the cue via personaLabel and
	// a short status token. It is not called for the generic persona.
	Persona      func(domain string)
	WebOnly      bool
	NoWeb        bool
	NoLocal      bool
	SearchTopK   int
	SearchFilter map[string]any

	History []priorTurn
	llm     toolLoopModel // reuse this client if set; nil builds one
}

// priorTurn is one earlier message in the conversation. Role is "human" or
// "ai" (the values the history store and langchaingo record, which match
// llms.ChatMessageType).
type priorTurn struct {
	Role    string
	Content string
}

// conversationMaxChars bounds the characters of prior conversation carried back
// as memory. The LLM context window is 256k tokens, so this is generous
// (~50k tokens): the WHOLE conversation stays in context for realistic sessions
// instead of being forgotten after a few turns, while leaving ample headroom for
// the current turn's retrieved sources and answer. Sessions that outgrow this
// are compressed by the conversation summarizer (compressTurns, convcompress.go)
// rather than truncated, so nothing is silently dropped. Override with
// BLKCHAIN_CONVERSATION_MAX_CHARS (see conversationBudget).
const conversationMaxChars = 200000

// boundTurns trims history to the most recent turns whose total content fits
// maxChars, preserving oldest-first order. The single newest turn is always
// kept, even when it alone exceeds the budget, so some memory always survives.
func boundTurns(turns []priorTurn, maxChars int) []priorTurn {
	if len(turns) == 0 {
		return turns
	}
	total := 0
	start := len(turns)
	for i := len(turns) - 1; i >= 0; i-- {
		total += len(turns[i].Content)
		if total > maxChars && i != len(turns)-1 {
			break
		}
		start = i
	}
	return turns[start:]
}

// priorContextMaxChars bounds how much of a prior user question is folded into
// a follow-up's retrieval query, so a long prior turn cannot dominate the
// embedded query.
const priorContextMaxChars = 400

// retrievalQuery makes the first retrieval history-aware: it prepends the most
// recent prior USER question (bounded) to the current question, so a follow-up
// like "and for Windows?" still retrieves the right chunks. Prior AI answers
// are deliberately excluded; they are long and would drown the embedded query.
// With no prior user turn it returns the question unchanged.
func retrievalQuery(history []priorTurn, question string) string {
	prev := ""
	for i := len(history) - 1; i >= 0; i-- {
		if chatType(history[i].Role) == llms.ChatMessageTypeHuman {
			prev = strings.TrimSpace(history[i].Content)
			break
		}
	}
	if prev == "" {
		return question
	}
	return capRunes(prev, priorContextMaxChars) + "\n" + question
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

	if opts.WebOnly {
		if opts.NoWeb || !loadPrefs().Web {
			return "", nil, false, nil, 0, errors.New("web: disabled; enable web before searching the internet")
		}
		if cveQueryPattern.MatchString(question) {
			results, err = cveResearch(ctx, cfg, question, stage)
			if err != nil {
				return "", nil, false, nil, 0, err
			}
		} else {
			stage(stageWeb)
			webLimit := cfg.TavilyMaxResults
			if opts.SearchTopK > 0 {
				webLimit = opts.SearchTopK
			}
			results, err = webSearch(ctx, tavilyKey(), question, webLimit, nil)
			if err != nil {
				return "", nil, false, nil, 0, err
			}
		}
		if len(results) == 0 {
			return "", nil, false, results, 0, ErrNoResults
		}
		answer, cits, tokens, err = SynthesizeFromResults(ctx, cfg, question, results, opts)
		return answer, cits, true, results, tokens, err
	}

	topK := cfg.TopK
	if opts.SearchTopK > 0 {
		topK = opts.SearchTopK
	}
	if !opts.NoLocal {
		stage(stageRetrieving)
		// History-aware first retrieval: a follow-up carries the prior user
		// question so it retrieves the right chunks. Grading/synthesis still use
		// the raw question below.
		results, err = rc.Search(ctx, retrievalQuery(opts.History, question), topK, opts.SearchFilter)
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
	// Automatic searches require saved permission and an available provider.
	_, webAvail := webProvider(tavilyKey())
	hasWeb := webAvail && !opts.NoWeb && loadPrefs().Web
	looksCVE := looksLikeCVEorPoC(question)
	var externalResults []retrieval.Result
	if cveQueryPattern.MatchString(question) && hasWeb {
		externalResults, err = cveResearch(ctx, cfg, question, stage)
		if err != nil {
			return "", nil, false, results, 0, err
		}
		results = append(externalResults, results...)
		usedWeb = true
	}

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

		action := nextAction(g, hasWeb && !usedWeb, looksCVE, len(results))
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
				externalResults = append(externalResults, webResults...)
				results = append(results, externalResults...)
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
			retried, rerr := rc.Search(ctx, searchQuery, topK, opts.SearchFilter)
			if rerr == nil && len(retried) > 0 {
				if len(externalResults) > 0 && externalResults[0].Payload.Source == nvdSource {
					results = append(append([]retrieval.Result{}, externalResults...), retried...)
				} else {
					results = append(retried, externalResults...)
				}
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
func synthesize(ctx context.Context, l toolLoopModel, cfg ragconfig.Config, question string, results []retrieval.Result, opts AnswerOpts) (answer string, cits []citation, tokens int, err error) {
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

	// Pick the domain-expert persona from what retrieval returned, and announce
	// it (cue) before streaming. Generic (empty) uses the default persona
	// without a cue. All personas share answerConstraints, so grounding,
	// citations, payload generation, and embedded-instruction handling are
	// identical regardless of persona.
	domain := domainFromResults(chunks)
	if opts.Persona != nil && personaLabel(domain) != "" {
		opts.Persona(domain)
	}

	msgs := buildMessages(personaPrompt(domain), question, chunks, opts.History)
	if strings.TrimSpace(opts.Preface) != "" {
		// Preface (project context + @file attachments) rides on the current
		// human turn; the history turns stay in place ahead of it.
		human := "Context the user provided:\n" + opts.Preface + "\n\n" + buildUserPrompt(question, chunks)
		msgs[len(msgs)-1] = llms.TextParts(llms.ChatMessageTypeHuman, human)
	}

	var full strings.Builder
	if domain == "cve" {
		for i, result := range chunks {
			if result.Payload.Source == nvdSource && strings.HasSuffix(result.Payload.Section, " summary") {
				prefix := "NVD record [" + strconv.Itoa(i+1) + "]\n" + sanitizeTerminal(result.Payload.Text) + "\n\n"
				full.WriteString(prefix)
				if opts.Stream != nil {
					opts.Stream([]byte(prefix))
				}
				break
			}
		}
	}
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
	cr, genErr := l.GenerateContent(withLLMStage(withSampling(ctx, cfg), "synthesis"), msgs, callOpts...)
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
