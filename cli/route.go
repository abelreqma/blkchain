package main

import (
	"context"
	"regexp"
	"strings"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"github.com/tmc/langchaingo/llms"
)

// route.go is the adaptive-retrieval router for the ask path: cheap
// deterministic guardrails, then a one-word model classifier, decide per query
// whether to skip retrieval (answer from the model) or ground it (AnswerLoop).
// Grounding reuses AnswerLoop unchanged; web escalation stays inside it.

// routeKind is the router's decision.
type routeKind int

const (
	routeSkip routeKind = iota
	routeGround
	routeAdvise
)

// enabledRoutes says which grounding routes are available, from the /models
// toggles. Local is the rag toggle (local KB), Web is the web toggle.
type enabledRoutes struct {
	Local bool
	Web   bool
}

// arithmeticPattern matches a whole string that is only digits, arithmetic
// operators, spaces, parentheses, and an optional trailing "=" or "?". It is
// deliberately narrow (high precision, low recall): only obvious arithmetic
// skips retrieval by guardrail; everything else falls to the model.
var arithmeticPattern = regexp.MustCompile(`^[0-9.+\-*/%^()\s]+[=?]?\s*$`)

var numberToken = regexp.MustCompile(`[0-9.]+`)

// operandOperator matches an operator that sits between two operands. A '-'
// tight between two digits ("2024-01-15", "2024-1234") is not counted, since it
// reads as a date or id; a '-' with whitespace on a side or next to a
// parenthesis is.
var operandOperator = regexp.MustCompile(`[0-9)]\s*[+*/%^]\s*[(0-9.]|[0-9)]\s+-\s*[(0-9.]|[0-9)]\s*-\s+[(0-9.]|\)\s*-\s*[(0-9.]|[0-9)]\s*-\s*\(`)

// isPureArithmetic reports whether s is an obvious arithmetic expression: it
// matches arithmeticPattern, has no number token with two or more dots, and has
// at least one operator between two operands.
func isPureArithmetic(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || !arithmeticPattern.MatchString(s) {
		return false
	}
	if !strings.ContainsAny(s, "0123456789") {
		return false
	}
	for _, tok := range numberToken.FindAllString(s, -1) {
		if strings.Count(tok, ".") >= 2 {
			return false
		}
	}
	return operandOperator.MatchString(s)
}

// routeGuard applies the deterministic guardrails. forced is true when a
// guardrail decides the route; when false, kind is unset and the caller must
// consult the model. CVE/PoC questions force grounding (AnswerLoop then
// escalates to the web PoC route); obvious arithmetic forces skip.
func routeGuard(question string) (kind routeKind, forced bool) {
	if looksLikeCVEorPoC(question) {
		return routeGround, true
	}
	if isPureArithmetic(question) {
		return routeSkip, true
	}
	return routeSkip, false
}

// routeSystemPrompt is the one-word classifier instruction shared by the ask
// path. It states which sources are available so the model does not pick a
// disabled route.
const routeSystemPrompt = "You decide how to handle the user's message in an offensive-security assistant. " +
	"Reply with ONLY one word, no punctuation: " +
	"SKIP if it is general knowledge, pure reasoning, math, or chit-chat that needs no security corpus; " +
	"ADVISE if the user wants interactive, step-by-step operational help running or planning an attack against a " +
	"specific target or from a foothold they describe (escalating privileges, exploiting a found service, walking " +
	"through an engagement, deciding the next action); " +
	"GROUND for anything else that needs grounded security facts, including explaining a concept, technique, or a " +
	"single question. When unsure, answer GROUND."

// parseRouteReply maps the classifier's one-word reply to a routeKind. SKIP and
// ADVISE are matched explicitly; anything else is GROUND (safe default: a
// security KB should prefer grounding over an ungrounded guess).
func parseRouteReply(raw string) routeKind {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "SKIP":
		return routeSkip
	case "ADVISE":
		return routeAdvise
	default:
		return routeGround
	}
}

// routeQuery decides skip vs ground for question. It short-circuits to skip when
// no grounding route is enabled, applies the deterministic guardrails, and
// otherwise asks the model for a one-word GROUND/SKIP verdict (temperature 0,
// bounded by RouteMaxTokens). Any classifier failure or unclear reply defaults
// to ground.
func routeQuery(ctx context.Context, m toolLoopModel, cfg ragconfig.Config, question string, enabled enabledRoutes) (routeKind, error) {
	if !enabled.Local && !enabled.Web {
		return routeSkip, nil
	}
	if kind, forced := routeGuard(question); forced {
		return kind, nil
	}
	msgs := []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeSystem, routeSystemPrompt),
		llms.TextParts(llms.ChatMessageTypeHuman, question),
	}
	maxTok := cfg.RouteMaxTokens
	if maxTok <= 0 {
		maxTok = 8
	}
	resp, err := m.GenerateContent(ctx, msgs,
		llms.WithTemperature(cfg.GradeTemperature),
		llms.WithMaxTokens(maxTok),
	)
	if err != nil {
		return routeGround, nil // degrade to grounding, never fail the turn
	}
	if resp == nil || len(resp.Choices) == 0 {
		return routeGround, nil
	}
	return parseRouteReply(resp.Choices[0].Content), nil
}

// directAnswerConstraints is the skip-path body: answer from the model's own
// knowledge, grounded in any user-provided context, generate ready-to-use
// payloads, and fabricate no citations/CVEs. It is prepended with a persona
// preamble (directAnswerSystemPrompt) so the skip path answers in the same
// expert voice as grounded answers.
const directAnswerConstraints = "Answer the user's question directly and completely from your own knowledge, grounded in any context the user " +
	"provided (their stated target, constraints, and attached project context). When the question calls for " +
	"payloads, exploit strings, test inputs, or commands, generate concrete, ready-to-use ones adapted to that " +
	"context. Whenever it helps the user act, name the specific tools to use and show concrete example commands " +
	"or invocations (copy-pasteable), not only prose. Do not invent citations or claim sources you were not given, " +
	"and do not fabricate CVE identifiers, " +
	"version numbers, or statistics."

// directAnswerSystemPrompt is the skip-path system prompt. directAnswer does no
// retrieval, so it always uses the offensive-security generalist persona plus the
// own-knowledge constraints - a persona is invoked on the skip path too.
const directAnswerSystemPrompt = genericPersonaPreamble + directAnswerConstraints

// directAnswer answers question with a single streamed model call and no
// retrieval. It is the skip route's handler. It mirrors AnswerLoop's streaming
// and sampling so the ask path renders identically, minus the sources.
func directAnswer(ctx context.Context, cfg ragconfig.Config, question string, opts AnswerOpts) (string, int, error) {
	l, err := newOMLX(cfg, opts.Model)
	if err != nil {
		return "", 0, err
	}
	// The skip path has no retrieval, so it is always the generalist persona;
	// announce it so the "answering as" cue fires here too (empty domain ->
	// personaLabel returns the generalist label).
	if opts.Persona != nil {
		opts.Persona("")
	}
	human := question
	if strings.TrimSpace(opts.Preface) != "" {
		human = "Context the user provided:\n" + opts.Preface + "\n\n" + question
	}
	// Carry conversation memory on the skip path too: this is where
	// conversational follow-ups ("the codeword", "an example of it") land.
	msgs := messagesWithHistory(directAnswerSystemPrompt, opts.History, human)
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
	cr, genErr := l.GenerateContent(withSampling(ctx, cfg), msgs, callOpts...)
	return full.String(), completionTokens(cr), mapLLMError(genErr, omlxBaseURL())
}

const skipValidateSystemPrompt = "You are checking whether retrieved snippets are relevant to the user's question. " +
	"Reply with ONLY one word, no punctuation: RELEVANT if the snippets directly address the question's topic, " +
	"or IRRELEVANT if they are off-topic. When unsure, answer IRRELEVANT."

// skipGroundsInCorpus validates a provisional skip against the corpus using the
// local LLM: it retrieves for question and asks whether the retrieved snippets
// are actually relevant to it. It returns true (override the skip to grounding)
// only on an explicit RELEVANT verdict. An empty corpus, any error, or any reply
// that is not RELEVANT leaves the skip in place, so validation never grounds on
// off-topic results and never fails the turn.
func skipGroundsInCorpus(ctx context.Context, l toolLoopModel, rc searcher, cfg ragconfig.Config, question string) bool {
	results, err := rc.Search(ctx, question, cfg.TopK, nil)
	if err != nil || len(results) == 0 {
		return false
	}
	maxTok := cfg.RouteMaxTokens
	if maxTok <= 0 {
		maxTok = 8
	}
	msgs := []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeSystem, skipValidateSystemPrompt),
		llms.TextParts(llms.ChatMessageTypeHuman, "Question: "+question+"\n\nSnippets:\n"+buildContext(results)),
	}
	resp, err := l.GenerateContent(ctx, msgs,
		llms.WithTemperature(cfg.GradeTemperature),
		llms.WithMaxTokens(maxTok),
	)
	if err != nil || resp == nil || len(resp.Choices) == 0 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(resp.Choices[0].Content), "RELEVANT")
}

// adaptiveAnswer routes question, then dispatches: skip -> directAnswer;
// ground -> AnswerLoop (web-only when local retrieval is disabled). force
// bypasses the router and always grounds locally (the /rag <q> and --rag
// paths). A provisional skip is validated against the corpus with the local LLM
// (skipGroundsInCorpus) and overridden to grounding when the corpus can answer
// it; the pure-arithmetic guard skip is never validated. route is "skip", "rag",
// or "web" (web when the grounded answer used the web fallback).
func adaptiveAnswer(ctx context.Context, rc searcher, cfg ragconfig.Config, question string, enabled enabledRoutes, force bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
	// Compress carried-back conversation memory once, before any dispatch, so a
	// long session stays within budget by condensing older turns rather than
	// dropping them. Shared by the CLI, REPL, and TUI (all reach here through
	// adaptiveAnswerFn). A client is built only when the history actually exceeds
	// the budget; otherwise this is a cheap length check.
	if budget := conversationBudget(); conversationChars(opts.History) > budget {
		if cl, err := newOMLX(cfg, opts.Model); err == nil {
			opts.History = compressTurns(ctx, cl, opts.History, budget)
		} else {
			opts.History = boundTurns(opts.History, budget)
		}
	}
	if !force {
		l, err := newOMLX(cfg, opts.Model)
		if err != nil {
			return "", nil, false, nil, 0, "", err
		}
		kind, _ := routeQuery(ctx, l, cfg, question, enabled)
		if kind == routeSkip && enabled.Local && !isPureArithmetic(question) {
			// Do not answer ungrounded until the local LLM confirms the corpus
			// cannot ground it; if it can, ground instead.
			if skipGroundsInCorpus(ctx, l, rc, cfg, question) {
				kind = routeGround
			}
		}
		if kind == routeSkip {
			ans, tokens, derr := directAnswer(ctx, cfg, question, opts)
			return ans, []citation{}, false, []retrieval.Result{}, tokens, "skip", derr
		}
		if kind == routeAdvise && enabled.Local {
			// Engagement-shaped turn: run the ungated, tool-using advisor
			// (route_skill + kb_search, no host execution). cat may be nil, which
			// only disables the route_skill playbook lookup.
			opts.llm = l
			cat, _ := loadEngageCatalog()
			ans, tokens, aerr := adviseLoop(ctx, l, rc, cfg, cat, question, opts)
			return ans, []citation{}, false, []retrieval.Result{}, tokens, "rag", aerr
		}
		opts.NoLocal = !enabled.Local
		opts.llm = l
	}
	ans, cits, usedWeb, results, tokens, err := AnswerLoop(ctx, rc, cfg, question, opts)
	route := "rag"
	if usedWeb {
		route = "web"
	}
	return ans, cits, usedWeb, results, tokens, route, err
}

// adaptiveAnswerFn is the router entry the ask command and the TUI both call. It
// is a variable so tests can capture the enabled routes and force flag the
// callers pass, without a live LLM.
var adaptiveAnswerFn = adaptiveAnswer
