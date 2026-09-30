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
const routeSystemPrompt = "You decide whether answering the user's question needs grounding in retrieved sources. " +
	"Reply with ONLY one word, no punctuation: GROUND if the question needs private, corpus-specific, recent, " +
	"or citable security information, or SKIP if it is general knowledge, pure reasoning, math, or creative writing. " +
	"When unsure, answer GROUND."

// parseRouteReply maps the classifier's one-word reply to a routeKind. Anything
// that is not clearly SKIP is treated as GROUND (safe default: a security KB
// should prefer grounding over an ungrounded guess).
func parseRouteReply(raw string) routeKind {
	if strings.EqualFold(strings.TrimSpace(raw), "SKIP") {
		return routeSkip
	}
	return routeGround
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

// directAnswerSystemPrompt is the skip-path system prompt: answer from the
// model's own knowledge, no corpus, no fabricated citations.
const directAnswerSystemPrompt = "You are a knowledgeable security research assistant. " +
	"Answer the user's question directly and concisely from your own knowledge. " +
	"Do not invent citations or claim sources you were not given."

// directAnswer answers question with a single streamed model call and no
// retrieval. It is the skip route's handler. It mirrors AnswerLoop's streaming
// and sampling so the ask path renders identically, minus the sources.
func directAnswer(ctx context.Context, cfg ragconfig.Config, question string, opts AnswerOpts) (string, int, error) {
	l, err := newOMLX(cfg, opts.Model)
	if err != nil {
		return "", 0, err
	}
	human := question
	if strings.TrimSpace(opts.Preface) != "" {
		human = "Additional context:\n" + opts.Preface + "\n\n" + question
	}
	msgs := []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeSystem, directAnswerSystemPrompt),
		llms.TextParts(llms.ChatMessageTypeHuman, human),
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
	cr, genErr := l.GenerateContent(withSampling(ctx, cfg), msgs, callOpts...)
	return full.String(), completionTokens(cr), mapLLMError(genErr, omlxBaseURL())
}

// adaptiveAnswer routes question, then dispatches: skip -> directAnswer;
// ground -> AnswerLoop (web-only when local retrieval is disabled). force
// bypasses the router and always grounds locally (the /rag <q> and --rag
// paths). route is "skip", "rag", or "web" (web when the grounded answer used
// the web fallback).
func adaptiveAnswer(ctx context.Context, rc searcher, cfg ragconfig.Config, question string, enabled enabledRoutes, force bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
	if !force {
		l, err := newOMLX(cfg, opts.Model)
		if err != nil {
			return "", nil, false, nil, 0, "", err
		}
		kind, _ := routeQuery(ctx, l, cfg, question, enabled)
		if kind == routeSkip {
			ans, tokens, derr := directAnswer(ctx, cfg, question, opts)
			return ans, []citation{}, false, []retrieval.Result{}, tokens, "skip", derr
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
