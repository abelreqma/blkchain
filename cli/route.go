package main

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"strings"

	"blkchain/cli/internal/promptguard"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"github.com/tmc/langchaingo/llms"
)

// route.go is the adaptive-retrieval router for the ask path: cheap
// deterministic guardrails, then a one-word model classifier, decide per query
// whether to skip retrieval (answer from the model) or ground it (AnswerLoop).
// Grounding uses AnswerLoop for live search and local retrieval.

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
var targetAddressPattern = regexp.MustCompile(`(?i)(?:[a-z][a-z0-9+.-]*://|\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*\.[a-z]{2,}\b|\blocalhost\b|\b[a-z][a-z0-9-]*:[0-9]{2,5}\b|\[[0-9a-f:]+\](?::[0-9]+)?|\b[a-z0-9._-]+@[a-z0-9._-]+\b)`)
var targetContextPattern = regexp.MustCompile(`(?i)\b(?:my|our|this)\s+(?:[a-z0-9-]+\s+)?(?:host|server|domain|cluster|tenant|app|application|environment|foothold|account|project|network|vpc|subscription|realm|asset|instance|service)\b|\b(?:foothold|internal|private|staging|production|dc[0-9]+|srv[0-9]+|host[0-9]+)\b`)
var targetSecretPattern = regexp.MustCompile(`(?i)\b(?:api[_-]?key|token|password|passwd|secret|authorization|credential|host|server|target)\s*[:=]\s*\S+|\b(?:api[_-]?key|token|password|passwd|secret|credential)\s+(?:is|was)\s+\S+|\bbearer\s+[a-z0-9._~-]{8,}\b`)

func questionHasTargetDetails(question string) bool {
	if targetAddressPattern.MatchString(question) || targetContextPattern.MatchString(question) || targetSecretPattern.MatchString(question) {
		return true
	}
	for _, field := range strings.Fields(question) {
		field = strings.Trim(field, `[](){}<>"'.,;!?`)
		if _, err := netip.ParseAddr(field); err == nil {
			return true
		}
		if _, err := netip.ParsePrefix(field); err == nil {
			return true
		}
	}
	return false
}

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

// routeSystemPrompt is the one-word classifier instruction shared by the ask path.
const routeSystemPrompt = "You decide how to handle the user's message in an offensive-security assistant. " +
	"Reply with ONLY one word, no punctuation: " +
	"SKIP if it is general knowledge, pure reasoning, math, or chit-chat that needs no security corpus; " +
	"ADVISE if the user wants you to use a tool, including reading a file or taking an engagement action, or wants step-by-step operational help against a " +
	"specific target or from a foothold they describe (scanning, sending a request, escalating privileges, exploiting a service, or deciding the next action); " +
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
	resp, err := m.GenerateContent(withLLMStage(ctx, "routing"), msgs,
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
const directAnswerConstraints = offensiveReasoningStandard + "Answer the user's question directly and completely from your own knowledge, grounded in any context the user " +
	"provided (their stated target, constraints, and attached project context). When the question calls for " +
	"payloads, exploit strings, test inputs, or commands, generate concrete, ready-to-use ones adapted to that " +
	"context. Whenever it helps the user act, name the specific tools to use and show concrete example commands " +
	"or invocations (copy-pasteable), not only prose. Do not invent citations or claim sources you were not given, " +
	"and do not fabricate CVE identifiers, " +
	"version numbers, or statistics."

// directAnswerSystemPrompt is the generic skip-path prompt used by prompt checks.
// directAnswer selects a question specialist when one is clear.
const directAnswerSystemPrompt = genericPersonaPreamble + directAnswerConstraints

// directAnswer answers question with a single streamed model call and no
// retrieval. It is the skip route's handler. It mirrors AnswerLoop's streaming
// and sampling so the ask path renders identically, minus the sources.
func directAnswer(ctx context.Context, cfg ragconfig.Config, question string, opts AnswerOpts) (string, int, error) {
	domain, err := answerAgentDomain(opts.Agent, domainFromQuestion(question))
	if err != nil {
		return "", 0, err
	}
	l := opts.llm
	if l == nil {
		l, err = newOMLX(cfg, opts.Model)
		if err != nil {
			return "", 0, err
		}
	}
	if opts.Persona != nil {
		opts.Persona(domain)
	}
	human := question
	if strings.TrimSpace(opts.Preface) != "" {
		human = "Context the user provided:\n" + opts.Preface + "\n\n" + question
	}
	// Carry conversation memory on the skip path too: this is where
	// conversational follow-ups ("the codeword", "an example of it") land.
	prompt := personaFor(domain).preamble + directAnswerConstraints
	msgs := messagesWithHistory(prompt, opts.History, human)
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
	cr, genErr := l.GenerateContent(withLLMStage(withSampling(ctx, cfg), "synthesis"), msgs, callOpts...)
	return full.String(), completionTokens(cr), mapLLMError(genErr, omlxBaseURL())
}

const skipValidateSystemPrompt = "You are checking whether retrieved snippets are relevant to the user's question. " +
	"Reply with ONLY one word, no punctuation: RELEVANT if the snippets directly address the question's topic, " +
	"or IRRELEVANT if they are off-topic. When unsure, answer IRRELEVANT. " + promptguard.UntrustedInputClause

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
	resp, err := l.GenerateContent(withLLMStage(ctx, "corpus_check"), msgs,
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
	if _, err := parseAnswerAgent(opts.Agent); err != nil {
		return "", nil, false, nil, 0, "", err
	}
	// The turn's two chains: the router answers the short decisions, the
	// assessment chain answers the turn. A caller that carries them resolved
	// them once for the whole turn; any other caller resolves them here.
	routerChain, assessmentChain := opts.routerChain, opts.assessmentChain
	if routerChain == nil || assessmentChain == nil {
		routerIDs, assessmentIDs := roleChains(cfg, opts.Model)
		var err error
		if routerChain == nil {
			if routerChain, err = chainOrDefault(cfg, routerIDs, opts.Model); err != nil {
				return "", nil, false, nil, 0, "", err
			}
		}
		if assessmentChain == nil {
			if assessmentChain, err = chainOrDefault(cfg, assessmentIDs, opts.Model); err != nil {
				return "", nil, false, nil, 0, "", err
			}
		}
	}
	opts.llm = assessmentChain
	opts.router = routerChain
	opts.assessment = assessmentChain
	keepLocal := opts.WebFirst && !opts.WebOnly && (questionHasTargetDetails(question) || len(chatTargetEntries(question, opts.History)) > 0)
	if keepLocal {
		opts.NoWeb = true
		enabled.Web = false
	}
	// Compress carried-back conversation memory once, before any dispatch, so a
	// long session stays within budget by condensing older turns rather than
	// dropping them. Shared by the CLI, REPL, and TUI (all reach here through
	// adaptiveAnswerFn). The model is only called when the history actually
	// exceeds the budget; otherwise this is a cheap length check.
	if budget := conversationBudget(); conversationChars(opts.History) > budget {
		opts.History = compressTurns(ctx, routerChain, opts.History, budget)
	}
	if !force && !opts.WebOnly {
		var err error
		kind := routeAdvise
		hasTarget := len(chatTargetEntries(question, opts.History)) > 0
		if !isPureArithmetic(question) {
			opts.requiredAction, err = classifyChatAction(ctx, routerChain, question, hasTarget)
			if err != nil {
				return "", nil, false, nil, 0, "", err
			}
			if opts.requiredAction == "web_search" && (!enabled.Web || opts.NoWeb || !loadPrefs().Web) {
				return "", nil, false, nil, 0, "", errors.New("native chat: public web search is disabled")
			}
		}
		if !hasTarget && opts.requiredAction == "" {
			kind, _ = routeQuery(ctx, routerChain, cfg, question, enabled)
		}
		if kind == routeAdvise && opts.WebFirst && enabled.Web && !opts.NoWeb && !hasTarget && opts.requiredAction == "" {
			kind = routeGround
		}
		if keepLocal && kind == routeSkip {
			kind = routeGround
		}
		if kind == routeSkip && opts.WebFirst && enabled.Web && !opts.NoWeb && !isPureArithmetic(question) {
			kind = routeGround
		}
		if kind == routeSkip && enabled.Local && !isPureArithmetic(question) {
			// Do not answer ungrounded until the local LLM confirms the corpus
			// cannot ground it; if it can, ground instead.
			if skipGroundsInCorpus(ctx, routerChain, rc, cfg, question) {
				kind = routeGround
			}
		}
		if kind == routeSkip {
			ans, tokens, derr := directAnswer(ctx, cfg, question, opts)
			return ans, []citation{}, false, []retrieval.Result{}, tokens, "skip", derr
		}
		if kind == routeAdvise {
			// Tool-using native chat shares this path across interactive and CLI turns.
			cat, _ := loadEngageCatalog()
			ans, tokens, aerr := adviseLoop(ctx, assessmentChain, rc, cfg, cat, question, opts)
			return ans, []citation{}, false, []retrieval.Result{}, tokens, "rag", aerr
		}
		opts.NoLocal = !enabled.Local
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
