package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

// nativeturn.go owns one conversational turn. It is the only place a turn
// assembles AnswerOpts and the only place a turn is persisted, so every entry
// point (ask, the plain REPL, the TUI, the MCP chat tool) reaches the same
// routing, tools, persona and session store by construction rather than by
// each caller agreeing to build the same thing.

// turnRequest is one turn's input. Zero values are the defaults: no session,
// auto specialist, the sandbox tool host, adaptive routing.
type turnRequest struct {
	Question string
	// SessionID selects the conversation. Empty is a stateless turn that
	// persists nothing. See sessionTarget for the resolving forms.
	SessionID string
	Agent     string
	// Model names the model to answer with. Empty resolves the served model.
	Model    string
	ToolHost string
	// BrowserCDP copies signed-in state from an explicit loopback CDP browser.
	BrowserCDP string
	// ForceRag skips adaptive routing and always grounds locally.
	ForceRag bool
	// WebOnly answers from the public web for this turn only.
	WebOnly bool
	// WebFirst requires a live search before answering a question with target details.
	WebFirst bool
	Preface  string
	// History is the caller's own conversation memory. A session turn reads its
	// memory from the session store instead and ignores this field.
	History []priorTurn
	// Stream receives answer bytes as they arrive; nil collects silently.
	Stream func([]byte)
	// Stage receives pipeline and tool progress text for display.
	Stage func(stage string)
	// Action receives one tool call's name with "running", then with the status
	// the call settled on, so a streaming caller reports tool activity as it
	// happens rather than only in the result's Actions.
	Action func(tool, status string)
	// Persona receives the chosen expert's domain key.
	Persona func(domain string)
	// Browser carries browser state across turns in one session.
	Browser *chatBrowserState
	// Vantage is the caller's. The zero value is remote; see clientVantage.
	Vantage clientVantage
}

// Session selectors for turnRequest.SessionID. Any other non-empty value is a
// session id, which must exist.
const (
	// sessionTargetNew starts a fresh session and persists the turn.
	sessionTargetNew = "new"
	// sessionTargetLast continues the most recent session, starting one when
	// there is none.
	sessionTargetLast = "last"
)

// resolveTurnSession returns the session a turn writes to, or nil for a
// stateless turn. An explicit id must already exist: answering a mistyped id as
// a fresh conversation would silently discard the history the caller asked for.
func resolveTurnSession(selector string) (*session, error) {
	switch selector {
	case "":
		return nil, nil
	case sessionTargetNew:
		return newSession()
	case sessionTargetLast:
		metas, err := listSessions()
		if err != nil {
			return nil, err
		}
		if len(metas) == 0 {
			return newSession()
		}
		return openSessionFor(metas[0].ID)
	default:
		return openSessionFor(selector)
	}
}

// openSessionFor opens an existing session by id. The id is untrusted input
// from a CLI flag, an MCP tool call or an HTTP request, so it is validated
// before it can reach a file path.
func openSessionFor(id string) (*session, error) {
	if !validSessionID(id) {
		return nil, usageErr("turn: invalid session id")
	}
	if sessionExists(id) {
		return openSession(id)
	}
	if store := openSessionStore(); store != nil {
		if _, ok, err := store.GetSessionRow(context.Background(), id); err == nil && ok {
			return attachSession(id)
		}
	}
	return nil, sessionNotFound(id)
}

// turnLock is one session's in-process turn lock plus the number of turns
// holding or waiting for it.
type turnLock struct {
	mu      sync.Mutex
	holders int
}

// The in-process turn locks, one per session id in use. The transcript flock
// taken in session.lock is per open file description, so two session handles in
// one process do not exclude each other: without this, two turns on one id both
// read the same history, both answer, and the one that persists second answered
// without ever seeing the other's question.
var (
	turnLocksMu sync.Mutex
	turnLocks   = map[string]*turnLock{}
)

// lockTurnSession blocks until this process holds the turn lock for id and
// returns its release. The entry is dropped when its last holder leaves, so the
// table holds one lock per session with a turn in flight rather than one per
// session a long-lived server has ever opened.
func lockTurnSession(id string) func() {
	turnLocksMu.Lock()
	l := turnLocks[id]
	if l == nil {
		l = &turnLock{}
		turnLocks[id] = l
	}
	l.holders++
	turnLocksMu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		turnLocksMu.Lock()
		l.holders--
		if l.holders == 0 {
			delete(turnLocks, id)
		}
		turnLocksMu.Unlock()
	}
}

// turnHistory reads a session's committed messages as conversation memory. A
// read failure yields no memory rather than failing the turn, so a damaged
// store degrades to a stateless answer instead of refusing to answer.
func turnHistory(sess *session) []priorTurn {
	if sess == nil {
		return nil
	}
	store := openSessionStore()
	if store == nil {
		return nil
	}
	recs, err := store.Messages(context.Background(), sess.id)
	if err != nil {
		return nil
	}
	out := make([]priorTurn, 0, len(recs))
	for _, r := range recs {
		out = append(out, priorTurn{Role: r.Role, Content: r.Content})
	}
	return out
}

// persistTurn writes one completed exchange: both transcript lines, then the
// single commit that records the memory rows and the transcript length they
// account for. A process interrupted between them leaves a tail that
// reconcileTranscript removes when the session is next opened.
func persistTurn(sess *session, model, question, answer string, tokens int) error {
	if sess == nil || strings.TrimSpace(answer) == "" {
		return nil
	}
	defer sess.endTurn()
	if err := sess.appendTurn(turnRecord{Role: roleUser, Content: question, Model: model}); err != nil {
		return err
	}
	if err := sess.appendTurn(turnRecord{Role: roleAssistant, Content: answer, Model: model, Tokens: tokens}); err != nil {
		return err
	}
	return sess.commitTurn(question, answer)
}

// turnAction is one tool call the turn made. Status is "running" while the call
// is in flight, then one of ToolDone, ToolFailed or ToolSkipped.
//   - done: the tool ran to completion. A replay or memo of completed calls
//     keys on this status alone.
//   - failed: the call was attempted and may have had a side effect before it
//     errored.
//   - running: the turn ended before an outcome was recorded; the call may have
//     run.
//   - skipped: the only status known not to have run the tool.
//
// A row carries the tool name and no arguments, so two calls to one tool with
// different arguments are indistinguishable here.
type turnAction struct {
	Tool   string `json:"tool"`
	Status string `json:"status"`
}

// turnUsage is what the turn cost.
type turnUsage struct {
	CompletionTokens int            `json:"completion_tokens,omitempty"`
	ElapsedMS        int64          `json:"elapsed_ms"`
	LLMCalls         []llmCallStats `json:"llm_calls,omitempty"`
	LLMCallsPartial  bool           `json:"llm_calls_partial,omitempty"`
}

// turnResult is one turn's output, shaped so blk ask --json, the MCP chat tool
// and the HTTP surface report the same fields.
type turnResult struct {
	SessionID string     `json:"session_id,omitempty"`
	Answer    string     `json:"answer"`
	Citations []citation `json:"citations"`
	UsedWeb   bool       `json:"used_web"`
	// Model is the model that answered, which is the model blk requested unless
	// a failover moved the answer to the next model in the role's chain.
	Model   string             `json:"model"`
	Agent   string             `json:"agent,omitempty"`
	Route   string             `json:"route,omitempty"`
	Actions []turnAction       `json:"actions,omitempty"`
	Usage   turnUsage          `json:"usage"`
	Results []retrieval.Result `json:"results,omitempty"`
}

// runNativeTurn answers one turn. rc may be nil for a web-only turn or when the
// caller has no long-lived retrieval client; cfg is the resolved rag config.
func runNativeTurn(ctx context.Context, rc *retrieval.Client, cfg ragconfig.Config, req turnRequest) (turnResult, error) {
	question := strings.TrimSpace(req.Question)
	if question == "" {
		return turnResult{}, usageErr("turn: missing question")
	}
	agent, err := parseAnswerAgent(req.Agent)
	if err != nil {
		return turnResult{}, usageErr("%s", err)
	}
	toolHost := req.ToolHost
	if toolHost == "" {
		toolHost = chatToolHostSandbox
	}
	if toolHost != chatToolHostSandbox && toolHost != chatToolHostLocal {
		return turnResult{}, usageErr("turn: tool host must be %s or %s", chatToolHostSandbox, chatToolHostLocal)
	}
	if req.BrowserCDP != "" {
		if err := webValidateCDPEndpoint(req.BrowserCDP); err != nil {
			return turnResult{}, usageErr("turn: %s", err)
		}
	}

	// A session turn holds that session's turn lock for the whole turn, from
	// before the history read to after the persist, so concurrent turns on one
	// session run one at a time. A named id is locked before the session is
	// opened, because opening it takes the transcript flock, which a second
	// handle in this process does not wait for. A stateless turn takes no lock.
	locked := ""
	if id := req.SessionID; id != "" && id != sessionTargetNew && id != sessionTargetLast {
		defer lockTurnSession(id)()
		locked = id
	}
	sess, err := resolveTurnSession(req.SessionID)
	if err != nil {
		return turnResult{}, err
	}
	if sess != nil && sess.id != locked {
		defer lockTurnSession(sess.id)()
	}
	history := req.History
	if sess != nil {
		history = turnHistory(sess)
	}

	metrics, _ := ctx.Value(metricsKey{}).(*callMetrics)
	if metrics == nil {
		ctx, metrics = withCallMetrics(ctx)
	}
	started := time.Now()

	// Both chains are resolved once here, and opts.Model carries only what the
	// caller named. Resolving the model for the caller instead would make every
	// turn look like an explicit pick to roleChains, which answers an explicit
	// pick with that one model for both roles.
	routerIDs, assessmentIDs := roleChains(cfg, req.Model)
	var routerChain, assessmentChain *modelChain
	if len(routerIDs) > 0 {
		routerChain, err = newModelChain(cfg, routerIDs)
		if err != nil {
			return turnResult{}, err
		}
	}
	if len(assessmentIDs) > 0 {
		assessmentChain, err = newModelChain(cfg, assessmentIDs)
		if err != nil {
			return turnResult{}, err
		}
	}
	// The turn reports the model that answers it, which is the assessment
	// chain's: its primary until a call succeeds, then the model that answered.
	// A chain is empty only when roleChains found no model at all, which is the
	// blank id a turn records today.
	turnModel := assessmentChain.primary()

	var actions []turnAction
	prefs := loadPrefs()
	chosenAgent := "general"
	opts := AnswerOpts{
		Agent:      agent,
		ToolHost:   toolHost,
		BrowserCDP: req.BrowserCDP,
		Browser:    req.Browser,
		Model:      strings.TrimSpace(req.Model),
		History:    history,
		Preface:    req.Preface,
		NoWeb:      !prefs.Web,
		WebOnly:    req.WebOnly,
		WebFirst:   req.WebFirst,
		Stream:     req.Stream,
		Stage:      req.Stage,
		Action: func(tool, status string) {
			actions = append(actions, turnAction{Tool: tool, Status: status})
			if req.Action != nil {
				req.Action(tool, status)
			}
		},
		Persona: func(domain string) {
			chosenAgent = answerAgentName(domain)
			if req.Persona != nil {
				req.Persona(domain)
			}
		},
		routerChain:     routerChain,
		assessmentChain: assessmentChain,
		vantage:         req.Vantage,
	}

	answer, cits, usedWeb, results, tokens, route, err := adaptiveAnswerFn(ctx, rc, cfg, question, askRoutes(prefs), req.ForceRag, opts)
	if err != nil && strings.TrimSpace(answer) == "" {
		return turnResult{}, err
	}
	if err == nil {
		if answered := assessmentChain.answered(); answered != "" {
			turnModel = answered
		}
	}

	calls, partial := metrics.snapshot()
	res := turnResult{
		Answer:    answer,
		Citations: cits,
		UsedWeb:   usedWeb,
		Model:     turnModel,
		Agent:     chosenAgent,
		Route:     route,
		Actions:   collapseActions(actions),
		Usage: turnUsage{
			CompletionTokens: tokens,
			ElapsedMS:        time.Since(started).Milliseconds(),
			LLMCalls:         calls,
			LLMCallsPartial:  partial,
		},
		Results: results,
	}
	if res.Citations == nil {
		res.Citations = []citation{}
	}
	if sess != nil {
		res.SessionID = sess.id
		// A turn the router failed is not recorded. Its answer is whatever had
		// streamed before the failure, and a later turn in this session reads the
		// transcript back as settled memory, so persisting a truncated answer
		// would carry it into every turn that follows. The answer still reaches
		// the caller with the error.
		if err == nil {
			if perr := persistTurn(sess, turnModel, question, answer, tokens); perr != nil {
				return res, fmt.Errorf("conversation save failed: %w", perr)
			}
		}
	}
	return res, err
}

// collapseActions keeps one entry per tool call, preferring the terminal status
// so a reader sees what finished rather than two rows per call. Order is the
// order the calls started.
func collapseActions(in []turnAction) []turnAction {
	if len(in) == 0 {
		return nil
	}
	out := make([]turnAction, 0, len(in))
	index := make(map[string]int, len(in))
	for _, a := range in {
		if at, ok := index[a.Tool]; ok && a.Status != "running" {
			out[at].Status = a.Status
			continue
		}
		index[a.Tool] = len(out)
		out = append(out, a)
	}
	return out
}

// errSessionNotFound is returned when a caller names a session that does not
// exist, so a mistyped id is never answered as a fresh conversation.
var errSessionNotFound = errors.New("session not found")

func sessionNotFound(id string) error {
	return fmt.Errorf("%w: %s", errSessionNotFound, sanitizeTerminal(id))
}
