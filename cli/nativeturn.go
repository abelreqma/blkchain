package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	ToolHost  string
	// BrowserCDP copies signed-in state from an explicit loopback CDP browser.
	BrowserCDP string
	// ForceRag skips adaptive routing and always grounds locally.
	ForceRag bool
	// WebOnly answers from the public web for this turn only.
	WebOnly bool
	Preface string
	// Stream receives answer bytes as they arrive; nil collects silently.
	Stream func([]byte)
	// Stage receives pipeline and tool progress text for display.
	Stage func(stage string)
	// Persona receives the chosen expert's domain key.
	Persona func(domain string)
	// Browser carries browser state across turns in one session.
	Browser *chatBrowserState
}

// turnAction is one tool call the turn made.
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
	SessionID string             `json:"session_id,omitempty"`
	Answer    string             `json:"answer"`
	Citations []citation         `json:"citations"`
	UsedWeb   bool               `json:"used_web"`
	Model     string             `json:"model"`
	Agent     string             `json:"agent,omitempty"`
	Route     string             `json:"route,omitempty"`
	Actions   []turnAction       `json:"actions,omitempty"`
	Usage     turnUsage          `json:"usage"`
	Results   []retrieval.Result `json:"results,omitempty"`
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

	ctx, metrics := withCallMetrics(ctx)
	started := time.Now()

	var actions []turnAction
	prefs := loadPrefs()
	chosenAgent := "general"
	opts := AnswerOpts{
		Agent:      agent,
		ToolHost:   toolHost,
		BrowserCDP: req.BrowserCDP,
		Browser:    req.Browser,
		Model:      resolveModel(cfg),
		Preface:    req.Preface,
		NoWeb:      !prefs.Web,
		WebOnly:    req.WebOnly,
		Stream:     req.Stream,
		Stage:      req.Stage,
		Action: func(tool, status string) {
			actions = append(actions, turnAction{Tool: tool, Status: status})
		},
		Persona: func(domain string) {
			chosenAgent = answerAgentName(domain)
			if req.Persona != nil {
				req.Persona(domain)
			}
		},
	}

	answer, cits, usedWeb, results, tokens, route, err := adaptiveAnswerFn(ctx, rc, cfg, question, askRoutes(prefs), req.ForceRag, opts)
	if err != nil && strings.TrimSpace(answer) == "" {
		return turnResult{}, err
	}

	calls, partial := metrics.snapshot()
	res := turnResult{
		Answer:    answer,
		Citations: cits,
		UsedWeb:   usedWeb,
		Model:     opts.Model,
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
