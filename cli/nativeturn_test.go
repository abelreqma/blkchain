package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

// stubAdaptiveAnswer replaces the router for one test and restores it after.
// capture receives the AnswerOpts the turn assembled, which is what these tests
// are really asserting on: one function builds the options.
func stubAdaptiveAnswer(t *testing.T, answer string, capture *AnswerOpts) {
	t.Helper()
	prev := adaptiveAnswerFn
	adaptiveAnswerFn = func(ctx context.Context, rc searcher, cfg ragconfig.Config, question string, enabled enabledRoutes, force bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		if capture != nil {
			*capture = opts
		}
		if opts.Action != nil {
			opts.Action("kb_search", "running")
			opts.Action("kb_search", "done")
		}
		if opts.Stream != nil {
			opts.Stream([]byte(answer))
		}
		return answer, []citation{}, false, []retrieval.Result{}, 7, "rag", nil
	}
	t.Cleanup(func() { adaptiveAnswerFn = prev })
}

func TestNativeTurnReturnsAnswerAndRecordsActions(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	var opts AnswerOpts
	stubAdaptiveAnswer(t, "native answer", &opts)

	res, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "what is SSRF?"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Answer != "native answer" {
		t.Fatalf("answer = %q", res.Answer)
	}
	if res.Route != "rag" || res.Usage.CompletionTokens != 7 {
		t.Fatalf("route = %q tokens = %d", res.Route, res.Usage.CompletionTokens)
	}
	if len(res.Actions) != 1 || res.Actions[0].Tool != "kb_search" || res.Actions[0].Status != "done" {
		t.Fatalf("actions = %+v", res.Actions)
	}
	if res.SessionID != "" {
		t.Fatalf("a stateless turn must not report a session, got %q", res.SessionID)
	}
}

func TestNativeTurnDefaultsToolHostToSandbox(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	var opts AnswerOpts
	stubAdaptiveAnswer(t, "ok", &opts)

	if _, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q"}); err != nil {
		t.Fatal(err)
	}
	if opts.ToolHost != chatToolHostSandbox {
		t.Fatalf("tool host = %q, want %q", opts.ToolHost, chatToolHostSandbox)
	}
}

func TestNativeTurnRejectsEmptyQuestion(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	for _, q := range []string{"", "   ", "\t\n"} {
		if _, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: q}); err == nil {
			t.Fatalf("empty question %q was accepted", q)
		}
	}
}

func TestNativeTurnRejectsUnknownAgent(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	_, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q", Agent: "not-a-specialist"})
	if err == nil {
		t.Fatal("unknown agent was accepted")
	}
	if !strings.Contains(err.Error(), "agent") {
		t.Fatalf("error does not name the agent problem: %v", err)
	}

	_, err = runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q", Agent: strings.Repeat("a", 65)})
	if err == nil {
		t.Fatal("oversized agent name was accepted")
	}
}

func TestNativeTurnRejectsBadToolHost(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	_, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q", ToolHost: "elsewhere"})
	if err == nil {
		t.Fatal("unknown tool host was accepted")
	}
}

func TestNativeTurnSurfacesRouterError(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	prev := adaptiveAnswerFn
	adaptiveAnswerFn = func(ctx context.Context, rc searcher, cfg ragconfig.Config, question string, enabled enabledRoutes, force bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		return "", nil, false, nil, 0, "", errors.New("router exploded")
	}
	t.Cleanup(func() { adaptiveAnswerFn = prev })

	if _, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q"}); err == nil {
		t.Fatal("router error was swallowed")
	}
}
