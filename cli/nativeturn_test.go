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

func TestNativeTurnUsesTheRequestedModel(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	var opts AnswerOpts
	stubAdaptiveAnswer(t, "ok", &opts)

	res, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q", Model: " picked-model "})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Model != "picked-model" || res.Model != "picked-model" {
		t.Fatalf("model = %q, result model = %q, want picked-model", opts.Model, res.Model)
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

func TestNativeTurnNewSessionPersistsTheExchange(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "persisted answer", nil)

	res, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{
		Question:  "first question",
		SessionID: sessionTargetNew,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.SessionID == "" {
		t.Fatal("a new session turn reported no session id")
	}
	recs, err := loadMessages(res.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Role != roleUser || recs[1].Role != roleAssistant {
		t.Fatalf("transcript = %+v", recs)
	}
	if recs[0].Content != "first question" || recs[1].Content != "persisted answer" {
		t.Fatalf("transcript content = %+v", recs)
	}
}

func TestNativeTurnContinuesNamedSessionWithHistory(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "first answer", nil)

	first, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q1", SessionID: sessionTargetNew})
	if err != nil {
		t.Fatal(err)
	}

	var opts AnswerOpts
	stubAdaptiveAnswer(t, "second answer", &opts)
	second, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q2", SessionID: first.SessionID})
	if err != nil {
		t.Fatal(err)
	}
	if second.SessionID != first.SessionID {
		t.Fatalf("session id changed: %q then %q", first.SessionID, second.SessionID)
	}
	if len(opts.History) != 2 {
		t.Fatalf("history carried into the second turn = %+v", opts.History)
	}
	if opts.History[0].Content != "q1" || opts.History[1].Content != "first answer" {
		t.Fatalf("history content = %+v", opts.History)
	}
	recs, err := loadMessages(first.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 4 {
		t.Fatalf("transcript has %d records, want 4", len(recs))
	}
}

func TestNativeTurnLastResolvesTheMostRecentSession(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "a", nil)

	created, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q1", SessionID: sessionTargetNew})
	if err != nil {
		t.Fatal(err)
	}
	stubAdaptiveAnswer(t, "b", nil)
	latest, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q2", SessionID: sessionTargetLast})
	if err != nil {
		t.Fatal(err)
	}
	if latest.SessionID != created.SessionID {
		t.Fatalf("last resolved %q, want %q", latest.SessionID, created.SessionID)
	}
}

func TestNativeTurnLastWithNoSessionsStartsOne(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "a", nil)

	res, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q", SessionID: sessionTargetLast})
	if err != nil {
		t.Fatal(err)
	}
	if res.SessionID == "" {
		t.Fatal("last with no sessions should start one, got no id")
	}
}

func TestNativeTurnRejectsUnknownAndMalformedSessionIDs(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	for _, id := range []string{"20260101T000000-aaaaaa", "with space"} {
		_, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q", SessionID: id})
		if !errors.Is(err, errSessionNotFound) {
			t.Fatalf("unknown session id %q: error = %v, want session not found", id, err)
		}
	}
	for _, id := range []string{"../escape", "a/b", ".."} {
		_, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q", SessionID: id})
		if err == nil {
			t.Fatalf("session id %q was accepted", id)
		}
		if errors.Is(err, errSessionNotFound) {
			t.Fatalf("malformed session id %q reached the lookup instead of being rejected: %v", id, err)
		}
	}
}

func TestNativeTurnReportsPersistenceFailureWithTheAnswer(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	// appendTurn refuses only once the transcript is ALREADY at maxSessionBytes
	// (session.go:344), so grow it through the real path: two turns of a 3 MiB
	// answer leave the file over the 4 MiB cap, and the third turn's first
	// append is refused. Writing junk into the file directly would not work:
	// openSession runs reconcileTranscript, which truncates anything past the
	// last committed watermark.
	big := strings.Repeat("y", 3<<20)
	stubAdaptiveAnswer(t, big, nil)

	first, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q1", SessionID: sessionTargetNew})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q2", SessionID: first.SessionID}); err != nil {
		t.Fatal(err)
	}

	res, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q3", SessionID: first.SessionID})
	if err == nil {
		t.Fatal("a refused transcript write was not reported")
	}
	if !errors.Is(err, errSessionFull) {
		t.Fatalf("error is not the size-cap refusal: %v", err)
	}
	if res.Answer != big {
		t.Fatalf("the answer was lost when persistence failed: %d bytes", len(res.Answer))
	}
}
