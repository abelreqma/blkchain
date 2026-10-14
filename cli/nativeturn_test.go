package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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

// A turn the router failed part-way returns what streamed and records nothing:
// the transcript and the memory rows are a later turn's memory, so a truncated
// answer must not reach them. Every surface takes this path or already skipped
// its own record.
func TestNativeTurnDoesNotPersistAnErroredTurn(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	prev := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = prev })
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		if opts.Stream != nil {
			opts.Stream([]byte("partial answer"))
		}
		return "partial answer", []citation{}, false, nil, 3, "rag", errors.New("router exploded")
	}

	res, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q", SessionID: sessionTargetNew})
	if err == nil {
		t.Fatal("the router error was swallowed")
	}
	if res.Answer != "partial answer" {
		t.Fatalf("the partial answer was lost: %q", res.Answer)
	}
	if res.SessionID == "" {
		t.Fatal("the turn did not report the session it belonged to")
	}
	if sessionExists(res.SessionID) {
		recs, _ := loadMessages(res.SessionID)
		t.Fatalf("an errored turn reached the transcript: %+v", recs)
	}
	store := openSessionStore()
	if store == nil {
		t.Fatal("history store unavailable")
	}
	if rows, err := store.Messages(context.Background(), res.SessionID); err != nil || len(rows) != 0 {
		t.Fatalf("an errored turn reached conversation memory: %+v, %v", rows, err)
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

// Two turns on one session id run one at a time: the second reads the first's
// exchange back as memory, both answers come back, and the transcript holds
// both exchanges as whole user/assistant pairs.
func TestNativeTurnSerializesTurnsOnOneSession(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "seed answer", nil)
	seed, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q0", SessionID: sessionTargetNew})
	if err != nil {
		t.Fatal(err)
	}

	prev := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = prev })
	var mu sync.Mutex
	var read []int
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, question string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		mu.Lock()
		read = append(read, len(opts.History))
		mu.Unlock()
		// Hold the turn open. Overlapping turns would both have read the history
		// above before either appended to it.
		time.Sleep(100 * time.Millisecond)
		return "answer to " + question, []citation{}, false, nil, 1, "rag", nil
	}

	var wg sync.WaitGroup
	answers, errs := make([]string, 2), make([]error, 2)
	for i, q := range []string{"qA", "qB"} {
		wg.Add(1)
		go func(i int, q string) {
			defer wg.Done()
			res, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: q, SessionID: seed.SessionID})
			answers[i], errs[i] = res.Answer, err
		}(i, q)
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("turn %d failed: %v", i, errs[i])
		}
		if answers[i] == "" {
			t.Fatalf("turn %d returned no answer", i)
		}
	}

	mu.Lock()
	lengths := slices.Clone(read)
	mu.Unlock()
	slices.Sort(lengths)
	if !slices.Equal(lengths, []int{2, 4}) {
		t.Fatalf("the two turns read history of lengths %v, want 2 then 4", lengths)
	}
	recs, err := loadMessages(seed.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 6 {
		t.Fatalf("transcript has %d records, want 6", len(recs))
	}
	for i, rec := range recs {
		want := roleUser
		if i%2 == 1 {
			want = roleAssistant
		}
		if rec.Role != want {
			t.Fatalf("record %d role = %q, want %q", i, rec.Role, want)
		}
	}
}

func TestNativeTurnReportsPersistenceFailureWithTheAnswer(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	// An answer whose transcript line would pass maxSessionRecordBytes is refused
	// by appendTurn, so the turn answers and then fails to persist, which is the
	// case this test is about: the caller keeps the answer and is told.
	big := strings.Repeat("y", maxSessionRecordBytes)
	stubAdaptiveAnswer(t, big, nil)

	res, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q1", SessionID: sessionTargetNew})
	if err == nil {
		t.Fatal("a refused transcript write was not reported")
	}
	if !errors.Is(err, errSessionRecordTooLarge) {
		t.Fatalf("error is not the record-cap refusal: %v", err)
	}
	if res.Answer != big {
		t.Fatalf("the answer was lost when persistence failed: %d bytes", len(res.Answer))
	}
}

// Each call of a tool keeps its own row: a second running after a settled call
// opens a new row rather than overwriting the first call's outcome.
func TestCollapseActionsKeepsOneRowPerCallOfARepeatedTool(t *testing.T) {
	got := collapseActions([]turnAction{
		{Tool: "run_command", Status: "running"},
		{Tool: "run_command", Status: "done"},
		{Tool: "run_command", Status: "running"},
		{Tool: "run_command", Status: "failed"},
	})
	want := []turnAction{{Tool: "run_command", Status: "done"}, {Tool: "run_command", Status: "failed"}}
	if !slices.Equal(got, want) {
		t.Fatalf("rows = %+v, want %+v", got, want)
	}
}

func TestCollapseActionsLeavesAnUnsettledCallRunning(t *testing.T) {
	got := collapseActions([]turnAction{
		{Tool: "run_command", Status: "running"},
		{Tool: "run_command", Status: "done"},
		{Tool: "run_command", Status: "running"},
	})
	want := []turnAction{{Tool: "run_command", Status: "done"}, {Tool: "run_command", Status: "running"}}
	if !slices.Equal(got, want) {
		t.Fatalf("rows = %+v, want %+v", got, want)
	}
	lone := collapseActions([]turnAction{{Tool: "kb_search", Status: "running"}})
	if !slices.Equal(lone, []turnAction{{Tool: "kb_search", Status: "running"}}) {
		t.Fatalf("a lone running call = %+v, want it to stay running", lone)
	}
}

// TestNativeTurnCarriesTheCallerVantage pins that the caller's vantage reaches
// the tool registry's options, and that a request that does not set one is
// remote, so a surface added without establishing its caller gets no tool that
// reaches this host.
func TestNativeTurnCarriesTheCallerVantage(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	prev := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = prev })
	var seen clientVantage
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		seen = opts.vantage
		return "an answer", []citation{}, false, nil, 1, "rag", nil
	}
	for _, c := range []struct {
		req  clientVantage
		want clientVantage
	}{{vantageLocal, vantageLocal}, {vantageRemote, vantageRemote}, {clientVantage(0), vantageRemote}} {
		seen = clientVantage(-1)
		if _, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "q", Vantage: c.req}); err != nil {
			t.Fatal(err)
		}
		if seen != c.want {
			t.Errorf("request vantage %v reached the registry as %v, want %v", c.req, seen, c.want)
		}
	}
}
