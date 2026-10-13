package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/skillcat"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPChatOpensAndContinuesASession(t *testing.T) {
	owner := newChatSessionOwner()
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "mcp answer", nil)

	first, err := mcpChatResult(context.Background(), nil, loadConfig(), owner, mcpChatIn{Message: "q1"})
	if err != nil {
		t.Fatal(err)
	}
	if first.SessionID == "" {
		t.Fatal("chat with no session id did not open one")
	}
	if first.Answer != "mcp answer" {
		t.Fatalf("answer = %q", first.Answer)
	}

	var opts AnswerOpts
	stubAdaptiveAnswer(t, "mcp second", &opts)
	second, err := mcpChatResult(context.Background(), nil, loadConfig(), owner, mcpChatIn{Message: "q2", SessionID: first.SessionID})
	if err != nil {
		t.Fatal(err)
	}
	if second.SessionID != first.SessionID {
		t.Fatalf("session changed: %q then %q", first.SessionID, second.SessionID)
	}
	if len(opts.History) != 2 {
		t.Fatalf("history = %+v", opts.History)
	}
}

func TestMCPChatSessionIsReadableAsAnOrdinarySession(t *testing.T) {
	owner := newChatSessionOwner()
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "from mcp", nil)

	res, err := mcpChatResult(context.Background(), nil, loadConfig(), owner, mcpChatIn{Message: "q"})
	if err != nil {
		t.Fatal(err)
	}
	if !sessionExists(res.SessionID) {
		t.Fatalf("session %q has no transcript", res.SessionID)
	}
	recs, err := loadMessages(res.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("transcript = %+v", recs)
	}
}

func TestMCPChatRejectsHostileSessionIDs(t *testing.T) {
	owner := newChatSessionOwner()
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	// Well-formed ids this server never created are refused as foreign before
	// any lookup.
	for _, id := range []string{"20260101T000000-aaaaaa", "with space"} {
		_, err := mcpChatResult(context.Background(), nil, loadConfig(), owner, mcpChatIn{Message: "q", SessionID: id})
		if !errors.Is(err, errChatForeignSession) {
			t.Fatalf("unknown session id %q: error = %v, want a foreign-session refusal", id, err)
		}
	}
	// Path-shaped ids must be rejected before the lookup. An error that wraps
	// errSessionNotFound means the id reached the file-path code.
	for _, id := range []string{"../../etc/passwd", "a/b", "..", `a\b`} {
		_, err := mcpChatResult(context.Background(), nil, loadConfig(), owner, mcpChatIn{Message: "q", SessionID: id})
		if err == nil {
			t.Fatalf("session id %q was accepted", id)
		}
		if errors.Is(err, errSessionNotFound) {
			t.Fatalf("malformed session id %q reached the lookup instead of being rejected: %v", id, err)
		}
	}
}

func TestMCPChatSessionIDIsNotASelector(t *testing.T) {
	owner := newChatSessionOwner()
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	// A rejected id must not reach the lookup: a not-found error would mean the
	// length bound or the selector check did not run.
	for _, id := range []string{sessionTargetNew, sessionTargetLast, strings.Repeat("a", mcpChatMaxSessionID+1)} {
		_, err := mcpChatResult(context.Background(), nil, loadConfig(), owner, mcpChatIn{Message: "q", SessionID: id})
		if err == nil {
			t.Fatalf("session id %q was accepted", id)
		}
		if errors.Is(err, errSessionNotFound) {
			t.Fatalf("session id %q reached the lookup instead of being rejected: %v", id, err)
		}
	}
	metas, err := listSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 0 {
		t.Fatalf("a rejected session id created sessions: %+v", metas)
	}
}

func TestMCPChatRejectsEmptyMessage(t *testing.T) {
	owner := newChatSessionOwner()
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	for _, msg := range []string{"", "   "} {
		if _, err := mcpChatResult(context.Background(), nil, loadConfig(), owner, mcpChatIn{Message: msg}); err == nil {
			t.Fatalf("message %q was accepted", msg)
		}
	}
}

func TestMCPChatRejectsOversizeMessage(t *testing.T) {
	owner := newChatSessionOwner()
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	big := strings.Repeat("a", mcpChatMaxMessage+1)
	if _, err := mcpChatResult(context.Background(), nil, loadConfig(), owner, mcpChatIn{Message: big}); err == nil {
		t.Fatal("oversize message accepted")
	}
}

func TestMCPChatRejectsUnknownAgent(t *testing.T) {
	owner := newChatSessionOwner()
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	_, err := mcpChatResult(context.Background(), nil, loadConfig(), owner, mcpChatIn{Message: "q", Agent: "nope"})
	if err == nil {
		t.Fatal("unknown agent accepted")
	}
	if !strings.Contains(err.Error(), "agent") {
		t.Fatalf("error does not name the agent: %v", err)
	}
}

// chat continues only what it created: a session another surface opened is
// refused with its own error class and left untouched, while the server's own
// session continues, and either one is still readable as a resource.
func TestMCPChatRefusesASessionItDidNotCreate(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "an answer", nil)

	elsewhere, err := runNativeTurn(context.Background(), nil, loadConfig(), turnRequest{Question: "operator question", SessionID: sessionTargetNew})
	if err != nil {
		t.Fatal(err)
	}
	owner := newChatSessionOwner()
	_, err = mcpChatResult(context.Background(), nil, loadConfig(), owner, mcpChatIn{Message: "planted turn", SessionID: elsewhere.SessionID})
	if !errors.Is(err, errChatForeignSession) {
		t.Fatalf("continuing a foreign session: error = %v, want a foreign-session refusal", err)
	}
	if errors.Is(err, errSessionNotFound) {
		t.Fatalf("the refusal is indistinguishable from a missing session: %v", err)
	}
	recs, err := loadMessages(elsewhere.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("the refused turn changed the transcript: %+v", recs)
	}

	own, err := mcpChatResult(context.Background(), nil, loadConfig(), owner, mcpChatIn{Message: "q1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mcpChatResult(context.Background(), nil, loadConfig(), owner, mcpChatIn{Message: "q2", SessionID: own.SessionID}); err != nil {
		t.Fatalf("continuing its own session: %v", err)
	}

	// Reading stays unrestricted whatever created the session.
	for _, id := range []string{elsewhere.SessionID, own.SessionID} {
		if _, err := mcpSessionResource(id); err != nil {
			t.Fatalf("session %q is not readable as a resource: %v", id, err)
		}
	}
}

// A restarted server owns nothing, so the id it handed out before cannot be
// continued. That is the cost of keeping the write side in the process that
// opened the conversation.
func TestMCPChatOwnedSessionsDoNotSurviveARestart(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "an answer", nil)

	first, err := mcpChatResult(context.Background(), nil, loadConfig(), newChatSessionOwner(), mcpChatIn{Message: "q1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = mcpChatResult(context.Background(), nil, loadConfig(), newChatSessionOwner(), mcpChatIn{Message: "q2", SessionID: first.SessionID})
	if !errors.Is(err, errChatForeignSession) {
		t.Fatalf("after a restart: error = %v, want a foreign-session refusal", err)
	}
}

// The owned set is bounded: past mcpChatMaxSessions the oldest id is forgotten
// and the newest are kept.
func TestChatSessionOwnerForgetsTheOldestPastTheCap(t *testing.T) {
	owner := newChatSessionOwner()
	ids := make([]string, 0, mcpChatMaxSessions+1)
	for i := range mcpChatMaxSessions + 1 {
		id := fmt.Sprintf("20260101T000000-%06x", i)
		ids = append(ids, id)
		owner.own(id)
	}
	if owner.owns(ids[0]) {
		t.Fatalf("the oldest id was kept past the cap of %d", mcpChatMaxSessions)
	}
	for _, id := range ids[1:] {
		if !owner.owns(id) {
			t.Fatalf("id %q was forgotten while within the cap", id)
		}
	}
}

// The in-flight bound refuses the turn past the cap instead of queueing it, and
// a freed slot is reusable.
func TestAcquireChatSlotRefusesPastTheCap(t *testing.T) {
	slots := make(chan struct{}, mcpChatMaxInFlight)
	releases := make([]func(), 0, mcpChatMaxInFlight)
	for i := range mcpChatMaxInFlight {
		release, err := acquireChatSlot(context.Background(), slots)
		if err != nil {
			t.Fatalf("slot %d of %d was refused: %v", i+1, mcpChatMaxInFlight, err)
		}
		releases = append(releases, release)
	}
	if _, err := acquireChatSlot(context.Background(), slots); !errors.Is(err, errChatBusy) {
		t.Fatalf("past the cap: err = %v, want errChatBusy", err)
	}
	releases[0]()
	release, err := acquireChatSlot(context.Background(), slots)
	if err != nil {
		t.Fatalf("a freed slot was not reusable: %v", err)
	}
	release()
	for _, done := range releases[1:] {
		done()
	}
}

// A cancelled request takes no slot: it is refused with its own context error.
func TestAcquireChatSlotRefusesACancelledRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	slots := make(chan struct{}, 1)
	if _, err := acquireChatSlot(ctx, slots); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request: err = %v, want context.Canceled", err)
	}
	if len(slots) != 0 {
		t.Fatalf("a cancelled request took %d slots", len(slots))
	}
}

func TestMCPChatKeepsTheAnswerWhenPersistenceFails(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	// The first turn opens the session normally. The second answers with a line
	// past maxSessionRecordBytes, which appendTurn refuses after the answer is
	// produced.
	big := strings.Repeat("y", maxSessionRecordBytes)
	stubAdaptiveAnswer(t, "a recorded answer", nil)

	dir := t.TempDir()
	writeTestSkill(t, dir, "aaa-web", "---\nname: aaa-web\ndescription: web http attacks\n---\nWEBBODY\n")
	cat, err := skillcat.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := newMCPServer(&retrieval.Client{}, loadConfig(), cat)
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	call := func(args map[string]any) *mcp.CallToolResult {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "chat", Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	decode := func(res *mcp.CallToolResult) map[string]any {
		t.Helper()
		raw, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	first := call(map[string]any{"message": "q1"})
	if first.IsError {
		t.Fatalf("first turn failed: %+v", first.Content)
	}
	firstOut := decode(first)
	if msg, set := firstOut["error"]; set {
		t.Fatalf("a recorded turn reported an error: %v", msg)
	}
	id, _ := firstOut["session_id"].(string)
	if id == "" {
		t.Fatalf("no session id in %v", firstOut)
	}
	stubAdaptiveAnswer(t, big, nil)
	third := call(map[string]any{"message": "q2", "session_id": id})
	if third.IsError {
		t.Fatalf("the answer was returned as a tool error: %+v", third.Content)
	}
	out := decode(third)
	if answer, _ := out["answer"].(string); answer != big {
		t.Fatalf("the answer was lost when persistence failed: %d bytes", len(answer))
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "conversation save failed") {
		t.Fatalf("the failed save was not reported: error = %q", msg)
	}
}

// A chat turn whose router never returns is cut off at the configured request
// timeout instead of holding its slot open.
func TestMCPChatBoundsATurnByTheRequestTimeout(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	prev := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = prev })
	adaptiveAnswerFn = func(ctx context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, _ AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		select {
		case <-ctx.Done():
			return "", nil, false, nil, 0, "", ctx.Err()
		case <-time.After(5 * time.Second):
			return "returned without a deadline", nil, false, nil, 0, "rag", nil
		}
	}
	cfg := loadConfig()
	cfg.RequestTimeoutSeconds = 1

	start := time.Now()
	_, err := mcpChatResult(context.Background(), nil, cfg, newChatSessionOwner(), mcpChatIn{Message: "q"})
	if !errors.Is(err, errRequestTimeout) {
		t.Fatalf("error = %v, want the request-timeout error", err)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("the turn ran %s past a 1s timeout", elapsed)
	}
}

func setMCPServesStdio(t *testing.T, v bool) {
	t.Helper()
	prev := mcpServesStdio.Load()
	mcpServesStdio.Store(v)
	t.Cleanup(func() { mcpServesStdio.Store(prev) })
}

// Without the stdio fact, tool_host local is refused with its own error class
// before any turn runs, and the sandbox host is unaffected.
func TestMCPChatRefusesLocalToolHostWithoutStdio(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	setMCPServesStdio(t, false)
	var opts AnswerOpts
	stubAdaptiveAnswer(t, "sandboxed", &opts)

	_, err := mcpChatResult(context.Background(), nil, loadConfig(), newChatSessionOwner(), mcpChatIn{Message: "q", ToolHost: "local"})
	if !errors.Is(err, errChatLocalHostRefused) {
		t.Fatalf("local without stdio: error = %v, want errChatLocalHostRefused", err)
	}
	if errors.Is(err, errChatForeignSession) || errors.Is(err, errChatBusy) {
		t.Fatalf("the refusal is not distinguishable from another class: %v", err)
	}
	if opts.ToolHost != "" {
		t.Fatalf("a refused turn reached the router with host %q", opts.ToolHost)
	}

	for _, host := range []string{"", "sandbox"} {
		res, err := mcpChatResult(context.Background(), nil, loadConfig(), newChatSessionOwner(), mcpChatIn{Message: "q", ToolHost: host})
		if err != nil || res.Answer != "sandboxed" {
			t.Fatalf("host %q: answer=%q err=%v", host, res.Answer, err)
		}
		if opts.ToolHost != "sandbox" {
			t.Fatalf("host %q reached the router as %q", host, opts.ToolHost)
		}
	}
}

func TestMCPChatAcceptsLocalToolHostOverStdio(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	setMCPServesStdio(t, true)
	var opts AnswerOpts
	stubAdaptiveAnswer(t, "on the host", &opts)

	res, err := mcpChatResult(context.Background(), nil, loadConfig(), newChatSessionOwner(), mcpChatIn{Message: "q", ToolHost: "local"})
	if err != nil || res.Answer != "on the host" {
		t.Fatalf("answer=%q err=%v", res.Answer, err)
	}
	if opts.ToolHost != "local" {
		t.Fatalf("the router saw host %q, want local", opts.ToolHost)
	}
}

func TestMCPServesStdioIsOffByDefault(t *testing.T) {
	if mcpServesStdio.Load() {
		t.Fatal("mcpServesStdio is set outside runMCP; a transport that does not opt in must be refused")
	}
}
