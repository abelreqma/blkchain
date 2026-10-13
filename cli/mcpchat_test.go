package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/skillcat"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPChatOpensAndContinuesASession(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "mcp answer", nil)

	first, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "q1"})
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
	second, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "q2", SessionID: first.SessionID})
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
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "from mcp", nil)

	res, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "q"})
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
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	// Well-formed ids that name no session reach the lookup and fail there.
	for _, id := range []string{"20260101T000000-aaaaaa", "with space"} {
		_, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "q", SessionID: id})
		if !errors.Is(err, errSessionNotFound) {
			t.Fatalf("unknown session id %q: error = %v, want session not found", id, err)
		}
	}
	// Path-shaped ids must be rejected before the lookup. An error that wraps
	// errSessionNotFound means the id reached the file-path code.
	for _, id := range []string{"../../etc/passwd", "a/b", "..", `a\b`} {
		_, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "q", SessionID: id})
		if err == nil {
			t.Fatalf("session id %q was accepted", id)
		}
		if errors.Is(err, errSessionNotFound) {
			t.Fatalf("malformed session id %q reached the lookup instead of being rejected: %v", id, err)
		}
	}
}

func TestMCPChatSessionIDIsNotASelector(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	// A rejected id must not reach the lookup: a not-found error would mean the
	// length bound or the selector check did not run.
	for _, id := range []string{sessionTargetNew, sessionTargetLast, strings.Repeat("a", mcpChatMaxSessionID+1)} {
		_, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "q", SessionID: id})
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
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	for _, msg := range []string{"", "   "} {
		if _, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: msg}); err == nil {
			t.Fatalf("message %q was accepted", msg)
		}
	}
}

func TestMCPChatRejectsOversizeMessage(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	big := strings.Repeat("a", mcpChatMaxMessage+1)
	if _, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: big}); err == nil {
		t.Fatal("oversize message accepted")
	}
}

func TestMCPChatRejectsUnknownAgent(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	_, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "q", Agent: "nope"})
	if err == nil {
		t.Fatal("unknown agent accepted")
	}
	if !strings.Contains(err.Error(), "agent") {
		t.Fatalf("error does not name the agent: %v", err)
	}
}

func TestMCPChatKeepsTheAnswerWhenPersistenceFails(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	// Two turns of a 3 MiB answer push the transcript past maxSessionBytes, so
	// the third turn's first append is refused after its answer is produced.
	big := strings.Repeat("y", 3<<20)
	stubAdaptiveAnswer(t, big, nil)

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
	if second := call(map[string]any{"message": "q2", "session_id": id}); second.IsError {
		t.Fatalf("second turn failed: %+v", second.Content)
	}

	third := call(map[string]any{"message": "q3", "session_id": id})
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
