package main

import (
	"context"
	"errors"
	"strings"
	"testing"
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

	for _, id := range []string{sessionTargetNew, sessionTargetLast, strings.Repeat("a", mcpChatMaxSessionID+1)} {
		if _, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "q", SessionID: id}); err == nil {
			t.Fatalf("session id %q was accepted", id)
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
