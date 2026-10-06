package main

import (
	"context"
	"strings"
	"testing"
)

func TestClearStartsFreshMemoryAndPreservesSavedSession(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	old := m.sess.id
	m.pendingQ = "first question"
	m.recordTurn("first answer")
	m.attachments = []attachment{{path: "notes.txt", content: "notes"}}
	nm, _ := m.clearScrollback("")
	m = nm.(model)
	if m.sess.id == old || len(m.conversationHistory()) != 0 || len(m.attachments) != 0 {
		t.Fatal("clear retained current context")
	}
	turns, err := m.hist.Messages(context.Background(), old)
	if err != nil || len(turns) != 2 {
		t.Fatal("clear erased the saved session")
	}
}

func TestUndoChangesNextAnswerAndReopenedHistory(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.pendingQ = "first question"
	m.recordTurn("first answer")
	m.pendingQ = "second question"
	m.recordTurn("second answer")
	nm, _ := m.undo("")
	m = nm.(model)
	turns := m.conversationHistory()
	if len(turns) != 2 || turns[0].Content != "first question" {
		t.Fatalf("undo kept %v", turns)
	}
	replay, err := loadMessages(m.sess.id)
	if err != nil || len(replay) != 2 {
		t.Fatalf("replay differs: %v, %v", replay, err)
	}
	nm, _ = m.openHistorySessionInto(m.sess.id)
	if len(nm.(model).conversationHistory()) != 2 {
		t.Fatal("reopen restored undone exchange")
	}
}

func TestScopedHelpSupportsInteractiveCommands(t *testing.T) {
	for _, name := range []string{"model", "history", "clear", "undo", "copy", "attach", "editor", "viz", "rag", "auto", "safe", "mode"} {
		got := stripANSI(helpResponse(name, 80))
		if strings.Contains(got, "unknown command") || !strings.Contains(got, "/"+name) {
			t.Errorf("%s: %s", name, got)
		}
	}
}

func TestUndoMemoryFailureKeepsTranscript(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.pendingQ = "question"
	m.recordTurn("answer")
	m.hist.Close()
	nm, _ := m.undo("")
	m = nm.(model)
	recs, err := loadMessages(m.sess.id)
	if err != nil || len(recs) != 2 {
		t.Fatalf("failed memory operation changed transcript: %v, %v", recs, err)
	}
}

func TestUndoPreservesUnfinishedExchange(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.pendingQ = "question"
	m.recordTurn("answer")
	if err := m.hist.AppendUser(context.Background(), m.sess.id, "unfinished"); err != nil {
		t.Fatal(err)
	}
	nm, _ := m.undo("")
	m = nm.(model)
	if len(m.conversationHistory()) != 3 || m.sess.count != 2 {
		t.Fatal("undo discarded an unfinished exchange")
	}
}

func TestUndoRejectsMismatchedTranscriptAndMemory(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.pendingQ = "first question"
	m.recordTurn("first answer")
	m.pendingQ = "second question"
	m.recordTurn("second answer")
	if err := m.sess.appendTurn(turnRecord{Role: roleTombstone}); err != nil {
		t.Fatal(err)
	}
	if err := m.undoConversation(); err == nil {
		t.Fatal("undo accepted inconsistent stores")
	}
	memory, err := m.hist.Messages(context.Background(), m.sess.id)
	if err != nil || len(memory) != 4 {
		t.Fatalf("rejected undo changed memory: %v, %v", memory, err)
	}
	replay, err := loadMessages(m.sess.id)
	if err != nil || len(replay) != 2 {
		t.Fatalf("rejected undo changed transcript: %v, %v", replay, err)
	}
}
