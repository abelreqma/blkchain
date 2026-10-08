package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestClearReplacesGatewayConversationIdentity(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.agentSession = "old-gateway-session"
	if err := m.resetConversation(); err != nil {
		t.Fatal(err)
	}
	if m.agentSession != "" {
		t.Fatal("clear retained gateway conversation identity")
	}
}

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

// Undo sorts the two kinds of divergence between the stores. A transcript tail
// past the committed watermark was never committed, so it is reconciled away and
// undo proceeds; a transcript that disagrees with memory inside the committed
// region cannot be reconciled from either side, so undo still refuses and
// leaves both stores untouched.
func TestUndoReconcilesAnUncommittedTailAndStillRejectsRealDivergence(t *testing.T) {
	seed := func(t *testing.T) model {
		t.Helper()
		m := newKeyModel(t)
		m.pendingQ = "first question"
		if err := m.recordTurn("first answer"); err != nil {
			t.Fatal(err)
		}
		m.pendingQ = "second question"
		if err := m.recordTurn("second answer"); err != nil {
			t.Fatal(err)
		}
		return m
	}

	t.Run("uncommitted tail is reconciled", func(t *testing.T) {
		useDeadServices(t)
		m := seed(t)
		// A transcript line no commit accounts for, as an interrupted turn leaves.
		if err := m.sess.appendTurn(turnRecord{Role: roleTombstone}); err != nil {
			t.Fatal(err)
		}
		if err := m.undoConversation(); err != nil {
			t.Fatalf("undo refused a reconcilable divergence: %v", err)
		}
		memory, err := m.hist.Messages(context.Background(), m.sess.id)
		if err != nil || len(memory) != 2 {
			t.Fatalf("undo did not remove the exchange from memory: %v, %v", memory, err)
		}
		replay, err := loadMessages(m.sess.id)
		if err != nil || len(replay) != 2 {
			t.Fatalf("transcript after undo = %v, %v", replay, err)
		}
	})

	t.Run("divergent content is still refused", func(t *testing.T) {
		useDeadServices(t)
		m := seed(t)
		// Rewrite a committed answer in place, keeping the byte length so the
		// watermark still covers the file and only the content disagrees.
		data, err := os.ReadFile(m.sess.filePath())
		if err != nil {
			t.Fatal(err)
		}
		edited := strings.Replace(string(data), "first answer", "FIRST ANSWER", 1)
		if edited == string(data) {
			t.Fatal("fixture did not change the transcript")
		}
		if err := os.WriteFile(m.sess.filePath(), []byte(edited), 0600); err != nil {
			t.Fatal(err)
		}
		if err := m.undoConversation(); err == nil {
			t.Fatal("undo accepted stores that disagree inside the committed region")
		}
		memory, err := m.hist.Messages(context.Background(), m.sess.id)
		if err != nil || len(memory) != 4 {
			t.Fatalf("refused undo changed memory: %v, %v", memory, err)
		}
		replay, err := loadMessages(m.sess.id)
		if err != nil || len(replay) != 4 {
			t.Fatalf("refused undo changed the transcript: %v, %v", replay, err)
		}
	})
}

func TestPersistenceFailureDoesNotMirrorAnUnsavedExchange(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	if err := os.WriteFile(m.sess.filePath(), []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(m.sess.filePath(), maxSessionBytes); err != nil {
		t.Fatal(err)
	}
	m.pendingQ = "fixture question"
	if err := m.recordTurn("fixture answer"); !errors.Is(err, errSessionFull) {
		t.Fatalf("persistence failure hidden: %v", err)
	}
	messages, err := m.hist.Messages(context.Background(), m.sess.id)
	if err != nil || len(messages) != 0 {
		t.Fatalf("unsaved exchange mirrored: %v %v", messages, err)
	}
}

// Undo drops the exchange locally, so the gateway's own conversation no longer
// matches this session and the next agent turn must start a new one. Pending
// context is not part of the undone exchange: attachments are consumed when a
// turn is sent, so anything staged now was staged afterwards and is kept.
func TestUndoReplacesGatewayConversationAndKeepsPendingContext(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.pendingQ = "first question"
	if err := m.recordTurn("first answer"); err != nil {
		t.Fatal(err)
	}
	m.agentSession = "old-gateway-session"
	m.attachments = []attachment{{path: "notes.txt", content: "notes"}}
	m.queue = []string{"queued question"}

	if err := m.undoConversation(); err != nil {
		t.Fatal(err)
	}

	if m.agentSession != "" {
		t.Errorf("undo retained the gateway conversation identity: %q", m.agentSession)
	}
	if len(m.attachments) != 1 {
		t.Errorf("undo dropped staged attachments: %v", m.attachments)
	}
	if len(m.queue) != 1 {
		t.Errorf("undo dropped the queued question: %v", m.queue)
	}
}

// Reopening a session switches conversation, so everything that belongs to the
// previous one goes: the gateway handle, the citation targets /open reads, the
// retained search results, and the attachments staged for it.
func TestReopenReplacesPreviousConversationContext(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.pendingQ = "first question"
	if err := m.recordTurn("first answer"); err != nil {
		t.Fatal(err)
	}
	id := m.sess.id

	for _, reopen := range []struct {
		name string
		call func(model) (tea.Model, tea.Cmd)
	}{
		{"openSessionInto", func(m model) (tea.Model, tea.Cmd) { return m.openSessionInto(id) }},
		{"openHistorySessionInto", func(m model) (tea.Model, tea.Cmd) { return m.openHistorySessionInto(id) }},
	} {
		t.Run(reopen.name, func(t *testing.T) {
			stale := m
			stale.agentSession = "old-gateway-session"
			stale.attachments = []attachment{{path: "notes.txt", content: "notes"}}
			stale.openTargets = []openTarget{{Path: "previous-citation.md"}}
			stale.lastQuery = "previous query"
			stale.lastCostSet = true

			nm, _ := reopen.call(stale)
			got := nm.(model)

			if got.agentSession != "" {
				t.Errorf("reopen retained the gateway conversation identity: %q", got.agentSession)
			}
			if len(got.attachments) != 0 {
				t.Errorf("reopen retained the previous session's attachments: %v", got.attachments)
			}
			if len(got.openTargets) != 0 {
				t.Errorf("reopen retained the previous session's open targets: %v", got.openTargets)
			}
			if got.lastQuery != "" || got.lastCostSet {
				t.Errorf("reopen retained the previous turn's query or cost: %q %v", got.lastQuery, got.lastCostSet)
			}
		})
	}
}
