package main

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestHistoryPickerEnablesFiltering(t *testing.T) {
	p := newHistoryPicker([]sessionMeta{{ID: "one", Title: "Research notes"}, {ID: "two", Title: "Source comparison"}}, "", 80)
	if !p.list.FilteringEnabled() {
		t.Fatal("history filter disabled")
	}
}

func TestHistoryDeletionRetainsRemainingFilteredSession(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.pendingQ = "research first"
	m.recordTurn("answer")
	if err := m.resetConversation(); err != nil {
		t.Fatal(err)
	}
	m.pendingQ = "research second"
	m.recordTurn("answer")
	nm, _ := m.dispatchInput("/history")
	p := nm.(model).overlay.(historyPicker)
	p.list.SetFilterText("research")
	if len(p.list.VisibleItems()) != 2 {
		t.Fatal("fixture did not filter both sessions")
	}
	op, _ := p.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	op, cmd := op.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	if cmd != nil {
		op, _ = op.Update(cmd())
	}
	p = op.(historyPicker)
	if len(p.list.VisibleItems()) != 1 {
		t.Fatalf("remaining filtered session hidden: %d", len(p.list.VisibleItems()))
	}
}

func TestHistoryPickerShowsLastQuestionPreview(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.width, m.height = 80, 24
	m.sess.title = "Source research"
	m.pendingQ = "Which source supports the setting?"
	m.recordTurn("A cited answer")
	nm, _ := m.dispatchInput("/history")
	m = nm.(model)
	if !strings.Contains(stripANSI(m.View()), "Which source supports the setting?") {
		t.Fatal("history preview missing")
	}
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("history no longer opens")
	}
	_ = nm
}

func TestHistoryRowsRetainUpdatedTimestamp(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.pendingQ = "Question"
	m.recordTurn("Answer")
	nm, _ := m.dispatchInput("/history")
	p := nm.(model).overlay.(historyPicker)
	if len(p.metas) != 1 || p.metas[0].UpdatedAt == 0 {
		t.Fatal("history timestamp discarded")
	}
	msgs, err := m.hist.Messages(context.Background(), m.sess.id)
	if err != nil || len(msgs) != 2 {
		t.Fatal("listing modified history")
	}
}

func TestHistorySelectionDuringTurnPreservesSessionOwnership(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	other, err := newSession()
	if err != nil {
		t.Fatal(err)
	}
	owner := m.sess.id
	m.working = true
	m.pendingQ = "running question"
	nm, _ := m.Update(historySelectedMsg{id: other.id})
	m = nm.(model)
	if m.sess.id != owner || m.pendingQ != "running question" {
		t.Fatal("history selection changed the running turn's session")
	}
	m.recordTurn("completed answer")
	memory, err := m.hist.Messages(context.Background(), owner)
	if err != nil || len(memory) != 2 {
		t.Fatal("completed answer was not saved to its original session")
	}
}
