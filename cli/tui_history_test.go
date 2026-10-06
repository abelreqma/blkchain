package main

import (
	"context"
	"testing"

	"blkchain/cli/internal/histstore"

	tea "github.com/charmbracelet/bubbletea"
)

// Cycle 3a seam: mergeHistoryMetas maps the langchaingo session list into the
// sessionMeta rows the resume picker renders, taking titles from the JSONL index
// by id and preserving the store's newest-first order.

func TestMergeHistoryMetasUsesTitlesAndPreservesOrder(t *testing.T) {
	hs := []histstore.SessionMeta{
		{ID: "s2", Count: 1},
		{ID: "s1", Count: 3},
	}
	titles := map[string]sessionMeta{"s1": {Title: "first session"}}

	got := mergeHistoryMetas(hs, titles)

	if len(got) != 2 {
		t.Fatalf("want 2 metas, got %d", len(got))
	}
	if got[0].ID != "s2" || got[0].Title != "s2" || got[0].MsgCount != 1 {
		t.Errorf("row0 = %+v, want {s2, title s2 (fallback to id), 1}", got[0])
	}
	if got[1].ID != "s1" || got[1].Title != "first session" || got[1].MsgCount != 3 {
		t.Errorf("row1 = %+v, want {s1, title 'first session', 3}", got[1])
	}
}

// Cycle 3b seam: recordTurn mirrors the completed exchange into the langchaingo
// history store (in addition to the JSONL transcript), keyed by session id.
func TestRecordTurnPersistsToHistStore(t *testing.T) {
	m := newKeyModel(t)
	if m.hist == nil {
		t.Fatal("initialModel should open a history store")
	}
	if m.sess == nil {
		t.Fatal("initialModel should create a session")
	}
	m.pendingQ = "what is xss"

	(&m).recordTurn("an answer")

	msgs, err := m.hist.Messages(context.Background(), m.sess.id)
	if err != nil {
		t.Fatalf("messages: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("want 2 stored turns, got %d: %+v", len(msgs), msgs)
	}
	if msgs[0].Role != histstore.RoleUser || msgs[0].Content != "what is xss" {
		t.Errorf("turn 0 = {%q,%q}, want {human, 'what is xss'}", msgs[0].Role, msgs[0].Content)
	}
	if msgs[1].Role != histstore.RoleAI || msgs[1].Content != "an answer" {
		t.Errorf("turn 1 = {%q,%q}, want {ai, 'an answer'}", msgs[1].Role, msgs[1].Content)
	}
}

// Cycle 3c seam: /history opens the session picker sourced from the langchaingo
// store (not the JSONL index), titled HISTORY, reusing the resume picker UI.
func TestHistoryCommandOpensPickerFromStore(t *testing.T) {
	m := newKeyModel(t)
	if m.hist == nil {
		t.Fatal("initialModel should open a history store")
	}
	ctx := context.Background()
	if err := m.hist.AppendUser(ctx, "sA", "qA"); err != nil {
		t.Fatalf("seed sA: %v", err)
	}
	if err := m.hist.AppendUser(ctx, "sB", "qB"); err != nil {
		t.Fatalf("seed sB: %v", err)
	}

	nm, _ := m.dispatchInput("/history")
	p, ok := nm.(model).overlay.(historyPicker)
	if !ok {
		t.Fatalf("overlay = %T, want historyPicker", nm.(model).overlay)
	}
	if p.title != "HISTORY" {
		t.Errorf("picker title = %q, want HISTORY", p.title)
	}
	if len(p.metas) != 2 {
		t.Fatalf("want 2 sessions in picker, got %d: %+v", len(p.metas), p.metas)
	}
	// Newest-touched first: sB was written last.
	if p.metas[0].ID != "sB" || p.metas[1].ID != "sA" {
		t.Errorf("order = [%s,%s], want [sB,sA]", p.metas[0].ID, p.metas[1].ID)
	}
}

// Cycle 3d seam: the session picker emits historySelectedMsg on both enter and a
// 1-9 quick pick, so /history reopens the chosen session from memory.
func TestHistoryPickerEmitsHistorySelected(t *testing.T) {
	metas := []sessionMeta{{ID: "x", Title: "x", MsgCount: 1}}

	p := newHistoryPicker(metas, "", 80)
	_, cmd := p.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("picker enter produced no command")
	}
	if hs, ok := cmd().(historySelectedMsg); !ok {
		t.Errorf("enter msg = %T, want historySelectedMsg", cmd())
	} else if hs.id != "x" {
		t.Errorf("selected id = %q, want x", hs.id)
	}

	_, cmd = p.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	if hs, ok := cmd().(historySelectedMsg); !ok || hs.id != "x" {
		t.Errorf("quick-pick 1 msg = %v, want historySelectedMsg{x}", cmd())
	}
}

// Cycle 3e seam: openHistorySessionInto replays a session from the langchaingo
// store and reactivates it, even when it exists ONLY there (an engage run that
// never wrote a JSONL transcript).
func TestOpenHistorySessionIntoReactivatesLangchaingoOnlySession(t *testing.T) {
	m := newKeyModel(t)
	ctx := context.Background()
	if err := m.hist.AppendAI(ctx, "engage-1", "Engagement report [complete]"); err != nil {
		t.Fatalf("seed engage-1: %v", err)
	}

	nm, _ := m.openHistorySessionInto("engage-1")
	got := nm.(model)
	if got.sess == nil || got.sess.id != "engage-1" {
		t.Fatalf("sess = %+v, want reactivated engage-1", got.sess)
	}
}

// /history clear erases the whole store; /history clear [n] erases the nth
// session (newest-first, matching the picker's numbering).
func TestHistoryClearAllErasesStore(t *testing.T) {
	m := newKeyModel(t)
	ctx := context.Background()
	_ = m.hist.AppendUser(ctx, "s1", "a")
	_ = m.hist.AppendUser(ctx, "s2", "b")

	nm, _ := m.dispatchInput("/history clear")
	hs, _ := nm.(model).hist.Sessions(ctx)
	if len(hs) != 0 {
		t.Fatalf("clear all left %d sessions", len(hs))
	}
}

func TestHistoryClearIndexErasesNewest(t *testing.T) {
	m := newKeyModel(t)
	ctx := context.Background()
	_ = m.hist.AppendUser(ctx, "s1", "a") // older
	_ = m.hist.AppendUser(ctx, "s2", "b") // newer -> index 1

	nm, _ := m.dispatchInput("/history clear 1")
	hs, _ := nm.(model).hist.Sessions(ctx)
	if len(hs) != 1 || hs[0].ID != "s1" {
		t.Fatalf("clear 1 should leave only s1, got %+v", hs)
	}
}

func TestHistoryClearBadIndexDoesNotErase(t *testing.T) {
	m := newKeyModel(t)
	ctx := context.Background()
	_ = m.hist.AppendUser(ctx, "s1", "a")

	for _, bad := range []string{"/history clear 9", "/history clear abc", "/history clear 0"} {
		nm, _ := m.dispatchInput(bad)
		hs, _ := nm.(model).hist.Sessions(ctx)
		if len(hs) != 1 {
			t.Fatalf("%q should not erase; left %d", bad, len(hs))
		}
	}
}

// Coherence: deleting in the /history picker (d then y) erases from the
// langchaingo store, and reload re-queries the store (not the JSONL list).
func TestHistoryPickerDeleteErasesFromStoreAndReloads(t *testing.T) {
	m := newKeyModel(t)
	ctx := context.Background()
	_ = m.hist.AppendUser(ctx, "s1", "q1")
	_ = m.hist.AppendUser(ctx, "s2", "q2") // newest -> selected by default

	nm, _ := m.dispatchInput("/history")
	p, ok := nm.(model).overlay.(historyPicker)
	if !ok {
		t.Fatalf("overlay = %T, want historyPicker", nm.(model).overlay)
	}

	ov, _ := p.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	p = ov.(historyPicker)
	if !p.confirm {
		t.Fatal("d should arm the delete confirm")
	}
	ov, _ = p.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	p = ov.(historyPicker)

	hs, _ := m.hist.Sessions(ctx)
	if len(hs) != 1 || hs[0].ID != "s1" {
		t.Fatalf("after delete, store should hold only s1, got %+v", hs)
	}
	if len(p.metas) != 1 || p.metas[0].ID != "s1" {
		t.Fatalf("after reload, picker should show only s1, got %+v", p.metas)
	}
}
