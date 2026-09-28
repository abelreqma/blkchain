package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tempSessions points the session store at a temp dir for the duration of a
// test, so nothing touches the real ~/.local/share.
func tempSessions(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir)
	return filepath.Join(dir, "blk", "sessions")
}

func TestNewSessionLazyFileAndAppend(t *testing.T) {
	tempSessions(t)

	s, err := newSession()
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	if s.id == "" {
		t.Fatal("newSession returned empty id")
	}
	// File is created lazily: nothing on disk before the first append.
	if _, err := os.Stat(s.filePath()); !os.IsNotExist(err) {
		t.Fatalf("transcript should not exist before first append, stat err = %v", err)
	}

	if err := s.appendTurn(turnRecord{Role: roleUser, Content: "how do I tune HNSW recall for my index quickly?"}); err != nil {
		t.Fatalf("appendTurn user: %v", err)
	}
	if err := s.appendTurn(turnRecord{Role: roleAssistant, Content: "Raise ef_search."}); err != nil {
		t.Fatalf("appendTurn assistant: %v", err)
	}

	if fi, err := os.Stat(s.filePath()); err != nil {
		t.Fatalf("transcript should exist after append: %v", err)
	} else if fi.Mode().Perm() != 0o644 {
		t.Errorf("transcript perm = %v, want 0644", fi.Mode().Perm())
	}

	// Title is the first user message, capped at titleMaxLen runes.
	if want := slugTitle("how do I tune HNSW recall for my index quickly?"); s.title != want {
		t.Errorf("auto title = %q, want %q", s.title, want)
	}
	if len([]rune(s.title)) > titleMaxLen {
		t.Errorf("title exceeds cap: %q", s.title)
	}
	if s.count != 2 {
		t.Errorf("count = %d, want 2", s.count)
	}
}

func TestListLoadRenameDelete(t *testing.T) {
	tempSessions(t)

	s, err := newSession()
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	_ = s.appendTurn(turnRecord{Role: roleUser, Content: "first question"})
	_ = s.appendTurn(turnRecord{Role: roleAssistant, Content: "an answer"})

	metas, err := listSessions()
	if err != nil {
		t.Fatalf("listSessions: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("listSessions len = %d, want 1", len(metas))
	}
	if metas[0].Title != "first question" || metas[0].MsgCount != 2 {
		t.Errorf("meta = %+v", metas[0])
	}

	recs, err := loadMessages(s.id)
	if err != nil {
		t.Fatalf("loadMessages: %v", err)
	}
	if len(recs) != 2 || recs[0].Role != roleUser || recs[1].Role != roleAssistant {
		t.Fatalf("loadMessages = %+v", recs)
	}

	if err := renameSession(s.id, "custom name"); err != nil {
		t.Fatalf("renameSession: %v", err)
	}
	metas, _ = listSessions()
	if metas[0].Title != "custom name" {
		t.Errorf("after rename title = %q", metas[0].Title)
	}

	if err := deleteSession(s.id); err != nil {
		t.Fatalf("deleteSession: %v", err)
	}
	if metas, _ := listSessions(); len(metas) != 0 {
		t.Errorf("after delete listSessions len = %d, want 0", len(metas))
	}
	if _, err := os.Stat(s.filePath()); !os.IsNotExist(err) {
		t.Errorf("transcript should be gone after delete, stat err = %v", err)
	}
}

func TestListSessionsNewestFirst(t *testing.T) {
	dir := tempSessions(t)
	if err := writeIndex(dir, []sessionMeta{
		{ID: "old", Title: "old", UpdatedAt: 100},
		{ID: "new", Title: "new", UpdatedAt: 300},
		{ID: "mid", Title: "mid", UpdatedAt: 200},
	}); err != nil {
		t.Fatalf("writeIndex: %v", err)
	}
	metas, err := listSessions()
	if err != nil {
		t.Fatalf("listSessions: %v", err)
	}
	got := []string{metas[0].ID, metas[1].ID, metas[2].ID}
	want := []string{"new", "mid", "old"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestLoadMessagesAppliesTombstone(t *testing.T) {
	tempSessions(t)
	s, _ := newSession()
	_ = s.appendTurn(turnRecord{Role: roleUser, Content: "q1"})
	_ = s.appendTurn(turnRecord{Role: roleAssistant, Content: "a1"})
	_ = s.appendTurn(turnRecord{Role: roleUser, Content: "q2"})
	_ = s.appendTurn(turnRecord{Role: roleAssistant, Content: "a2"})
	_ = s.appendTurn(turnRecord{Role: roleTombstone})

	recs, err := loadMessages(s.id)
	if err != nil {
		t.Fatalf("loadMessages: %v", err)
	}
	if len(recs) != 2 || recs[0].Content != "q1" || recs[1].Content != "a1" {
		t.Fatalf("after tombstone recs = %+v, want q1/a1", recs)
	}
	if s.count != 2 {
		t.Errorf("count after tombstone = %d, want 2", s.count)
	}
}

func TestAppendTurnSizeCap(t *testing.T) {
	tempSessions(t)
	s, _ := newSession()
	// Write a record and then force the file over the cap by padding on disk.
	_ = s.appendTurn(turnRecord{Role: roleUser, Content: "seed"})
	big := make([]byte, maxSessionBytes)
	if err := os.WriteFile(s.filePath(), big, 0o644); err != nil {
		t.Fatalf("pad file: %v", err)
	}
	if err := s.appendTurn(turnRecord{Role: roleAssistant, Content: "over cap"}); err != errSessionFull {
		t.Fatalf("appendTurn past cap err = %v, want errSessionFull", err)
	}
}

func TestSlugTitle(t *testing.T) {
	cases := []struct{ in, want string }{
		{"  hello   world  ", "hello world"},
		{"line one\nline two", "line one line two"},
		{strings.Repeat("a", 50), strings.Repeat("a", titleMaxLen)},
	}
	for _, tc := range cases {
		if got := slugTitle(tc.in); got != tc.want {
			t.Errorf("slugTitle(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestApplyTombstonesUnbalanced(t *testing.T) {
	// A tombstone with only a user record (no assistant) drops just the operator.
	recs := []turnRecord{{Role: roleUser, Content: "q"}, {Role: roleTombstone}}
	if got := applyTombstones(recs); len(got) != 0 {
		t.Errorf("applyTombstones dropped %d, want 0 remaining", len(got))
	}
	// A leading tombstone with nothing before it is a no-op.
	if got := applyTombstones([]turnRecord{{Role: roleTombstone}}); len(got) != 0 {
		t.Errorf("leading tombstone left %d records", len(got))
	}
}

func TestEnsureFirst(t *testing.T) {
	got := ensureFirst([]string{"b", "a", "b"}, "a")
	want := []string{"a", "b"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("ensureFirst = %v, want %v", got, want)
	}
	// "unknown"/empty current is dropped, models deduped.
	got = ensureFirst([]string{"x", "x", "y"}, "unknown")
	if strings.Join(got, ",") != "x,y" {
		t.Errorf("ensureFirst(unknown) = %v, want [x y]", got)
	}
}
