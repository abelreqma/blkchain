package histstore

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Slice 1 seam: the histStore public methods, backed by langchaingo's
// memory/sqlite3 store at a temp db path. We observe behavior only through
// appendUser/appendAI, messages, and sessions, never the raw table.

func newTestHistStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "history.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestHistStoreAppendAndReadBackInOrder(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()

	if err := s.AppendUser(ctx, "s1", "what is reflected xss"); err != nil {
		t.Fatalf("appendUser: %v", err)
	}
	if err := s.AppendAI(ctx, "s1", "an answer"); err != nil {
		t.Fatalf("appendAI: %v", err)
	}
	if err := s.AppendUser(ctx, "s1", "second question"); err != nil {
		t.Fatalf("appendUser: %v", err)
	}

	msgs, err := s.Messages(ctx, "s1")
	if err != nil {
		t.Fatalf("messages: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("want 3 messages, got %d: %+v", len(msgs), msgs)
	}
	want := []Turn{
		{Role: RoleUser, Content: "what is reflected xss"},
		{Role: RoleAI, Content: "an answer"},
		{Role: RoleUser, Content: "second question"},
	}
	for i, w := range want {
		if msgs[i].Role != w.Role || msgs[i].Content != w.Content {
			t.Errorf("msg[%d] = {%q,%q}, want {%q,%q}", i, msgs[i].Role, msgs[i].Content, w.Role, w.Content)
		}
	}
}

func TestHistStoreSessionsNewestFirstWithCounts(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()

	// s1 gets two messages, then s2 gets one. s2 is touched last.
	if err := s.AppendUser(ctx, "s1", "q1"); err != nil {
		t.Fatalf("appendUser s1: %v", err)
	}
	if err := s.AppendAI(ctx, "s1", "a1"); err != nil {
		t.Fatalf("appendAI s1: %v", err)
	}
	if err := s.AppendUser(ctx, "s2", "q2"); err != nil {
		t.Fatalf("appendUser s2: %v", err)
	}

	sess, err := s.Sessions(ctx)
	if err != nil {
		t.Fatalf("sessions: %v", err)
	}
	if len(sess) != 2 {
		t.Fatalf("want 2 sessions, got %d: %+v", len(sess), sess)
	}
	if sess[0].ID != "s2" {
		t.Errorf("newest session = %q, want s2", sess[0].ID)
	}
	if sess[1].ID != "s1" {
		t.Errorf("oldest session = %q, want s1", sess[1].ID)
	}
	if sess[1].Count != 2 {
		t.Errorf("s1 count = %d, want 2", sess[1].Count)
	}
	if sess[0].Count != 1 {
		t.Errorf("s2 count = %d, want 1", sess[0].Count)
	}
}

func TestHistStoreMessagesUnknownSessionEmpty(t *testing.T) {
	s := newTestHistStore(t)
	msgs, err := s.Messages(context.Background(), "does-not-exist")
	if err != nil {
		t.Fatalf("messages: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("want no messages, got %d", len(msgs))
	}
}

// Shared-access: Open enables WAL so multiple writers (the REPL and the
// engage harness sharing the db file) do not deadlock, and DB()/DBPath()
// expose the handle and path for that sharing.
func TestOpenHistStoreEnablesWALAndExposesDB(t *testing.T) {
	s := newTestHistStore(t)
	if s.DB() == nil {
		t.Fatal("DB() returned nil")
	}
	var mode string
	if err := s.DB().QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if strings.ToLower(mode) != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
	var busy int
	if err := s.DB().QueryRow("PRAGMA busy_timeout").Scan(&busy); err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if busy < 5000 {
		t.Errorf("busy_timeout = %d, want >= 5000", busy)
	}
}

func TestHistDBPathHonorsXDGDataHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir)
	p, err := DBPath()
	if err != nil {
		t.Fatalf("DBPath: %v", err)
	}
	want := filepath.Join(dir, "blk", "history.db")
	if p != want {
		t.Errorf("DBPath = %q, want %q", p, want)
	}
}

// Rename migration: an existing blk_history table (old name) is renamed to
// blk_sessions on open, preserving its rows.
func TestOpenHistStoreMigratesBlkHistoryToBlkSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE blk_history (
		id INTEGER PRIMARY KEY, name TEXT, session TEXT NOT NULL,
		content TEXT NOT NULL, type TEXT NOT NULL,
		created TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`); err != nil {
		t.Fatalf("create old table: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO blk_history (session, content, type) VALUES ('s1','old question','human');`); err != nil {
		t.Fatalf("seed old row: %v", err)
	}
	raw.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	msgs, err := s.Messages(context.Background(), "s1")
	if err != nil {
		t.Fatalf("messages: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Content != "old question" {
		t.Fatalf("migration lost data: %+v", msgs)
	}
	var n int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='blk_history'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("blk_history should have been renamed to blk_sessions")
	}
}

func TestHistStoreEraseSessionAndEraseAll(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()
	_ = s.AppendUser(ctx, "s1", "a")
	_ = s.AppendUser(ctx, "s2", "b")

	if err := s.EraseSession(ctx, "s1"); err != nil {
		t.Fatalf("eraseSession: %v", err)
	}
	sess, _ := s.Sessions(ctx)
	if len(sess) != 1 || sess[0].ID != "s2" {
		t.Fatalf("after eraseSession want only s2, got %+v", sess)
	}

	if err := s.EraseAll(ctx); err != nil {
		t.Fatalf("eraseAll: %v", err)
	}
	sess, _ = s.Sessions(ctx)
	if len(sess) != 0 {
		t.Fatalf("after eraseAll want 0 sessions, got %d", len(sess))
	}
}

// Several blk processes can open the same database at once, and the first one
// through takes an exclusive lock to set the journal mode, which does not go
// through the busy handler the DSN configures. Open waits that out rather than
// handing the loser no store, because a process with no store writes no memory
// and no session listing while still appending transcripts.
func TestOpenWaitsOutAnExclusiveLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")

	// A database that exists but is still in rollback-journal mode, with a write
	// transaction open on it. That is the state the loser of the startup race
	// sees: switching this to WAL needs a lock the holder has, and the switch
	// does not wait for it.
	holder, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if _, err := holder.Exec("CREATE TABLE lock_probe (id INTEGER);"); err != nil {
		t.Fatal(err)
	}
	tx, err := holder.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO lock_probe (id) VALUES (1);"); err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = tx.Rollback()
		close(released)
	}()

	s, err := Open(path)
	<-released
	if err != nil {
		t.Fatalf("open gave up while the database was briefly locked: %v", err)
	}
	defer s.Close()
	// The store is usable, not just opened.
	if err := s.UpsertSessionRow(context.Background(), SessionRow{ID: "after-the-lock"}); err != nil {
		t.Fatalf("store opened but cannot write: %v", err)
	}
}

// A locked database is retried; anything else is reported as it is, so a real
// schema problem is not retried forty times before surfacing.
func TestLockedErrOnlyMatchesContention(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("database is locked"), true},
		{errors.New("Database Is Locked"), true},
		{errors.New("database table is locked"), true},
		{errors.New("no such column: watermark"), false},
		{errors.New("disk I/O error"), false},
	} {
		if got := lockedErr(tc.err); got != tc.want {
			t.Errorf("lockedErr(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
