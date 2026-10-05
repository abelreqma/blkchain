package engagement

import (
	"os"
	"path/filepath"
	"testing"
)

func revision(t *testing.T, s *Store) string {
	t.Helper()
	var v string
	if err := s.db.QueryRow(`SELECT v FROM meta WHERE k = 'revision'`).Scan(&v); err != nil {
		t.Fatalf("read revision: %v", err)
	}
	return v
}

func TestOpenTwiceSamePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "e.db")
	a, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	defer a.Close()
	b, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer b.Close()
}

func TestOpenFreshRevisionZero(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if got := revision(t, s); got != "0" {
		t.Fatalf("revision = %q, want 0", got)
	}
}

func TestReopenKeepsRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE meta SET v = '7' WHERE k = 'revision'`); err != nil {
		t.Fatalf("bump revision: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer s2.Close()
	if got := revision(t, s2); got != "7" {
		t.Fatalf("revision after reopen = %q, want 7", got)
	}
}

func TestOpenCreatesAllTables(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	for _, name := range []string{"task", "meta", "transition", "evidence", "receipt", "audit"} {
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n); err != nil || n != 1 {
			t.Fatalf("table %s missing (n=%d err=%v)", name, n, err)
		}
	}
}

func TestOpenCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.db")
	garbage := make([]byte, 4096)
	for i := range garbage {
		garbage[i] = byte(0xA5 ^ i)
	}
	if err := os.WriteFile(path, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err == nil {
		s.Close()
		t.Fatal("Open on a corrupt file returned nil error")
	}
}

func TestCodeCandidatePersistsAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engagement.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(Delta{Kind: "correlate", Upserts: []Task{{ID: "c1", Kind: "exploit", Status: StatusTodo, CodeCandidate: true}}}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	task, err := s.GetTask("c1")
	if err != nil || !task.CodeCandidate {
		t.Fatalf("reopened candidate=%+v err=%v", task, err)
	}
}
