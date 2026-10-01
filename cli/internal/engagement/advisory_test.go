package engagement

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestAdvisoryRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	adv := "[prior episode 2026-09-28] OpenSSH 8.2 on this host yielded CVE-2023-38408 via ssh-agent; evidence quote e42"
	if _, err := s.Apply(Delta{Upserts: []Task{{
		ID: "e1", Kind: "exploit", Status: StatusTodo, Phase: PhaseExploit, Surface: SurfaceNetwork, Advisory: adv,
	}}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetTask("e1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Advisory != adv {
		t.Fatalf("GetTask advisory = %q, want %q", got.Advisory, adv)
	}
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tk := range snap.Tasks {
		if tk.ID == "e1" {
			found = true
			if tk.Advisory != adv {
				t.Fatalf("Snapshot advisory = %q, want %q", tk.Advisory, adv)
			}
		}
	}
	if !found {
		t.Fatal("task e1 missing from snapshot")
	}
}

func TestAdvisoryEmptyByDefault(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Apply(Delta{Upserts: []Task{{
		ID: "r1", Kind: "recon", Status: StatusTodo, Phase: PhaseRecon, Surface: SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetTask("r1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Advisory != "" {
		t.Fatalf("default advisory = %q, want empty", got.Advisory)
	}
}

// TestMigrateAddsAdvisoryColumn: an engagement DB whose task table predates the
// advisory column gets it added additively on Open (migrate), with no clean
// rebuild, and a task with an advisory round-trips.
func TestMigrateAddsAdvisoryColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE task (
		id TEXT PRIMARY KEY, kind TEXT, target TEXT, objective TEXT, done_when TEXT, status TEXT,
		depends_on TEXT, basis_ids TEXT, created_rev INTEGER, updated_rev INTEGER,
		phase TEXT, surface TEXT, capability TEXT, armed INTEGER)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("migrate old db: %v", err)
	}
	defer s.Close()
	adv := "[prior episode] recon hint"
	if _, err := s.Apply(Delta{Upserts: []Task{{
		ID: "e1", Kind: "exploit", Status: StatusTodo, Phase: PhaseExploit, Surface: SurfaceNetwork, Advisory: adv,
	}}}); err != nil {
		t.Fatalf("apply after migrate: %v", err)
	}
	got, err := s.GetTask("e1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Advisory != adv {
		t.Fatalf("advisory after migrate = %q, want %q", got.Advisory, adv)
	}
}
