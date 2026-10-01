package engagement

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestCitationRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cit := Citation{Source: "offensive-rce", Path: "rce/eval.md", Section: "Exploitation", CWEClass: "rce", Origin: "trusted"}
	if _, err := s.Apply(Delta{Upserts: []Task{{
		ID: "e1", Kind: "exploit", Status: StatusTodo, Phase: PhaseExploit, Surface: SurfaceNetwork, Citation: cit,
	}}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetTask("e1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Citation != cit {
		t.Fatalf("GetTask citation = %+v, want %+v", got.Citation, cit)
	}
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tk := range snap.Tasks {
		if tk.ID == "e1" {
			found = true
			if tk.Citation != cit {
				t.Fatalf("Snapshot citation = %+v, want %+v", tk.Citation, cit)
			}
		}
	}
	if !found {
		t.Fatal("task e1 missing from snapshot")
	}
}

func TestCitationEmptyByDefault(t *testing.T) {
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
	if got.Citation != (Citation{}) {
		t.Fatalf("default citation = %+v, want empty", got.Citation)
	}
}

// TestMigrateAddsCitationColumn: an engagement DB whose task table predates the
// citation column gets it added additively on Open (migrate), with no clean
// rebuild, and a task with a citation round-trips.
func TestMigrateAddsCitationColumn(t *testing.T) {
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
	cit := Citation{Source: "kb", Origin: "trusted"}
	if _, err := s.Apply(Delta{Upserts: []Task{{
		ID: "e1", Kind: "exploit", Status: StatusTodo, Phase: PhaseExploit, Surface: SurfaceNetwork, Citation: cit,
	}}}); err != nil {
		t.Fatalf("apply after migrate: %v", err)
	}
	got, err := s.GetTask("e1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Citation != cit {
		t.Fatalf("citation after migrate = %+v, want %+v", got.Citation, cit)
	}
}
