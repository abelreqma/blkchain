package engagement

import (
	"strings"
	"testing"
	"time"
)

func seedMixed(t *testing.T, s *Store) {
	t.Helper()
	seed := []Task{
		{ID: "T1", Kind: "recon", Target: "t", Objective: "o", DoneWhen: "d", Status: StatusTodo},
		{ID: "T2", Kind: "scan", Target: "t", Objective: "o", DoneWhen: "d", Status: StatusActive},
		{ID: "T3", Kind: "recon", Target: "t", Objective: "o", DoneWhen: "d", Status: StatusTodo, DependsOn: []string{"T1"}},
		{ID: "T4", Kind: "scan", Target: "t", Objective: "o", DoneWhen: "d", Status: StatusDone},
		{ID: "T5", Kind: "recon", Target: "t", Objective: "o", DoneWhen: "d", Status: StatusNA},
	}
	for _, task := range seed {
		if _, err := s.Apply(Delta{Upserts: []Task{task}, Kind: "plan", Detail: "seed"}); err != nil {
			t.Fatalf("seed %s: %v", task.ID, err)
		}
	}
}

func TestOpenTasksOnlyTodoAndActiveInCreatedOrder(t *testing.T) {
	s := openTemp(t)
	seedMixed(t, s)

	got, err := s.OpenTasks()
	if err != nil {
		t.Fatalf("OpenTasks: %v", err)
	}
	ids := []string{}
	for _, task := range got {
		ids = append(ids, task.ID)
	}
	if strings.Join(ids, ",") != "T1,T2,T3" {
		t.Fatalf("OpenTasks ids = %v, want T1,T2,T3", ids)
	}
	if got[2].Status != StatusTodo || len(got[2].DependsOn) != 1 || got[2].DependsOn[0] != "T1" {
		t.Fatalf("T3 not fully scanned: %+v", got[2])
	}
	if got[0].CreatedRev != 1 || got[1].CreatedRev != 2 {
		t.Fatalf("created revs = %d, %d", got[0].CreatedRev, got[1].CreatedRev)
	}
}

func TestOpenTasksEmpty(t *testing.T) {
	s := openTemp(t)
	got, err := s.OpenTasks()
	if err != nil {
		t.Fatalf("OpenTasks: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("OpenTasks = %v, want empty", got)
	}
}

func TestCoverageIndex(t *testing.T) {
	s := openTemp(t)
	seedMixed(t, s)

	c, err := s.CoverageIndex()
	if err != nil {
		t.Fatalf("CoverageIndex: %v", err)
	}
	if c.Total != 5 || c.Done != 1 || c.Open != 3 {
		t.Fatalf("coverage = %+v, want Total 5 Done 1 Open 3", c)
	}
	if len(c.Kinds) != 2 || c.Kinds["recon"] != 3 || c.Kinds["scan"] != 2 {
		t.Fatalf("Kinds = %v, want recon 3 scan 2", c.Kinds)
	}
}

func TestCoverageIndexEmpty(t *testing.T) {
	s := openTemp(t)
	c, err := s.CoverageIndex()
	if err != nil {
		t.Fatalf("CoverageIndex: %v", err)
	}
	if c.Total != 0 || c.Done != 0 || c.Open != 0 || c.Kinds == nil || len(c.Kinds) != 0 {
		t.Fatalf("coverage = %+v, want zero with empty non-nil Kinds", c)
	}
}

func TestAuditAppendsMonotonic(t *testing.T) {
	s := openTemp(t)

	if err := s.Audit("operator", "scope", "added example.test"); err != nil {
		t.Fatalf("Audit 1: %v", err)
	}
	if err := s.Audit("agent", "tool", "ran probe \u00e9"); err != nil {
		t.Fatalf("Audit 2: %v", err)
	}

	rows, err := s.db.Query(`SELECT id, at, actor, action, detail FROM audit ORDER BY id`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var ids []int64
	var actors []string
	for rows.Next() {
		var (
			id                        int64
			at, actor, action, detail string
		)
		if err := rows.Scan(&id, &at, &actor, &action, &detail); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if _, err := time.Parse(time.RFC3339, at); err != nil || !strings.HasSuffix(at, "Z") {
			t.Fatalf("at = %q, want RFC3339 UTC", at)
		}
		ids = append(ids, id)
		actors = append(actors, actor)
	}
	if len(ids) != 2 || ids[1] <= ids[0] {
		t.Fatalf("ids = %v, want two increasing ids", ids)
	}
	if actors[0] != "operator" || actors[1] != "agent" {
		t.Fatalf("actors = %v", actors)
	}
}
