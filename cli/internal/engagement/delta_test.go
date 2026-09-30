package engagement

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

func countRows(t *testing.T, s *Store, query string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

func seedAB(t *testing.T, s *Store) {
	t.Helper()
	rev, err := s.Apply(Delta{
		Upserts: []Task{
			{ID: "A", Kind: "recon", Target: "t", Objective: "o", DoneWhen: "d", Status: StatusTodo},
			{ID: "B", Kind: "scan", Target: "t", Objective: "o", DoneWhen: "d", Status: StatusTodo, DependsOn: []string{"A"}},
		},
		Kind:   "plan",
		Detail: "seed",
	})
	if err != nil {
		t.Fatalf("seed Apply: %v", err)
	}
	if rev != 1 {
		t.Fatalf("seed rev = %d, want 1", rev)
	}
}

func TestApplyAddsTasksBumpsRevision(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)

	if rev, _ := s.Revision(context.Background()); rev != 1 {
		t.Fatalf("Revision = %d, want 1", rev)
	}
	a, err := s.GetTask("A")
	if err != nil {
		t.Fatalf("GetTask A: %v", err)
	}
	b, err := s.GetTask("B")
	if err != nil {
		t.Fatalf("GetTask B: %v", err)
	}
	if a.CreatedRev != 1 || a.UpdatedRev != 1 || b.CreatedRev != 1 || b.UpdatedRev != 1 {
		t.Fatalf("revs: A=%+v B=%+v", a, b)
	}
	if len(b.DependsOn) != 1 || b.DependsOn[0] != "A" {
		t.Fatalf("B.DependsOn = %v", b.DependsOn)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM transition WHERE rev = 1 AND kind = 'plan' AND detail = 'seed'`); n != 1 {
		t.Fatalf("transition rows for rev 1 = %d, want 1", n)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM transition`); n != 1 {
		t.Fatalf("total transitions = %d, want 1", n)
	}
}

func TestApplyDanglingDependsOnRollsBack(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)

	_, err := s.Apply(Delta{
		Upserts: []Task{{ID: "C", Status: StatusTodo, DependsOn: []string{"ghost"}}},
		Kind:    "plan",
	})
	if err == nil {
		t.Fatal("expected error for dangling depends_on")
	}
	if rev, _ := s.Revision(context.Background()); rev != 1 {
		t.Fatalf("Revision = %d, want 1", rev)
	}
	if _, err := s.GetTask("C"); err != ErrNotFound {
		t.Fatalf("GetTask C err = %v, want ErrNotFound", err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM transition`); n != 1 {
		t.Fatalf("transitions = %d, want 1", n)
	}
}

func TestApplyRejectsInvalidStatusAndUnknownComplete(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)

	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "C", Status: "bogus"}}}); err == nil {
		t.Fatal("expected error for invalid status")
	}
	if _, err := s.Apply(Delta{Completes: []string{"ghost"}}); err == nil {
		t.Fatal("expected error for unknown complete id")
	}
	if rev, _ := s.Revision(context.Background()); rev != 1 {
		t.Fatalf("Revision = %d, want 1", rev)
	}
}

func TestApplyCompleteMarksDone(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)

	rev, err := s.Apply(Delta{Completes: []string{"A"}, Kind: "complete", Detail: "A done"})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if rev != 2 {
		t.Fatalf("rev = %d, want 2", rev)
	}
	a, err := s.GetTask("A")
	if err != nil {
		t.Fatalf("GetTask: %v", err)
	}
	if a.Status != StatusDone || a.UpdatedRev != 2 || a.CreatedRev != 1 {
		t.Fatalf("A = %+v", a)
	}
}

func TestApplyUpsertKeepsCreatedRev(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)

	if _, err := s.Apply(Delta{
		Upserts: []Task{{ID: "A", Kind: "recon", Objective: "new", Status: StatusActive}},
		Kind:    "update",
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	a, err := s.GetTask("A")
	if err != nil {
		t.Fatalf("GetTask: %v", err)
	}
	if a.CreatedRev != 1 || a.UpdatedRev != 2 || a.Objective != "new" || a.Status != StatusActive {
		t.Fatalf("A = %+v", a)
	}
}

func TestApplyDependsOnEarlierUpsertInSameBatch(t *testing.T) {
	s := openTemp(t)
	// B listed before A in the batch; both are new.
	if _, err := s.Apply(Delta{
		Upserts: []Task{
			{ID: "B", Status: StatusTodo, DependsOn: []string{"A"}},
			{ID: "A", Status: StatusTodo},
		},
		Kind: "plan",
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

func TestApplyConcurrentNoBusy(t *testing.T) {
	s := openTemp(t)
	const n = 20
	var wg sync.WaitGroup
	revs := make([]int64, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			revs[i], errs[i] = s.Apply(Delta{
				Upserts: []Task{{ID: fmt.Sprintf("T%d", i), Status: StatusTodo}},
				Kind:    "plan",
			})
		}(i)
	}
	wg.Wait()
	seen := map[int64]bool{}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("Apply %d: %v", i, errs[i])
		}
		seen[revs[i]] = true
	}
	for r := int64(1); r <= n; r++ {
		if !seen[r] {
			t.Fatalf("missing revision %d in %v", r, revs)
		}
	}
	if got, _ := s.Revision(context.Background()); got != n {
		t.Fatalf("Revision = %d, want %d", got, n)
	}
}

func TestApplyStageOnlyBumpsRevisionAndSnapshot(t *testing.T) {
	s, err := Open(t.TempDir() + "/e.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	name := "acme-web"
	active := "t1"
	stage := Stage{Label: "dispatch", Step: 1, Total: 3, Tool: "web"}
	rev, err := s.Apply(Delta{Kind: "stage", Detail: "start", SetName: &name, SetActiveID: &active, SetStage: &stage})
	if err != nil {
		t.Fatal(err)
	}
	if rev != 1 {
		t.Fatalf("rev = %d, want 1", rev)
	}

	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Revision != 1 {
		t.Errorf("snap.Revision = %d, want 1", snap.Revision)
	}
	if snap.Name != name || snap.ActiveID != active {
		t.Errorf("snap Name/ActiveID = %q/%q, want %q/%q", snap.Name, snap.ActiveID, name, active)
	}
	if snap.Stage != stage {
		t.Errorf("snap.Stage = %+v, want %+v", snap.Stage, stage)
	}

	// One transition row for this revision.
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM transition WHERE rev = 1`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("transition rows at rev 1 = %d, want 1", n)
	}
}

func TestApplyNilMetaLeavesPriorValues(t *testing.T) {
	s, err := Open(t.TempDir() + "/e.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	name := "acme-web"
	if _, err := s.Apply(Delta{Kind: "init", SetName: &name}); err != nil {
		t.Fatal(err)
	}
	// A later delta that does not set the name must not clear it.
	if _, err := s.Apply(Delta{Kind: "noop"}); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Name != name {
		t.Errorf("snap.Name = %q, want %q", snap.Name, name)
	}
	if snap.Revision != 2 {
		t.Errorf("snap.Revision = %d, want 2", snap.Revision)
	}
}

func mustOpen(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir() + "/e.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestApplyRejectsEmptyTaskID(t *testing.T) {
	s := mustOpen(t)
	_, err := s.Apply(Delta{Upserts: []Task{{ID: "", Kind: "recon", Status: StatusTodo}}})
	if err == nil {
		t.Fatal("want error for empty task id")
	}
	if rev, _ := s.Revision(context.Background()); rev != 0 {
		t.Errorf("revision moved to %d on rejected delta", rev)
	}
}

func TestApplyRejectsSelfDependency(t *testing.T) {
	s := mustOpen(t)
	_, err := s.Apply(Delta{Upserts: []Task{{ID: "t1", Status: StatusTodo, DependsOn: []string{"t1"}}}})
	if err == nil {
		t.Fatal("want error for self-dependency")
	}
}

func TestApplyRejectsCycleAcrossStoredAndUpsert(t *testing.T) {
	s := mustOpen(t)
	// t1 depends on t2; both new.
	if _, err := s.Apply(Delta{Upserts: []Task{
		{ID: "t2", Status: StatusTodo},
		{ID: "t1", Status: StatusTodo, DependsOn: []string{"t2"}},
	}}); err != nil {
		t.Fatal(err)
	}
	// Now upsert t2 to depend on t1 -> closes a cycle t1->t2->t1.
	_, err := s.Apply(Delta{Upserts: []Task{{ID: "t2", Status: StatusTodo, DependsOn: []string{"t1"}}}})
	if err == nil {
		t.Fatal("want error for dependency cycle")
	}
	if rev, _ := s.Revision(context.Background()); rev != 1 {
		t.Errorf("revision = %d after rejected cycle, want 1", rev)
	}
}

func TestApplyRejectsDoneToTodo(t *testing.T) {
	s := mustOpen(t)
	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "t1", Status: StatusDone}}}); err != nil {
		t.Fatal(err)
	}
	_, err := s.Apply(Delta{Upserts: []Task{{ID: "t1", Status: StatusTodo}}})
	if err == nil {
		t.Fatal("want error for done->todo downgrade")
	}
}

func TestApplyAllowsDoneToActive(t *testing.T) {
	s := mustOpen(t)
	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "t1", Status: StatusDone}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "t1", Status: StatusActive}}}); err != nil {
		t.Fatalf("done->active should be allowed: %v", err)
	}
}
