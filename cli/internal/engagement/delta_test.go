package engagement

import (
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

	if rev, _ := s.Revision(); rev != 1 {
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
	if rev, _ := s.Revision(); rev != 1 {
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
	if rev, _ := s.Revision(); rev != 1 {
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
	if got, _ := s.Revision(); got != n {
		t.Fatalf("Revision = %d, want %d", got, n)
	}
}
