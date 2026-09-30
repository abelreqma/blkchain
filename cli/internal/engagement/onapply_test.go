package engagement

import (
	"sync"
	"testing"
)

func TestAddOnApplyFiresAllListeners(t *testing.T) {
	s := mustOpen(t)
	var mu sync.Mutex
	a, b := 0, 0
	remA := s.AddOnApply(func(rev int64, e Engagement) { mu.Lock(); a++; mu.Unlock() })
	_ = s.AddOnApply(func(rev int64, e Engagement) { mu.Lock(); b++; mu.Unlock() })
	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "t1", Status: StatusTodo}}, Kind: "init"}); err != nil {
		t.Fatal(err)
	}
	if a != 1 || b != 1 {
		t.Fatalf("listeners fired a=%d b=%d, want 1,1", a, b)
	}
	remA() // remove the first listener
	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "t2", Status: StatusTodo}}, Kind: "add"}); err != nil {
		t.Fatal(err)
	}
	if a != 1 {
		t.Errorf("removed listener still fired: a=%d, want 1", a)
	}
	if b != 2 {
		t.Errorf("remaining listener count b=%d, want 2", b)
	}
}

func TestAddOnApplySnapshotMatchesRev(t *testing.T) {
	s := mustOpen(t)
	var gotRev, gotSnapRev int64
	s.AddOnApply(func(rev int64, e Engagement) { gotRev = rev; gotSnapRev = e.Revision })
	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "t1", Status: StatusTodo}}, Kind: "init"}); err != nil {
		t.Fatal(err)
	}
	if gotRev != gotSnapRev {
		t.Errorf("listener rev %d != snapshot rev %d", gotRev, gotSnapRev)
	}
}
