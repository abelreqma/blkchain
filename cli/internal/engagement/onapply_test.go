package engagement

import "testing"

func TestSetOnApplyFiresWithRevisionAndSnapshot(t *testing.T) {
	s := mustOpen(t)
	var gotRev int64
	var gotTasks int
	calls := 0
	s.SetOnApply(func(rev int64, e Engagement) {
		calls++
		gotRev = rev
		gotTasks = len(e.Tasks)
	})
	rev, err := s.Apply(Delta{Upserts: []Task{{ID: "t1", Status: StatusTodo}}, Kind: "init"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("onApply called %d times, want 1", calls)
	}
	if gotRev != rev {
		t.Errorf("onApply rev = %d, want %d", gotRev, rev)
	}
	if gotTasks != 1 {
		t.Errorf("onApply snapshot had %d tasks, want 1", gotTasks)
	}
}

func TestSetOnApplyNilClears(t *testing.T) {
	s := mustOpen(t)
	calls := 0
	s.SetOnApply(func(rev int64, e Engagement) { calls++ })
	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "a", Status: StatusTodo}}, Kind: "init"}); err != nil {
		t.Fatal(err)
	}
	s.SetOnApply(nil)
	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "b", Status: StatusTodo}}, Kind: "add"}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("onApply called %d times, want 1 (cleared before second Apply)", calls)
	}
}
