package engagement

import "testing"

func TestTransitionsOrderedByRev(t *testing.T) {
	s := mustOpen(t)
	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "a", Status: StatusTodo}}, Kind: "init"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "b", Status: StatusTodo}}, Kind: "add"}); err != nil {
		t.Fatal(err)
	}
	tr, err := s.Transitions()
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 2 {
		t.Fatalf("transitions = %d, want 2", len(tr))
	}
	if tr[0].Rev >= tr[1].Rev {
		t.Errorf("not ordered by rev: %+v", tr)
	}
	if tr[0].Kind != "init" {
		t.Errorf("first kind = %q, want init", tr[0].Kind)
	}
}

func TestAllEvidenceByTask(t *testing.T) {
	s := mustOpen(t)
	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "a", Status: StatusTodo}, {ID: "b", Status: StatusTodo}}, Kind: "init"}); err != nil {
		t.Fatal(err)
	}
	for _, e := range []struct{ id, quote string }{{"a", "quote-a1"}, {"a", "quote-a2"}, {"b", "quote-b1"}} {
		if _, err := s.RecordEvidence(e.id, e.quote); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.AllEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if len(all["a"]) != 2 || len(all["b"]) != 1 {
		t.Errorf("evidence counts wrong: a=%d b=%d", len(all["a"]), len(all["b"]))
	}
	if all["a"][0] != "quote-a1" || all["a"][1] != "quote-a2" {
		t.Errorf("evidence for a not oldest first: %v", all["a"])
	}
}
