package engagement

import (
	"context"
	"errors"
	"testing"
)

func TestRecordAndReadReceipt(t *testing.T) {
	s := mustOpen(t) // helper from delta_test.go
	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "t1", Status: StatusTodo}}, Kind: "init"}); err != nil {
		t.Fatal(err)
	}
	id, err := s.RecordReceipt("t1", "abusing-adcs", "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if id <= 0 {
		t.Errorf("bad id %d", id)
	}
	got, err := s.ReceiptsFor("t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Skill != "abusing-adcs" || got[0].BundleDigest != "deadbeef" {
		t.Errorf("receipt = %+v", got)
	}
	rev, _ := s.Revision(context.Background())
	if got[0].ContextGen != rev {
		t.Errorf("context_gen = %d, want revision %d", got[0].ContextGen, rev)
	}
}

func TestRecordReceiptUnknownTask(t *testing.T) {
	s := mustOpen(t)
	if _, err := s.RecordReceipt("nope", "x", "y"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound for unknown task", err)
	}
}
