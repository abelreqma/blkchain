package engagement

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestConcurrentApplyAllLand asserts that N concurrent Apply calls all commit
// (no SQLITE_BUSY, no lost writes) and the final revision equals N.
func TestConcurrentApplyAllLand(t *testing.T) {
	s := mustOpen(t)
	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("t%d", i)
			if _, err := s.Apply(Delta{Upserts: []Task{{ID: id, Status: StatusTodo}}, Kind: "add"}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Apply error: %v", err)
	}
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Tasks) != n {
		t.Errorf("tasks = %d, want %d (lost writes)", len(snap.Tasks), n)
	}
	if snap.Revision != n {
		t.Errorf("revision = %d, want %d", snap.Revision, n)
	}
}

// TestConcurrentWritersMixed interleaves Apply, RecordEvidence and RecordReceipt
// on one task and asserts all land without error or race.
func TestConcurrentWritersMixed(t *testing.T) {
	s := mustOpen(t)
	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "t1", Status: StatusTodo}}, Kind: "init"}); err != nil {
		t.Fatal(err)
	}
	const n = 30
	var wg sync.WaitGroup
	errs := make(chan error, n*3)
	for i := 0; i < n; i++ {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			if _, err := s.Apply(Delta{Upserts: []Task{{ID: fmt.Sprintf("x%d", i), Status: StatusTodo}}, Kind: "add"}); err != nil {
				errs <- err
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			if _, err := s.RecordEvidence("t1", fmt.Sprintf("ev%d", i)); err != nil {
				errs <- err
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			if _, err := s.RecordReceipt("t1", "skill", fmt.Sprintf("d%d", i)); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent mixed-writer error: %v", err)
	}
	ev, err := s.EvidenceFor("t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != n {
		t.Errorf("evidence rows = %d, want %d", len(ev), n)
	}
	rc, err := s.ReceiptsFor("t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rc) != n {
		t.Errorf("receipt rows = %d, want %d", len(rc), n)
	}
}

// TestAllWritersBlockUnderWriteLock is a deterministic white-box guard: while the
// write mutex is held, EVERY store writer must block, then complete once it is
// released. It goes red for any writer that does not take wmu (it would complete
// while the lock is held), which is exactly the coverage the wmu contract claims.
func TestAllWritersBlockUnderWriteLock(t *testing.T) {
	s := mustOpen(t)
	if _, err := s.Apply(Delta{Upserts: []Task{{ID: "t1", Status: StatusTodo}}, Kind: "init"}); err != nil {
		t.Fatal(err)
	}
	writers := map[string]func(){
		"Apply":          func() { s.Apply(Delta{Upserts: []Task{{ID: "w", Status: StatusTodo}}, Kind: "add"}) },
		"RecordEvidence": func() { s.RecordEvidence("t1", "q") },
		"RecordReceipt":  func() { s.RecordReceipt("t1", "sk", "dg") },
		"Audit":          func() { s.Audit("actor", "action", "detail") },
	}
	for name, w := range writers {
		done := make(chan struct{})
		s.wmu.Lock()
		go func() { w(); close(done) }()
		select {
		case <-done:
			s.wmu.Unlock()
			t.Fatalf("%s completed while the write lock was held (writer not serialized by wmu)", name)
		case <-time.After(150 * time.Millisecond):
			// expected: the writer is blocked on wmu
		}
		s.wmu.Unlock()
		select {
		case <-done:
			// completed after unlock
		case <-time.After(3 * time.Second):
			t.Fatalf("%s did not complete after wmu was released", name)
		}
	}
}
