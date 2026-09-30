package engagement

import (
	"context"
	"strconv"
	"testing"
)

func TestSnapshotEmptyStore(t *testing.T) {
	s, err := Open(t.TempDir() + "/e.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rev, err := s.Revision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rev != 0 {
		t.Fatalf("Revision = %d, want 0", rev)
	}

	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Revision != 0 {
		t.Errorf("snap.Revision = %d, want 0", snap.Revision)
	}
	if snap.Name != "" || snap.ActiveID != "" {
		t.Errorf("snap Name/ActiveID = %q/%q, want empty", snap.Name, snap.ActiveID)
	}
	if snap.Stage != (Stage{}) {
		t.Errorf("snap.Stage = %+v, want zero", snap.Stage)
	}
	if len(snap.Tasks) != 0 {
		t.Errorf("snap.Tasks = %d, want 0", len(snap.Tasks))
	}
}

func TestSnapshotPopulatedIsConsistent(t *testing.T) {
	s, err := Open(t.TempDir() + "/e.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	name := "acme-web"
	active := "t1"
	stage := Stage{Label: "dispatch", Step: 2, Total: 3, Tool: "web"}
	if _, err := s.Apply(Delta{
		Upserts: []Task{
			{ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "enumerate", Status: StatusActive},
			{ID: "t2", Kind: "web", Target: "10.0.0.5", Objective: "login", Status: StatusTodo, DependsOn: []string{"t1"}},
		},
		Kind:        "init",
		SetName:     &name,
		SetActiveID: &active,
		SetStage:    &stage,
	}); err != nil {
		t.Fatal(err)
	}

	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Revision returned by Snapshot must equal the standalone Revision read:
	// both come from a consistent point.
	rev, err := s.Revision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Revision != rev || snap.Revision != 1 {
		t.Errorf("snap.Revision = %d, standalone = %d, want 1", snap.Revision, rev)
	}
	if snap.Name != name || snap.ActiveID != active {
		t.Errorf("snap Name/ActiveID = %q/%q, want %q/%q", snap.Name, snap.ActiveID, name, active)
	}
	if snap.Stage != stage {
		t.Errorf("snap.Stage = %+v, want %+v", snap.Stage, stage)
	}
	if len(snap.Tasks) != 2 {
		t.Fatalf("snap.Tasks = %d, want 2", len(snap.Tasks))
	}
	// Ordering is by created_rev then id.
	if snap.Tasks[0].ID != "t1" || snap.Tasks[1].ID != "t2" {
		t.Errorf("task order = %q,%q, want t1,t2", snap.Tasks[0].ID, snap.Tasks[1].ID)
	}
	if snap.Tasks[0].Status != StatusActive || len(snap.Tasks[1].DependsOn) != 1 || snap.Tasks[1].DependsOn[0] != "t1" {
		t.Errorf("task fields not preserved: %+v", snap.Tasks)
	}
}

// TestSnapshotConcurrentApplyStaysConsistent runs Snapshot while Apply mutates
// the store on another goroutine. It cannot deterministically force a torn read,
// but with the read transaction every Snapshot must be internally consistent:
// its Revision must never exceed the number of committed deltas it can see, and
// a non-zero revision must carry the tasks written by then.
func TestSnapshotConcurrentApplyStaysConsistent(t *testing.T) {
	s, err := Open(t.TempDir() + "/e.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			id := "t" + strconv.Itoa(i)
			if _, err := s.Apply(Delta{Upserts: []Task{{ID: id, Kind: "recon", Status: StatusTodo}}, Kind: "add"}); err != nil {
				t.Errorf("apply: %v", err)
				return
			}
		}
	}()

	for i := 0; i < 200; i++ {
		snap, err := s.Snapshot(context.Background())
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		// Each Apply upserts exactly one new task and bumps the revision by one,
		// so a consistent snapshot has exactly Revision tasks.
		if int64(len(snap.Tasks)) != snap.Revision {
			t.Fatalf("torn snapshot: Revision %d but %d tasks", snap.Revision, len(snap.Tasks))
		}
	}
	<-done
}
