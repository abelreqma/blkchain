package engagement

import (
	"context"
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
