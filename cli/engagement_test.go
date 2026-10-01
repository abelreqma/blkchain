package main

import (
	"context"
	"testing"

	eng "blkchain/cli/internal/engagement"
)

func TestStubEngagementRevisionBumps(t *testing.T) {
	s := newStubEngagement("acme")
	ctx := context.Background()
	r0, err := s.Revision(ctx)
	if err != nil || r0 != 0 {
		t.Fatalf("initial revision = %d, %v; want 0, nil", r0, err)
	}
	s.setSnapshot(eng.Engagement{Tasks: []eng.Task{{ID: "t1", Kind: "recon", Objective: "enumerate host", Status: eng.StatusDone}}})
	r1, _ := s.Revision(ctx)
	if r1 != 1 {
		t.Fatalf("revision after set = %d; want 1", r1)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Revision != 1 || len(snap.Tasks) != 1 || snap.Tasks[0].Status != eng.StatusDone {
		t.Fatalf("snapshot = %+v; want revision 1, one done task", snap)
	}
}
