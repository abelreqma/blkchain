package main

import (
	"context"
	"testing"
)

func TestStubEngagementRevisionBumps(t *testing.T) {
	s := newStubEngagement("acme")
	ctx := context.Background()
	r0, err := s.Revision(ctx)
	if err != nil || r0 != 0 {
		t.Fatalf("initial revision = %d, %v; want 0, nil", r0, err)
	}
	s.setSnapshot(Engagement{Tasks: []Task{{ID: "t1", Kind: "recon", Objective: "enumerate host", Status: TaskDone}}})
	r1, _ := s.Revision(ctx)
	if r1 != 1 {
		t.Fatalf("revision after set = %d; want 1", r1)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Revision != 1 || len(snap.Tasks) != 1 || snap.Tasks[0].Status != TaskDone {
		t.Fatalf("snapshot = %+v; want revision 1, one done task", snap)
	}
	if TaskDone.String() != "done" || TaskTodo.String() != "todo" || TaskNA.String() != "na" {
		t.Fatalf("status strings wrong: done=%q todo=%q na=%q", TaskDone, TaskTodo, TaskNA)
	}
	if taskStatusFromStore("na") != TaskNA || taskStatusFromStore("todo") != TaskTodo || taskStatusFromStore("???") != TaskTodo {
		t.Fatalf("taskStatusFromStore mapping wrong")
	}
}
