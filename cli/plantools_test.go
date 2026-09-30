package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
)

func openStore(t *testing.T) *engagement.Store {
	t.Helper()
	s, err := engagement.Open(t.TempDir() + "/e.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestPlanAddCreatesTask(t *testing.T) {
	st := openStore(t)
	tool := newPlanAddTool(st)
	out, err := tool.Call(context.Background(), `{"id":"t1","kind":"recon","target":"10.0.0.5","objective":"enumerate services"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "t1") {
		t.Errorf("result %q missing task id", out)
	}
	got, err := st.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != engagement.StatusTodo || got.Kind != "recon" {
		t.Errorf("task = %+v, want todo/recon", got)
	}
}

func TestPlanAddRejectsBadDeltaSoftly(t *testing.T) {
	st := openStore(t)
	tool := newPlanAddTool(st)
	out, err := tool.Call(context.Background(), `{"id":"","kind":"recon"}`)
	if err != nil {
		t.Fatalf("bad delta must not be a Go error: %v", err)
	}
	if !strings.Contains(strings.ToLower(out), "empty") {
		t.Errorf("result %q should explain the empty-id rejection", out)
	}
}

func TestPlanCompleteMarksDone(t *testing.T) {
	st := openStore(t)
	if _, err := newPlanAddTool(st).Call(context.Background(), `{"id":"t1","kind":"recon"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := newPlanCompleteTool(st).Call(context.Background(), `{"id":"t1"}`); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetTask("t1")
	if got.Status != engagement.StatusDone {
		t.Errorf("status = %q, want done", got.Status)
	}
}

func TestRecordEvidenceStoresQuote(t *testing.T) {
	st := openStore(t)
	if _, err := newPlanAddTool(st).Call(context.Background(), `{"id":"t1","kind":"recon"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := newRecordEvidenceTool(st).Call(context.Background(), `{"task_id":"t1","quote":"port 22 open"}`); err != nil {
		t.Fatal(err)
	}
	ev, _ := st.EvidenceFor("t1")
	if len(ev) != 1 || !strings.Contains(ev[0], "port 22 open") {
		t.Errorf("evidence = %v", ev)
	}
}

func TestRecordEvidenceUnknownTaskSoft(t *testing.T) {
	st := openStore(t)
	out, err := newRecordEvidenceTool(st).Call(context.Background(), `{"task_id":"nope","quote":"x"}`)
	if err != nil {
		t.Fatalf("unknown task must be soft: %v", err)
	}
	if out == "" {
		t.Error("want a message for unknown task")
	}
}

func TestPlanUpdatePartialMerge(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	if _, err := newPlanAddTool(st).Call(ctx, `{"id":"t1","kind":"recon","target":"X","objective":"Y","status":"active"}`); err != nil {
		t.Fatal(err)
	}
	out, err := newPlanUpdateTool(st).Call(ctx, `{"id":"t1","objective":"Z"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "updated task t1") {
		t.Errorf("result %q, want an updated message", out)
	}
	got, err := st.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "recon" || got.Target != "X" {
		t.Errorf("kind/target = %q/%q, want recon/X", got.Kind, got.Target)
	}
	if got.Status != engagement.StatusActive {
		t.Errorf("status = %q, want active", got.Status)
	}
	if got.Objective != "Z" {
		t.Errorf("objective = %q, want Z", got.Objective)
	}
}

func TestPlanUpdateUnknownTaskSoft(t *testing.T) {
	st := openStore(t)
	out, err := newPlanUpdateTool(st).Call(context.Background(), `{"id":"nope","objective":"Z"}`)
	if err != nil {
		t.Fatalf("unknown task must not be a Go error: %v", err)
	}
	if !strings.Contains(out, "not found") {
		t.Errorf("result %q, want a not-found message", out)
	}
	if _, err := st.GetTask("nope"); !errors.Is(err, engagement.ErrNotFound) {
		t.Errorf("GetTask err = %v, want ErrNotFound", err)
	}
}
