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
	if _, err := newRecordEvidenceTool(st).Call(context.Background(), `{"task_id":"t1","quote":"port 22 open"}`); err != nil {
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

func TestPlanCompleteRequiresEvidence(t *testing.T) {
	st := openStore(t)
	if _, err := newPlanAddTool(st).Call(context.Background(), `{"id":"t1","kind":"recon"}`); err != nil {
		t.Fatal(err)
	}
	// No evidence yet -> complete is soft-rejected and the task stays not-done.
	out, err := newPlanCompleteTool(st).Call(context.Background(), `{"id":"t1"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(out), "evidence") {
		t.Errorf("expected an evidence-required message, got %q", out)
	}
	got, _ := st.GetTask("t1")
	if got.Status == engagement.StatusDone {
		t.Error("task must not be done without evidence")
	}
	// With evidence, complete succeeds.
	if _, err := newRecordEvidenceTool(st).Call(context.Background(), `{"task_id":"t1","quote":"port 22 open"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := newPlanCompleteTool(st).Call(context.Background(), `{"id":"t1"}`); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetTask("t1")
	if got.Status != engagement.StatusDone {
		t.Errorf("status = %q, want done after evidence", got.Status)
	}
}

func TestVerifiedRecordEvidenceRejectsFabricated(t *testing.T) {
	st := openStore(t)
	if _, err := newPlanAddTool(st).Call(context.Background(), `{"id":"t1","kind":"recon"}`); err != nil {
		t.Fatal(err)
	}
	verify := func(task, quote string) bool { return task == "t1" && quote == "real output" }
	tool := newVerifiedRecordEvidenceTool(st, verify)
	// A fabricated quote is rejected and stored nothing.
	out, err := tool.Call(context.Background(), `{"task_id":"t1","quote":"made up"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(out), "exact quote") {
		t.Errorf("want a real-quote-required message, got %q", out)
	}
	if ev, _ := st.EvidenceFor("t1"); len(ev) != 0 {
		t.Error("fabricated evidence must not be stored")
	}
	// A real quote is stored.
	if _, err := tool.Call(context.Background(), `{"task_id":"t1","quote":"real output"}`); err != nil {
		t.Fatal(err)
	}
	if ev, _ := st.EvidenceFor("t1"); len(ev) != 1 {
		t.Error("verified evidence should be stored")
	}
}

func TestPlanAddAndUpdateRefuseDoneStatus(t *testing.T) {
	st := openStore(t)
	out, err := newPlanAddTool(st).Call(context.Background(), `{"id":"t1","kind":"recon","status":"done"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(out), "done") {
		t.Errorf("plan_add should refuse status done, got %q", out)
	}
	if _, err := st.GetTask("t1"); err == nil {
		t.Error("plan_add with status done must not create the task")
	}
	// plan_update likewise.
	if _, err := newPlanAddTool(st).Call(context.Background(), `{"id":"t2","kind":"recon"}`); err != nil {
		t.Fatal(err)
	}
	out2, err := newPlanUpdateTool(st).Call(context.Background(), `{"id":"t2","status":"done"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(out2), "done") {
		t.Errorf("plan_update should refuse status done, got %q", out2)
	}
	got, _ := st.GetTask("t2")
	if got.Status == engagement.StatusDone {
		t.Error("plan_update must not set done directly")
	}
}
