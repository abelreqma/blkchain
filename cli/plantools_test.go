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

func TestPlanAddBasisIDsPersisted(t *testing.T) {
	st := openStore(t)
	tool := newPlanAddTool(st)
	if _, err := tool.Call(context.Background(), `{"id":"t1","kind":"recon"}`); err != nil {
		t.Fatal(err)
	}
	out, err := tool.Call(context.Background(), `{"id":"t2","kind":"web","basis_ids":["t1"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "rejected") {
		t.Fatalf("plan_add with a known basis id was rejected: %q", out)
	}
	got, err := st.GetTask("t2")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.BasisIDs) != 1 || got.BasisIDs[0] != "t1" {
		t.Errorf("BasisIDs = %v, want [t1]", got.BasisIDs)
	}
	if len(got.DependsOn) != 0 {
		t.Errorf("DependsOn = %v, basis_ids must not create a dependency", got.DependsOn)
	}
}

func TestPlanAddBasisUnknownRejected(t *testing.T) {
	st := openStore(t)
	out, err := newPlanAddTool(st).Call(context.Background(), `{"id":"t2","kind":"web","basis_ids":["ghost"]}`)
	if err != nil {
		t.Fatalf("unknown basis must be a soft rejection: %v", err)
	}
	if !strings.Contains(out, "rejected") || !strings.Contains(out, "ghost") {
		t.Errorf("result %q should reject unknown basis id ghost", out)
	}
	if _, err := st.GetTask("t2"); !errors.Is(err, engagement.ErrNotFound) {
		t.Errorf("t2 must not be stored, GetTask err = %v", err)
	}
}

func TestPlanAddBasisSelfRejected(t *testing.T) {
	st := openStore(t)
	out, err := newPlanAddTool(st).Call(context.Background(), `{"id":"t1","kind":"web","basis_ids":["t1"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "rejected") || !strings.Contains(out, "itself") {
		t.Errorf("result %q should reject a self basis", out)
	}
}

func TestPlanAddBasisDoesNotBlockScheduling(t *testing.T) {
	st := openStore(t)
	add := newPlanAddTool(st)
	if _, err := add.Call(context.Background(), `{"id":"t1","kind":"recon"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := add.Call(context.Background(), `{"id":"t2","kind":"web","basis_ids":["t1"]}`); err != nil {
		t.Fatal(err)
	}

	out, err := newPlanUpdateTool(st).Call(context.Background(), `{"id":"t2","status":"active"}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "rejected") {
		t.Fatalf("activating a task whose basis is todo was rejected: %q", out)
	}
	got, _ := st.GetTask("t2")
	if got.Status != engagement.StatusActive {
		t.Errorf("status = %q, want active", got.Status)
	}
	if len(got.BasisIDs) != 1 || got.BasisIDs[0] != "t1" {
		t.Errorf("BasisIDs = %v after update, want [t1] preserved", got.BasisIDs)
	}
}

// planAddJSON is a small helper to call the plan_add tool.
func callPlanAdd(t *testing.T, tool interface {
	Call(context.Context, string) (string, error)
}, json string) string {
	t.Helper()
	out, err := tool.Call(context.Background(), json)
	if err != nil {
		t.Fatalf("plan_add call: %v", err)
	}
	return out
}

func TestPlanAddRejectsOpenDuplicate(t *testing.T) {
	st := openStore(t)
	tool := newPlanAddTool(st)
	callPlanAdd(t, tool, `{"id":"t1","kind":"recon","target":"10.0.0.5","objective":"enumerate services","surface":"network"}`)
	// A near-duplicate storm entry: different id, identical kind/target/objective/surface.
	out := callPlanAdd(t, tool, `{"id":"t2","kind":"recon","target":"10.0.0.5","objective":"enumerate services","surface":"network"}`)
	if !strings.Contains(out, "duplicate") {
		t.Fatalf("plan_add of a duplicate = %q, want a duplicate rejection", out)
	}
	if _, err := st.GetTask("t2"); !errors.Is(err, engagement.ErrNotFound) {
		t.Fatalf("duplicate task t2 was created (err=%v); it must not be added", err)
	}
}

func TestPlanAddAllowsDistinctObjective(t *testing.T) {
	st := openStore(t)
	tool := newPlanAddTool(st)
	callPlanAdd(t, tool, `{"id":"t1","kind":"recon","target":"10.0.0.5","objective":"enumerate services","surface":"network"}`)
	out := callPlanAdd(t, tool, `{"id":"t2","kind":"recon","target":"10.0.0.5","objective":"brute force ssh","surface":"network"}`)
	if strings.Contains(out, "duplicate") {
		t.Fatalf("distinct-objective task rejected as duplicate: %q", out)
	}
	if _, err := st.GetTask("t2"); err != nil {
		t.Fatalf("distinct task t2 should be added: %v", err)
	}
}

func TestPlanAddAllowsDuplicateAfterTaskClosed(t *testing.T) {
	st := openStore(t)
	tool := newPlanAddTool(st)
	callPlanAdd(t, tool, `{"id":"t1","kind":"recon","target":"10.0.0.5","objective":"enumerate services","surface":"network"}`)
	// Close t1 so it is no longer open.
	if _, err := st.Apply(engagement.Delta{Completes: []string{"t1"}, Kind: "test-close"}); err != nil {
		t.Fatal(err)
	}
	out := callPlanAdd(t, tool, `{"id":"t2","kind":"recon","target":"10.0.0.5","objective":"enumerate services","surface":"network"}`)
	if strings.Contains(out, "duplicate") {
		t.Fatalf("re-adding an identical task after the prior one closed was rejected: %q", out)
	}
	if _, err := st.GetTask("t2"); err != nil {
		t.Fatalf("task t2 should be added after t1 closed: %v", err)
	}
}

func TestPlanAddExplicitDifferentSurfaceAllowed(t *testing.T) {
	st := openStore(t)
	tool := newPlanAddTool(st)
	callPlanAdd(t, tool, `{"id":"t1","kind":"recon","target":"10.0.0.5","objective":"enumerate services","surface":"network"}`)
	out := callPlanAdd(t, tool, `{"id":"t2","kind":"recon","target":"10.0.0.5","objective":"enumerate services","surface":"web"}`)
	if strings.Contains(out, "duplicate") {
		t.Fatalf("an explicitly different surface should not be a duplicate: %q", out)
	}
	if _, err := st.GetTask("t2"); err != nil {
		t.Fatalf("different-surface task t2 should be added: %v", err)
	}
}

func TestModelPlanCannotRetargetCodeCandidate(t *testing.T) {
	st := openStore(t)
	base := engagement.Task{ID: "c1", Kind: "exploit", Target: "192.0.2.1", Phase: engagement.PhaseExploit, Surface: engagement.SurfaceNetwork, Status: engagement.StatusTodo, CodeCandidate: true}
	if _, err := st.Apply(engagement.Delta{Kind: "correlate", Upserts: []engagement.Task{base}}); err != nil {
		t.Fatal(err)
	}
	for _, args := range []string{
		`{"id":"c1","target":"198.51.100.2"}`,
		`{"id":"c1","phase":"post-ex"}`,
		`{"id":"c1","surface":"web"}`,
	} {
		out, err := newPlanUpdateTool(st).Call(context.Background(), args)
		if err != nil || !strings.Contains(out, "identity cannot be changed") {
			t.Fatalf("update %s: out=%q err=%v", args, out, err)
		}
	}
	out, err := newPlanAddTool(st).Call(context.Background(), `{"id":"c1","kind":"exploit","target":"198.51.100.2"}`)
	if err != nil || !strings.Contains(out, "cannot be replaced") {
		t.Fatalf("replacement out=%q err=%v", out, err)
	}
	got, err := st.GetTask("c1")
	if err != nil || !got.CodeCandidate || got.Target != "192.0.2.1" || got.Surface != engagement.SurfaceNetwork {
		t.Fatalf("candidate changed: %+v err=%v", got, err)
	}
}

func TestCoverageGapCannotBeUnblockedByModel(t *testing.T) {
	st := openStore(t)
	gap := engagement.Task{ID: "gap", Kind: "exploit", Target: "192.0.2.1", Phase: engagement.PhaseExploit, Surface: engagement.SurfaceNetwork, Status: engagement.StatusBlocked, CoverageGap: true, CodeCandidate: true}
	if _, err := st.Apply(engagement.Delta{Kind: "correlate", Upserts: []engagement.Task{gap}}); err != nil {
		t.Fatal(err)
	}
	out, err := newPlanUpdateTool(st).Call(context.Background(), `{"id":"gap","status":"todo"}`)
	if err != nil || !strings.Contains(out, "needs code-owned grounding") {
		t.Fatalf("unblock out=%q err=%v", out, err)
	}
	got, err := st.GetTask("gap")
	if err != nil || got.Status != engagement.StatusBlocked || !got.CoverageGap {
		t.Fatalf("coverage gap changed: %+v err=%v", got, err)
	}
}
