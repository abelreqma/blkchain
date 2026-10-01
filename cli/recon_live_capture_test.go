package main

import (
	"testing"

	"blkchain/cli/internal/engagement"
)

func TestRunOutputsOutputs(t *testing.T) {
	r := NewRunOutputs()
	r.Add("t1", "a")
	r.Add("t1", "b")
	r.Add("t2", "x")
	got := r.Outputs("t1")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("Outputs(t1) = %v, want [a b]", got)
	}
	// Returned slice is a copy: mutating it does not corrupt the store.
	got[0] = "mutated"
	if r.Outputs("t1")[0] != "a" {
		t.Fatalf("Outputs returned an aliased slice; mutation leaked into the store")
	}
	if len(r.Outputs("none")) != 0 {
		t.Fatalf("Outputs(none) should be empty")
	}
}

// captureDeps builds a genericExecutor with a real store + capture store for the
// helper tests; the model is unused by captureTierEvidence.
func captureDeps(t *testing.T) genericExecutor {
	t.Helper()
	d := testDeps(t, nil)
	d.Runs = NewRunOutputs()
	// RecordEvidence requires the task to exist, so seed t1.
	if _, err := d.Store.Apply(engagement.Delta{Kind: "seed", Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "h", Status: engagement.StatusTodo,
	}}}); err != nil {
		t.Fatal(err)
	}
	return genericExecutor{d: d}
}

func TestCaptureTierEvidenceBackstopRecordsWhenModelDidnt(t *testing.T) {
	e := captureDeps(t)
	// Simulate run_command captures this pass; the model recorded nothing.
	e.d.Runs.Add("t1", "Nmap scan report for 10.0.0.5\n8080/tcp open http nginx 1.25.5")
	e.d.Runs.Add("t1", "") // empty output is skipped, not recorded
	rows, err := e.captureTierEvidence("t1", "web", "10.0.0.5", "liveness", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("backstop recorded %d rows, want 1 (empty output skipped)", len(rows))
	}
	ev, _ := e.d.Store.EvidenceFor("t1")
	if len(ev) != 1 || ev[0] != "Nmap scan report for 10.0.0.5\n8080/tcp open http nginx 1.25.5" {
		// No-fabrication: the recorded quote is the captured output verbatim.
		t.Fatalf("recorded evidence = %v, want the captured command output verbatim", ev)
	}
}

func TestCaptureTierEvidenceNoDoubleCountWhenModelRecorded(t *testing.T) {
	e := captureDeps(t)
	// The model recorded a row this pass AND a command output was captured.
	if _, err := e.d.Store.RecordEvidence("t1", "model-quoted finding"); err != nil {
		t.Fatal(err)
	}
	e.d.Runs.Add("t1", "some captured output")
	rows, err := e.captureTierEvidence("t1", "network", "10.0.0.5", "sweep", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Quote != "model-quoted finding" {
		t.Fatalf("rows = %+v, want only the model's row (no backstop double-count)", rows)
	}
	ev, _ := e.d.Store.EvidenceFor("t1")
	if len(ev) != 1 {
		t.Fatalf("evidence rows = %d, want 1; the backstop double-counted the captured output", len(ev))
	}
}

func TestCaptureTierEvidenceCoverageGapWhenNothingCaptured(t *testing.T) {
	e := captureDeps(t)
	// Model recorded nothing and nothing was captured this pass.
	rows, err := e.captureTierEvidence("t1", "web", "10.0.0.5", "liveness", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("rows = %d, want 0 when nothing was captured (coverage-gap path)", len(rows))
	}
	// The no-evidence outcome is surfaced (coverage-gap audit), not silently
	// dropped; no evidence row is fabricated.
	ev, _ := e.d.Store.EvidenceFor("t1")
	if len(ev) != 0 {
		t.Fatalf("evidence rows = %d, want 0 (nothing to record)", len(ev))
	}
}

// Guard: the backstop only records outputs captured AFTER the pre-pass count, so
// a prior pass's output is not re-recorded.
func TestCaptureTierEvidenceOnlyThisPassOutputs(t *testing.T) {
	e := captureDeps(t)
	e.d.Runs.Add("t1", "prior pass output")
	beforeCmds := e.d.Runs.Count("t1") // 1
	e.d.Runs.Add("t1", "this pass output")
	rows, err := e.captureTierEvidence("t1", "network", "h", "sweep", nil, beforeCmds)
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := e.d.Store.EvidenceFor("t1")
	if len(rows) != 1 || len(ev) != 1 || ev[0] != "this pass output" {
		t.Fatalf("recorded = %v, want only this pass's output", ev)
	}
}
