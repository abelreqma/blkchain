package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"

	"github.com/tmc/langchaingo/llms"
)

// TestCorrelateNewEvidenceInScopeAndCandidates: the live recon wiring parses a
// tier pass's evidence into in-scope new assets (for per-asset recursion) and
// persisted candidate exploit tasks, and drops an out-of-scope asset.
func TestCorrelateNewEvidenceInScopeAndCandidates(t *testing.T) {
	d := testDeps(t, nil)
	d.Gate = autoGate(t) // scope 10.0.0.0/24
	ex := genericExecutor{d: d}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "10.0.0.5", Status: engagement.StatusTodo,
		Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}
	quote := "Nmap scan report for 10.0.0.42\n" +
		"22/tcp open ssh OpenSSH 8.2p1\n" +
		"Nmap scan report for 8.8.8.8\n"
	id, err := d.Store.RecordEvidence("t1", quote)
	if err != nil {
		t.Fatal(err)
	}
	rows := []engagement.EvidenceRow{{ID: id, Quote: quote}}

	newAssets := ex.correlateNewEvidence(context.Background(), "t1", rows, nil)
	if len(newAssets) != 1 || newAssets[0] != "10.0.0.42" {
		t.Fatalf("newAssets = %v, want [10.0.0.42] (8.8.8.8 is out of scope and dropped)", newAssets)
	}
	cand, err := d.Store.GetTask("exploit-10.0.0.42-22-openssh")
	if err != nil {
		t.Fatalf("candidate exploit task not persisted: %v", err)
	}
	if cand.Phase != engagement.PhaseExploit || cand.Armed || cand.Status != engagement.StatusTodo {
		t.Errorf("candidate = %+v, want unarmed exploit todo", cand)
	}
	if len(cand.BasisIDs) != 1 || cand.BasisIDs[0] != "t1" {
		t.Errorf("candidate BasisIDs = %v, want [t1]", cand.BasisIDs)
	}
}

// TestVantageAdvanceUnlocksLockedSurface: a local-surface task is refused at
// external-unauth; a simulated access-yielding exploit advances the vantage,
// which seeds new-vantage recon (per-asset T0) and unlocks the local surface so
// the task runs.
func TestVantageAdvanceUnlocksLockedSurface(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	d.ReconTiers = false // generic loop; the scripted "done" ends it immediately

	ext := engagement.VantageExternalUnauth
	if _, err := d.Store.Apply(engagement.Delta{SetVantage: &ext}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "loc", Kind: "local", Target: "10.0.0.5", Objective: "enumerate", Status: engagement.StatusTodo,
		Phase: engagement.PhaseRecon, Surface: engagement.SurfaceLocal,
	}}}); err != nil {
		t.Fatal(err)
	}
	ex := genericExecutor{d: d}

	task, err := d.Store.GetTask("loc")
	if err != nil {
		t.Fatal(err)
	}
	out, err := ex.Run(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "not reachable at the current vantage") {
		t.Fatalf("local task at external-unauth must be refused, got %q", out)
	}

	// Simulated successful access-yielding exploit advances the vantage.
	if err := advanceVantage(context.Background(), d.Store, engagement.VantageInternalFoothold, "10.0.0.5", ""); err != nil {
		t.Fatalf("advanceVantage: %v", err)
	}
	if _, err := d.Store.GetTask(reconTaskID("10.0.0.5") + "-local"); err != nil {
		t.Fatalf("advance did not seed a per-asset local recon T0 task: %v", err)
	}

	task2, err := d.Store.GetTask("loc")
	if err != nil {
		t.Fatal(err)
	}
	out2, err := ex.Run(context.Background(), task2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out2, "not reachable at the current vantage") {
		t.Fatalf("local task must run after the vantage advance, got refusal: %q", out2)
	}
}
