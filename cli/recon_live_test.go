package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

// reconLiveModel drives the live recon-phase executor: within each tier's tool
// loop it runs one command, records an evidence quote from its output, then
// yields; when handed the sufficiency-grader prompt it says stop, so the loop
// ends after the first tier. It branches on message content, so it works across
// the separate per-tier tool loops and the grader call that share one model.
type reconLiveModel struct{}

func (reconLiveModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	for _, m := range msgs {
		if m.Role != llms.ChatMessageTypeHuman {
			continue
		}
		for _, p := range m.Parts {
			tc, ok := p.(llms.TextContent)
			if !ok {
				continue
			}
			if strings.Contains(tc.Text, "Corpus notes (reference only") {
				return finalResp(`{"action": "icmp echo sweep"}`), nil
			}
			if strings.Contains(tc.Text, "Respond with ONLY one JSON object") {
				return finalResp(`{"continue": false}`), nil
			}
		}
	}
	toolTurns := 0
	for _, m := range msgs {
		if m.Role == llms.ChatMessageTypeTool {
			toolTurns++
		}
	}
	switch toolTurns {
	case 0:
		return toolCallResp("c1", "run_command", `{"binary":"nmap","args":["-p","22","10.0.0.5"]}`), nil
	case 1:
		return toolCallResp("c2", "record_evidence", `{"task_id":"t1","quote":"banner-xyz"}`), nil
	}
	return finalResp("tier done"), nil
}

// TestRunReconPhaseDrivesLadderAndPersistsCoverage: a recon-phase task, with the
// tier loop enabled, drives the real gated run_command + evidence path and
// persists ReconCoverage. Hermetic: execRunner is stubbed, no real binary runs.
func TestRunReconPhaseDrivesLadderAndPersistsCoverage(t *testing.T) {
	d := testDeps(t, reconLiveModel{})
	d.ReconTiers = true
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		return runResult{Output: "banner-xyz 22/tcp open"}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "enumerate",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}

	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	ex := genericExecutor{d: d}
	if _, err := ex.Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}

	rows, err := d.Store.AllReconCoverage()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Asset != "10.0.0.5" {
		t.Fatalf("recon coverage rows = %+v, want one for 10.0.0.5", rows)
	}
	if rows[0].Dimensions["hosts"] != engagement.ReconCovered {
		t.Fatalf("hosts dimension = %q, want covered (a tier ran and recorded evidence)", rows[0].Dimensions["hosts"])
	}
}

// TestRunNonReconTaskUsesGenericLoop: even with the tier loop enabled, a task
// that is neither recon (the tier ladder) nor exploit/post-ex (the exploitation
// lifecycle) goes through the generic executor loop and records no recon
// coverage. A report-phase task is such a case.
func TestRunNonReconTaskUsesGenericLoop(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	d.ReconTiers = true
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "web", Target: "10.0.0.5", Objective: "write the report",
		Status: engagement.StatusTodo, Phase: engagement.PhaseReport, Surface: engagement.SurfaceWeb,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	ex := genericExecutor{d: d}
	out, err := ex.Run(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "done") {
		t.Fatalf("non-recon task output = %q, want the generic loop result", out)
	}
	rows, err := d.Store.AllReconCoverage()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("non-recon task produced recon coverage rows %+v, want none", rows)
	}
}

// TestRunReconPhaseConsultsCorpusSelector: with retrieval available, the live
// recon path consults the corpus to prioritize the next action (read-only) and
// still persists coverage through the real gated run_command + evidence path.
func TestRunReconPhaseConsultsCorpusSelector(t *testing.T) {
	d := testDeps(t, reconLiveModel{})
	d.ReconTiers = true
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	rc := &recSearcher{results: []retrieval.Result{
		chunk("offensive-network-attacks", "recon/host.md", "Discovery", "Use an ICMP echo sweep for host discovery."),
	}}
	d.RC = rc
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		return runResult{Output: "banner-xyz 22/tcp open"}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "enumerate",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	ex := genericExecutor{d: d}
	if _, err := ex.Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(rc.query, "reconnaissance") {
		t.Fatalf("selector did not consult the corpus; recSearcher.query = %q", rc.query)
	}
	rows, err := d.Store.AllReconCoverage()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Dimensions["hosts"] != engagement.ReconCovered {
		t.Fatalf("coverage rows = %+v, want one for 10.0.0.5 with hosts covered", rows)
	}
}
