package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"

	"github.com/tmc/langchaingo/llms"
)

// cloudProbeNoRecordModel drives the cloud recon executor to run ONE in-scope curl
// metadata probe and then finish WITHOUT ever calling record_evidence, and to stop
// at the sufficiency grader. It proves the code-side capture backstop
// (captureTierEvidence) records the probe output as evidence even though the model
// recorded nothing - the no-silent-drop guarantee the shared helper provides, adopted on
// the bespoke cloud recon path.
type cloudProbeNoRecordModel struct{}

func (cloudProbeNoRecordModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	var human string
	toolTurns := 0
	for _, m := range msgs {
		if m.Role == llms.ChatMessageTypeTool {
			toolTurns++
		}
		if m.Role != llms.ChatMessageTypeHuman {
			continue
		}
		for _, p := range m.Parts {
			if tc, ok := p.(llms.TextContent); ok {
				human += tc.Text
			}
		}
	}
	if strings.Contains(human, "Respond with ONLY one JSON object") {
		return finalResp(`{"continue": false}`), nil
	}
	if toolTurns == 0 {
		return toolCallResp("c1", "run_command", `{"binary":"curl","args":["http://10.0.0.5/latest/meta-data/iam/security-credentials/role"]}`), nil
	}
	return finalResp("tier done"), nil
}

// TestCloudReconCodeSideEvidenceAndCandidate: the cloud recon path adopts the
// code-side capture helper. The model runs an in-scope metadata probe but never
// records evidence; captureTierEvidence must still record the captured command
// output as evidence (no silent drop), and the cloud finding correlation must then
// emit a candidate from it. With no retrieval configured (RC nil) the IMDS-credential
// detection cannot be grounded, so it surfaces as a non-actionable coverage-gap
// (Status blocked + CoverageGap), never vanishing. Hermetic: execRunner stubbed.
func TestCloudReconCodeSideEvidenceAndCandidate(t *testing.T) {
	d := testDeps(t, cloudProbeNoRecordModel{})
	d.ReconTiers = true
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		return runResult{Output: awsCredQuote}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "cloud", Target: "10.0.0.5", Objective: "enumerate cloud surface",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceCloudAWS,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executorFor(d, task).Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}

	rows, err := d.Store.EvidenceRowsFor("t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no evidence row for the cloud recon: the model did not record_evidence and the code-side capture backstop did not record it (no-silent-drop violated)")
	}

	findings, gaps := cloudCandidateSplit(t, d)
	if len(findings) != 0 {
		t.Errorf("RC nil cannot ground the detection; want no actionable finding, got %+v", findings)
	}
	if len(gaps) != 1 {
		t.Fatalf("the captured IMDS-credential evidence must emit exactly one coverage-gap (no silent drop), got %d", len(gaps))
	}
	if !gaps[0].CoverageGap || gaps[0].Status != engagement.StatusBlocked {
		t.Errorf("uncited cloud candidate = {Status:%q CoverageGap:%v}, want a blocked coverage-gap", gaps[0].Status, gaps[0].CoverageGap)
	}
	if gaps[0].Phase != engagement.PhaseExploit || gaps[0].Armed {
		t.Errorf("cloud candidate = %+v, want an unarmed exploit candidate", gaps[0])
	}
}
