package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"

	"github.com/tmc/langchaingo/llms"
)

type webFingerprintNoRecordModel struct{}

func (webFingerprintNoRecordModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
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
		return toolCallResp("c1", "run_command", `{"binary":"nmap","args":["-sV","-p","8080","10.0.0.5"]}`), nil
	}
	return finalResp("tier done"), nil
}

const webNginxScan = "Nmap scan report for 10.0.0.5\n8080/tcp open http nginx 1.25.5"

func TestWebReconCodeSideEvidenceAndCandidate(t *testing.T) {
	d := testDeps(t, webFingerprintNoRecordModel{})
	d.ReconTiers = true
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		return runResult{Output: webNginxScan}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "web", Target: "http://10.0.0.5:8080/", Objective: "fingerprint",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceWeb,
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
		t.Fatal("no evidence row for the web recon: the model did not record_evidence and nothing captured it code-side (upstream no-silent-drop violated)")
	}
	cand, err := d.Store.GetTask("exploit-10.0.0.5-8080-nginx")
	if err != nil {
		t.Fatalf("no candidate-or-coverage-gap from the web recon fingerprint: %v", err)
	}
	if cand.Phase != engagement.PhaseExploit || cand.Armed {
		t.Errorf("candidate = %+v, want unarmed exploit", cand)
	}
	if cand.Status != engagement.StatusBlocked || !cand.CoverageGap {
		t.Errorf("uncited candidate = {Status:%q CoverageGap:%v}, want a blocked coverage-gap", cand.Status, cand.CoverageGap)
	}
}
