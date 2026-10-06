package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"

	"github.com/tmc/langchaingo/llms"
)

// A-REPL: the gate the REPL builds from the session mode actually governs
// execution - not a cosmetic indicator, and not the ungated Hermes path. Safe
// with no confirmer fails closed; Auto in scope allows a recon command.
func TestReplEngageGateGovernsBySessionMode(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	scope, _ := secgate.ParseScope(strings.NewReader("10.0.0.0/24\n"))
	recon := secgate.Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}

	// Safe mode, no confirmer: the command denies (fail closed) -> the path is gated.
	g := buildEngageGate(ws, scope, secgate.Safe, nil, secgate.NewSessionApprovals(), t.TempDir(), gatePolicy{}, func(string, string) {})
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	if d := g.Authorize(context.Background(), recon); d.Allowed {
		t.Errorf("Safe mode, no confirmer: command allowed, want deny (fail closed, gated)")
	}

	// Auto mode in scope: the recon command is allowed (gate governs, not Hermes).
	g2 := buildEngageGate(ws, scope, secgate.Auto, nil, secgate.NewSessionApprovals(), t.TempDir(), gatePolicy{}, func(string, string) {})
	if err := g2.Start(); err != nil {
		t.Fatal(err)
	}
	if d := g2.Authorize(context.Background(), recon); !d.Allowed {
		t.Errorf("Auto mode in scope: recon command denied: %s", d.Reason)
	}
}

func TestScopeDetected(t *testing.T) {
	dir := t.TempDir()
	if scopeDetected(dir) {
		t.Errorf("empty dir: scopeDetected = true, want false")
	}
	if err := os.WriteFile(filepath.Join(dir, "ROE.md"), []byte("## In Scope\n10.0.0.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !scopeDetected(dir) {
		t.Errorf("dir with ROE.md: scopeDetected = false, want true")
	}
}

// Smoke: runReplEngage assembles the gated run and completes. The scripted model
// returns a final answer with no tool calls, so this exercises scope resolve ->
// buildEngageGate -> gate.Start -> runOrchestrator end to end in Safe mode.
func TestRunReplEngageSmoke(t *testing.T) {
	stubEngageRunner(t)
	workspace := t.TempDir()
	model := &scriptModel{resps: []*llms.ContentResponse{finalResp("engagement complete")}}
	final, err := runReplEngage(
		context.Background(),
		workspace, // wsDir (hermetic)
		testEngageRoE(t),
		secgate.Safe, false,
		model, nil, ragconfig.Config{TopK: 5}, modelPrefs{}, nil,
		&countingConfirmer{ok: true}, askuser.AutoAsker{}, nil, "enumerate the lab", nil,
	)
	if err != nil {
		t.Fatalf("runReplEngage: %v", err)
	}
	if !strings.Contains(final, "engagement complete") {
		t.Errorf("final = %q, want the model's answer", final)
	}
	for _, name := range []string{"report.md", "report.json", "actions.jsonl"} {
		if _, err := os.Stat(filepath.Join(workspace, name)); err != nil {
			t.Fatalf("REPL report %s missing: %v", name, err)
		}
	}

}

func TestRunReplEngagePersistsFinalAssessment(t *testing.T) {
	stubEngageRunner(t)
	wsDir := t.TempDir()
	model := &scriptModel{resps: []*llms.ContentResponse{finalResp("observed HTTP response")}}
	final, err := runReplEngage(context.Background(), wsDir, testEngageRoE(t), secgate.Safe, false,
		model, nil, ragconfig.Config{TopK: 5}, modelPrefs{}, nil,
		&countingConfirmer{ok: true}, askuser.AutoAsker{}, nil, "inspect the lab", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(final, "observed HTTP response") || !strings.Contains(final, filepath.Join(wsDir, "report.md")) {
		t.Fatalf("final output=%q", final)
	}
	data, err := os.ReadFile(filepath.Join(wsDir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Final string `json:"final"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Final != "observed HTTP response" {
		t.Fatalf("saved final=%q", report.Final)
	}
}

func TestRunReplEngageRetainsPriorAssessmentOnRetryFailure(t *testing.T) {
	stubEngageRunner(t)
	wsDir, cwd := t.TempDir(), testEngageRoE(t)
	args := func(model toolLoopModel) (string, error) {
		return runReplEngage(context.Background(), wsDir, cwd, secgate.Safe, false,
			model, nil, ragconfig.Config{TopK: 5}, modelPrefs{}, nil,
			&countingConfirmer{ok: true}, askuser.AutoAsker{}, nil, "inspect the lab", nil)
	}
	if _, err := args(&scriptModel{resps: []*llms.ContentResponse{finalResp("prior assessment")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := args(errModel{}); err == nil {
		t.Fatal("expected model failure on retry")
	}
	data, err := os.ReadFile(filepath.Join(wsDir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Final string `json:"final"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Final != "prior assessment" {
		t.Fatalf("prior assessment lost: %q", report.Final)
	}
}

func TestRunReplEngageResumesSavedScopeAndOpenTask(t *testing.T) {
	stubEngageRunner(t)
	wsDir, cwd := t.TempDir(), t.TempDir()
	roePath := filepath.Join(cwd, "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	goal := "inspect 192.0.2.1"
	run := func(model toolLoopModel) (string, error) {
		return runReplEngage(context.Background(), wsDir, cwd, secgate.Safe, false,
			model, nil, ragconfig.Config{TopK: 5}, modelPrefs{}, nil,
			&countingConfirmer{ok: true}, askuser.AutoAsker{}, nil, goal, nil)
	}
	first := &scriptModel{resps: []*llms.ContentResponse{
		toolCallResp("c1", "plan_add", `{"id":"t1","kind":"web","target":"192.0.2.1","objective":"inspect"}`),
		finalResp("paused for continuation"),
	}}
	if _, err := run(first); err != nil {
		t.Fatal(err)
	}
	before, err := engagement.OpenWorkspace(wsDir)
	if err != nil {
		t.Fatal(err)
	}
	vantage := engagement.VantageInternalFoothold
	if _, err := before.Store.Apply(engagement.Delta{Kind: "vantage", SetVantage: &vantage}); err != nil {
		t.Fatal(err)
	}
	before.Close()
	if err := os.WriteFile(roePath, []byte("## In Scope\n198.51.100.2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(&scriptModel{resps: []*llms.ContentResponse{finalResp("must not run")}}); err == nil || !strings.Contains(err.Error(), "policy differs") {
		t.Fatalf("changed RoE was accepted: %v", err)
	}
	if err := os.WriteFile(roePath, []byte("## In Scope\n192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	final, err := run(&scriptModel{resps: []*llms.ContentResponse{finalResp("continued")}})
	if err != nil || !strings.Contains(final, "continued") {
		t.Fatalf("final=%q err=%v", final, err)
	}
	ws, err := engagement.OpenWorkspace(wsDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if _, err := ws.Store.GetTask("t1"); err != nil {
		t.Fatalf("open task lost: %v", err)
	}
	if snap, err := ws.Store.Snapshot(context.Background()); err != nil || snap.Vantage != vantage {
		t.Fatalf("resumed vantage=%q err=%v", snap.Vantage, err)
	}
	saved, err := os.ReadFile(filepath.Join(wsDir, "policy.json"))
	if err != nil || !strings.Contains(string(saved), "192.0.2.1") || strings.Contains(string(saved), "198.51.100.2") {
		t.Fatalf("saved RoE=%q err=%v", saved, err)
	}
}

type reportWriteFailureModel struct{ workspace string }

func (m reportWriteFailureModel) GenerateContent(_ context.Context, _ []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	path := filepath.Join(m.workspace, "report.md")
	if err := os.Remove(path); err != nil {
		return nil, err
	}
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, err
	}
	return finalResp("validated finding"), nil
}

func TestRunReplEngagePreservesFinalOnReportWriteFailure(t *testing.T) {
	stubEngageRunner(t)
	wsDir := t.TempDir()
	final, err := runReplEngage(context.Background(), wsDir, testEngageRoE(t), secgate.Safe, false,
		reportWriteFailureModel{workspace: wsDir}, nil, ragconfig.Config{TopK: 5}, modelPrefs{}, nil,
		&countingConfirmer{ok: true}, askuser.AutoAsker{}, nil, "inspect the lab", nil)
	if err == nil || !strings.Contains(err.Error(), "final report write failed") || final != "validated finding" || strings.Contains(final, "Report:") {
		t.Fatalf("final=%q err=%v", final, err)
	}
}

// TestApplyArmReqInjectsRequester: the REPL arm-requester injection seam sets
// deps.ArmReq when a requester is passed, and leaves it nil otherwise (fail-safe).
func TestApplyArmReqInjectsRequester(t *testing.T) {
	req := &testArmRequester{decision: ArmApprove}
	if got := applyArmReq(engageDeps{}, req); got.ArmReq != req {
		t.Fatal("applyArmReq did not set deps.ArmReq from the passed requester")
	}
	if got := applyArmReq(engageDeps{}); got.ArmReq != nil {
		t.Fatal("applyArmReq with no requester must leave deps.ArmReq nil")
	}
	if got := applyArmReq(engageDeps{}, ArmRequester(nil)); got.ArmReq != nil {
		t.Fatal("applyArmReq with an explicit nil requester must leave deps.ArmReq nil")
	}
}

// TestSetReplArmRequester: the TUI's injection seam round-trips through the
// process-wide setter that runReplEngage reads into deps.ArmReq.
func TestSetReplArmRequester(t *testing.T) {
	t.Cleanup(func() { SetReplArmRequester(nil) })
	if replArmReq() != nil {
		t.Fatal("replArmReq must start nil")
	}
	req := &testArmRequester{decision: ArmApprove}
	SetReplArmRequester(req)
	if replArmReq() != req {
		t.Fatal("SetReplArmRequester did not wire the requester")
	}
	if got := applyArmReq(engageDeps{}, replArmReq()); got.ArmReq != req {
		t.Fatal("runReplEngage's applyArmReq(replArmReq()) must carry the wired requester into deps")
	}
	SetReplArmRequester(nil)
	if replArmReq() != nil {
		t.Fatal("SetReplArmRequester(nil) must clear the requester")
	}
}
