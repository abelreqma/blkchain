package main

import (
	"context"
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

func TestValidateEngageModeAutoNeedsScopeOrOverride(t *testing.T) {
	if err := validateEngageMode(secgate.Auto, false, nil); err == nil {
		t.Errorf("auto + no scope + no override: want error")
	}
	if err := validateEngageMode(secgate.Auto, true, nil); err != nil {
		t.Errorf("auto + override: want nil, got %v", err)
	}
	if err := validateEngageMode(secgate.Safe, false, nil); err != nil {
		t.Errorf("safe: want nil, got %v", err)
	}
	// Auto with a real in-scope scope validates.
	scope, _ := secgate.ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err := validateEngageMode(secgate.Auto, false, scope); err != nil {
		t.Errorf("auto + scope: want nil, got %v", err)
	}
}

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

func TestUnattendedBoundEmpty(t *testing.T) {
	// No config -> empty bound -> HITL fallback (true).
	empty := t.TempDir()
	if !unattendedBoundEmpty(empty) {
		t.Errorf("no config: unattendedBoundEmpty = false, want true")
	}
	// Config with a non-empty allowed_binaries list -> not empty (false).
	withList := t.TempDir()
	cfgDir := filepath.Join(withList, ".blkchain")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.yaml"), []byte("allowed_binaries:\n  - nmap\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if unattendedBoundEmpty(withList) {
		t.Errorf("config with allowed_binaries list: unattendedBoundEmpty = true, want false")
	}
}

// Smoke: runReplEngage assembles the gated run and completes. The scripted model
// returns a final answer with no tool calls, so this exercises scope resolve ->
// buildEngageGate -> gate.Start -> runOrchestrator end to end in Safe mode.
func TestRunReplEngageSmoke(t *testing.T) {
	model := &scriptModel{resps: []*llms.ContentResponse{finalResp("engagement complete")}}
	final, err := runReplEngage(
		context.Background(),
		t.TempDir(), // wsDir (hermetic)
		t.TempDir(), // cwd with no ROE.md -> scope nil, Safe is fine
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
}
