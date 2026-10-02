package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

// In the EXTERNAL /auto profile a local read utility carrying an
// in-scope host operand and an out-of-scratch file operand is DENIED (not
// allowlisted). A network tool with a file-write escaping scratch is also denied
// (FileAccessViolation), confirming both classes are covered.
func TestExternalAutoDeniesLocalReadUtilities(t *testing.T) {
	s, _ := secgate.ParseScope(strings.NewReader("10.0.0.5\n"))
	g := &secgate.Gate{Mode: secgate.Auto, Scope: s, Allow: secgate.NewAllowlist(externalEngageAllowlist()...)}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	// Read utility with in-scope host operand + file operand: denied by allowlist.
	if d := g.Authorize(context.Background(), secgate.Command{Binary: "grep", Args: []string{"root", "/etc/passwd", "10.0.0.5"}}); d.Allowed {
		t.Error("grep must be denied in external /auto (not on the external allowlist)")
	}
	if d := g.Authorize(context.Background(), secgate.Command{Binary: "cat", Args: []string{"/etc/passwd", "10.0.0.5"}}); d.Allowed {
		t.Error("cat must be denied in external /auto")
	}
	// Network tool still allowed for an in-scope target, but a scratch-escaping
	// write is denied by the file-access recheck.
	if d := g.Authorize(context.Background(), secgate.Command{Binary: "curl", Args: []string{"-o", "/etc/cron.d/x", "http://10.0.0.5/"}}); d.Allowed {
		t.Error("curl -o /etc/cron.d/x must be denied (FileAccessViolation)")
	}
}

// One-composition-root parity: the gate built for a local scope and for an
// external scope carries the same 5 Protected paths (the single recipe lives
// in buildEngageGate), and the external allowlist excludes cat/grep while the
// local profile carries no allowlist at all.
func TestBuildEngageGateOneCompositionRoot(t *testing.T) {
	dir := t.TempDir()
	ws, err := engagement.OpenWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	extScope, err := secgate.ParseScope(strings.NewReader("10.0.0.5\n"))
	if err != nil {
		t.Fatal(err)
	}
	localScope, err := secgate.ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}

	extGate := buildEngageGate(ws, extScope, secgate.Auto, nil, secgate.NewSessionApprovals(), t.TempDir(), gatePolicy{}, nil)
	localGate := buildEngageGate(ws, localScope, secgate.Auto, fakeConfirmer{}, secgate.NewSessionApprovals(), t.TempDir(), gatePolicy{}, nil)

	protMD, protJSON := reportPaths(ws.Dir)
	want := []string{
		ws.Dir + "/engagement.db",
		ws.Dir + "/audit.jsonl",
		ws.EvidenceDir(),
		protMD,
		protJSON,
	}
	for _, gate := range []*secgate.Gate{extGate, localGate} {
		if len(gate.Protected) != len(want) {
			t.Fatalf("Protected = %v, want %v", gate.Protected, want)
		}
		for i, p := range want {
			if gate.Protected[i] != p {
				t.Errorf("Protected[%d] = %q, want %q", i, gate.Protected[i], p)
			}
		}
	}

	if extGate.Allow == nil {
		t.Fatal("external gate must have an allowlist")
	}
	if extGate.Allow.Permits("cat") || extGate.Allow.Permits("grep") {
		t.Error("external allowlist must not permit cat/grep")
	}
	if !extGate.Allow.Permits("nmap") {
		t.Error("external allowlist must permit nmap")
	}
	if localGate.Allow != nil {
		t.Error("local profile must have no allowlist")
	}
}

type fakeConfirmer struct{}

func (fakeConfirmer) Confirm(context.Context, secgate.Command) bool { return true }

// buildEngageGate threads the .blkchain/config.yaml gate policy and the
// auto-scope override onto the Gate.
func TestBuildEngageGateSetsConfigPolicy(t *testing.T) {
	dir := t.TempDir()
	ws, err := engagement.OpenWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	scope, err := secgate.ParseScope(strings.NewReader("10.0.0.5\n"))
	if err != nil {
		t.Fatal(err)
	}
	pol := gatePolicy{
		DeniedBinaries:      []string{"nc"},
		UnattendedAllow:     secgate.NewAllowlist("nmap"),
		AllowInterpreterPoC: true,
		AutoScopeOverride:   true,
	}
	g := buildEngageGate(ws, scope, secgate.Auto, nil, secgate.NewSessionApprovals(), t.TempDir(), pol, nil)
	if len(g.ConfigDenied) != 1 || g.ConfigDenied[0] != "nc" {
		t.Errorf("ConfigDenied not threaded: %v", g.ConfigDenied)
	}
	if g.UnattendedAllow == nil || !g.UnattendedAllow.Permits("nmap") {
		t.Error("UnattendedAllow not threaded")
	}
	if !g.AllowInterpreterPoC {
		t.Error("AllowInterpreterPoC not threaded")
	}
	if !g.AutoScopeOverride {
		t.Error("AutoScopeOverride not threaded")
	}
}
