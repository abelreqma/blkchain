package secgate

import (
	"context"
	"testing"
	"time"
)

func TestA5_OutOfScopeFailsClosed(t *testing.T) {
	s, err := BuildScope(ScopeSpec{In: []string{"10.0.0.5"}, Out: []string{"10.0.0.5"}})
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Auto, Scope: s, Allow: NewAllowlist("nmap")}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}})
	if d.Allowed {
		t.Error("A5: a target in both In and Out scope must be denied (fail closed)")
	}
}

func TestA6_AutoEmptyAllowlistFallsBackToHITL(t *testing.T) {
	g := &Gate{Mode: Auto, Scope: okScope(t), Allow: NewAllowlist("nmap"), UnattendedAllow: NewAllowlist()}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}})
	if d.Allowed {
		t.Error("A6: /auto with an empty unattended allowlist and no confirmer must deny (HITL fallback)")
	}
}

func TestA7_AutoNoScopeOverrideReconProceedsAndLogs(t *testing.T) {
	// Refused without override.
	g0 := &Gate{Mode: Auto, Allow: NewAllowlist("curl")}
	if err := g0.Start(); err == nil {
		t.Error("A7: /auto with no scope and no override must refuse to start")
	}
	// Logged override: starts, audits, no-target recon proceeds.
	var actions []string
	g := recordingGate(&Gate{Mode: Auto, Allow: NewAllowlist("curl", "nmap"), AutoScopeOverride: true}, &actions)
	if err := g.Start(); err != nil {
		t.Fatalf("A7: override must start: %v", err)
	}
	logged := false
	for _, a := range actions {
		if a == "override" {
			logged = true
		}
	}
	if !logged {
		t.Errorf("A7: the override must be logged; actions=%v", actions)
	}
	if d := g.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"--version"}}); !d.Allowed {
		t.Errorf("A7: no-target recon should proceed under the override: %q", d.Reason)
	}
	if d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}); d.Allowed {
		t.Error("A7: a targeted command must fail closed under the no-scope override")
	}
}

func TestA8_RateExceededDenied(t *testing.T) {
	s, err := BuildScope(ScopeSpec{In: []string{"10.0.0.0/24"}, Rate: "1/s"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2000, 0)
	g := &Gate{Mode: Auto, Scope: s, Allow: NewAllowlist("nmap"), Now: func() time.Time { return now }}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	cmd := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}
	if d := g.Authorize(context.Background(), cmd); !d.Allowed {
		t.Fatalf("A8: first command within rate should be allowed: %q", d.Reason)
	}
	if d := g.Authorize(context.Background(), cmd); d.Allowed {
		t.Error("A8: a command exceeding the RoE rate must be denied")
	}
}
