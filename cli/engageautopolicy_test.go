package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

func TestAutoActionPolicyMatchesClassAndHost(t *testing.T) {
	roe, err := ParseRoE(strings.NewReader("## In Scope\n192.0.2.1\n198.51.100.2\n## Autonomous Actions\nexploit/network 192.0.2.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	task := engagement.Task{ID: "e1", Kind: "exploit", Target: "192.0.2.1:80", Phase: engagement.PhaseExploit, Surface: engagement.SurfaceNetwork, Status: engagement.StatusTodo, CodeCandidate: true}
	if !roe.AutoActions.permitsTask(task) {
		t.Fatal("authorized task class and host did not match")
	}
	cmd := secgate.Command{Binary: "curl", Args: []string{"http://192.0.2.1:80/"}, Phase: secgate.PhaseExploit, Surface: secgate.SurfaceNetwork, Armed: true, Target: task.Target}
	if !roe.AutoActions.permitsCommand(cmd) {
		t.Fatal("authorized command did not match")
	}
	gate := &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, Allow: secgate.NewAllowlist("curl"), UnattendedAllow: secgate.NewAllowlist("curl"), AutoAction: roe.AutoActions.permitsCommand}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	if d := gate.Authorize(context.Background(), cmd); !d.Allowed {
		t.Fatalf("RoE-authorized armed action still required a confirmer: %s", d.Reason)
	}
	cmd.Args = []string{"http://198.51.100.2/"}
	if roe.AutoActions.permitsCommand(cmd) {
		t.Fatal("another in-scope host received autonomous authority")
	}
	if d := gate.Authorize(context.Background(), cmd); d.Allowed {
		t.Fatal("another in-scope host bypassed per-action confirmation")
	}
	cmd.Args = []string{"http://192.0.2.1/"}
	cmd.Armed = false
	if roe.AutoActions.permitsCommand(cmd) {
		t.Fatal("unarmed exploit received autonomous authority")
	}
	task.Status = engagement.StatusBlocked
	if roe.AutoActions.permitsTask(task) {
		t.Fatal("blocked task received autonomous authority")
	}
	task.Status, task.CoverageGap = engagement.StatusTodo, true
	if roe.AutoActions.permitsTask(task) {
		t.Fatal("coverage gap received autonomous authority")
	}
	task.CoverageGap, task.CodeCandidate = false, false
	if roe.AutoActions.permitsTask(task) {
		t.Fatal("model-created task received autonomous authority")
	}
}

func TestLocalUnattendedRequiresRoEAndBinaryAllowlist(t *testing.T) {
	roe, err := ParseRoE(strings.NewReader("## In Scope\nlocal\n## Autonomous Actions\nrecon/local local\n"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := secgate.Command{Binary: "id", Phase: secgate.PhaseRecon, Surface: secgate.SurfaceLocal, Target: "local"}
	gate := &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, UnattendedAllow: secgate.NewAllowlist(), LocalUnattendedAllow: secgate.NewAllowlist("id"), AutoAction: roe.AutoActions.permitsCommand}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	if d := gate.Authorize(context.Background(), cmd); !d.Allowed {
		t.Fatalf("RoE and allowlist authorized id but gate denied: %s", d.Reason)
	}
	cmd.Target = "pivot.example.com"
	if d := gate.Authorize(context.Background(), cmd); !d.Allowed {
		t.Fatalf("local rule did not cover the generated pivot target: %s", d.Reason)
	}
	localExploitRoE, err := ParseRoE(strings.NewReader("## In Scope\nlocal\n## Autonomous Actions\nexploit/local local\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !localExploitRoE.AutoActions.permitsTask(engagement.Task{ID: "local-defect", Kind: "exploit", Phase: engagement.PhaseExploit, Surface: engagement.SurfaceLocal, Status: engagement.StatusTodo, CodeCandidate: true}) {
		t.Fatal("code-derived local defect with empty analytical target did not match local authority")
	}
	cmd.Target = "local"
	gate.LocalUnattendedAllow = secgate.NewAllowlist()
	if d := gate.Authorize(context.Background(), cmd); d.Allowed {
		t.Fatal("RoE alone allowed local command")
	}
	gate.LocalUnattendedAllow = secgate.NewAllowlist("id")
	gate.AutoAction = nil
	if d := gate.Authorize(context.Background(), cmd); d.Allowed {
		t.Fatal("allowlist alone allowed local command")
	}
	gate.AutoAction = roe.AutoActions.permitsCommand
	cmd.Binary, cmd.Args = "bash", []string{"-c", "id"}
	gate.LocalUnattendedAllow = secgate.NewAllowlist("bash")
	if d := gate.Authorize(context.Background(), cmd); d.Allowed {
		t.Fatal("unattended LOCAL relaxed a structural denial")
	}
	cmd.Binary, cmd.Args = "curl", []string{"http://198.51.100.2/"}
	gate.LocalUnattendedAllow = secgate.NewAllowlist("curl")
	if d := gate.Authorize(context.Background(), cmd); d.Allowed {
		t.Fatal("local autonomous rule allowed a network target")
	}
}
