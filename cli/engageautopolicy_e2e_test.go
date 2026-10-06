package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
)

func TestRoEAutoArmLocalLLM(t *testing.T) {
	requireLocalStack(t, "requires the local LLM stack")
	t.Setenv("BLK_ENABLE_THINKING", "0")
	cfg := ragconfig.Load()
	model, err := newOMLX(cfg, resolveModel(cfg))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := newRetrievalClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	roe, err := ParseRoE(strings.NewReader("## In Scope\n192.0.2.1\n## Autonomous Actions\nexploit/network 192.0.2.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	d := testDeps(t, model)
	d.RC, d.Cfg = rc, cfg
	d.WorkDir = t.TempDir()
	d.Runs = NewRunOutputs()
	d.ExploitTools = []string{"curl"}
	d.AutoActions = roe.AutoActions
	d.Gate = &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, Allow: secgate.NewAllowlist("curl"), UnattendedAllow: secgate.NewAllowlist("curl"), AutoAction: roe.AutoActions.permitsCommand}
	if err := d.Gate.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "b1", Kind: "recon", Status: engagement.StatusDone}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.RecordEvidence("b1", "192.0.2.1 service observed"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "e1", Kind: "exploit", Target: "192.0.2.1:80", Phase: engagement.PhaseExploit, Surface: engagement.SurfaceNetwork, Status: engagement.StatusTodo, BasisIDs: []string{"b1"}, CodeCandidate: true}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("e1")
	if err != nil {
		t.Fatal(err)
	}
	requester := &testArmRequester{decision: ArmSkip}
	d.ArmReq = requester
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		return runResult{Output: "HTTP 200 from test fixture"}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := (genericExecutor{d: d}).runExploitPhase(ctx, task)
	if err != nil {
		t.Fatal(err)
	}
	armed, err := d.Store.GetTask("e1")
	if err != nil || !armed.Armed || requester.called {
		t.Fatalf("local model auto-arm: task=%+v requester=%t err=%v output=%q", armed, requester.called, err, out)
	}
	t.Logf("local model=%s auto-arm output=%q", resolveModel(cfg), out)
}
