package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
)

func TestExternalADAndApprovedPivotLocalLLM(t *testing.T) {
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
	for _, tc := range []struct {
		name, roe, target, objective string
		surface                      engagement.Surface
		pivot, attached              bool
	}{
		{"external-ad", "## In Scope\n203.0.113.10\n", "203.0.113.10", "Run one bounded nmap -n -Pn -sT -p 389 check of 203.0.113.10 to identify an externally reachable LDAP service. Report only the observed port result.", engagement.SurfaceAD, false, false},
		{"approved-internal-network", "## In Scope\n203.0.113.10\n\n## Foothold\n203.0.113.10 user=svc key=/unused surfaces=network\n", "10.7.0.7", "Run one bounded nmap -n -Pn -sT -p 389 check of approved private target 10.7.0.7 through the declared foothold. Report only the observed port result.", engagement.SurfaceNetwork, true, false},
		{"attached-internal-network", "## In Scope\n203.0.113.10\n", "10.7.0.7", "Run one bounded nmap -n -Pn -sT -p 389 check of approved private target 10.7.0.7 through the attached foothold. Report only the observed port result.", engagement.SurfaceNetwork, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roe, err := ParseRoE(strings.NewReader(tc.roe))
			if err != nil {
				t.Fatal(err)
			}
			g := &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, Policy: roe.Policy, Allow: secgate.NewAllowlist("nmap")}
			if tc.pivot {
				g.PivotScope, err = roe.Scope.WithApprovedPrivateNetworks([]string{"10.7.0.0/24"})
				if err != nil {
					t.Fatal(err)
				}
			}
			if tc.attached {
				g.AttachedFoothold, err = secgate.ParseFoothold("10.7.0.7 transport=command surfaces=local,network,web,ad,container,cloud-aws,cloud-gcp exec=kubectl exec -i fixture --")
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := g.Start(); err != nil {
				t.Fatal(err)
			}
			d := testDeps(t, model)
			d.Cfg, d.RC, d.Gate, d.Runs, d.WorkDir = cfg, rc, g, NewRunOutputs(), t.TempDir()
			d.ReconTiers = true
			vantage := engagement.VantageExternalUnauth
			if tc.pivot {
				vantage = engagement.VantageInternalFoothold
			}
			if _, err := d.Store.Apply(engagement.Delta{SetVantage: &vantage}); err != nil {
				t.Fatal(err)
			}
			task := engagement.Task{ID: "pivot-fixture", Kind: "recon", Target: tc.target, Objective: tc.objective,
				DoneWhen: "Port 389 is observed", Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: tc.surface}
			if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{task}}); err != nil {
				t.Fatal(err)
			}
			workspace := t.TempDir()
			trace := newActionTranscript(workspace, "off", roe.Policy.RunnerID, 10, 65536, nil)
			if err := os.WriteFile(filepath.Join(workspace, "actions.jsonl"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			runner := &engageRunner{workers: map[string]string{},
				runFn: func(_ context.Context, stages []pipelineStage, _ string, _ int, _ time.Duration) (runResult, []isolatedStageResult) {
					wantBinary := "nmap"
					if tc.pivot {
						wantBinary = "ssh"
					}
					if tc.attached {
						wantBinary = "kubectl"
					}
					if len(stages) != 1 || stages[0].Binary != wantBinary {
						return runResult{Err: context.Canceled}, nil
					}
					calls++
					return runResult{Output: "389/tcp open ldap"}, []isolatedStageResult{{Stdout: "389/tcp open ldap"}}
				}}
			if tc.pivot && !tc.attached {
				runner.foothold = &footholdTransport{name: "ssh", prefix: []string{"ssh", "svc@203.0.113.10", "--"}}
			}
			if tc.attached {
				runner.foothold = &footholdTransport{name: "command", carrier: "kubectl", prefix: []string{"kubectl", "exec", "-i", "fixture", "--"}, quote: secgate.QuoteArgv}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
			defer cancel()
			ctx = context.WithValue(ctx, engageRuntimeKey{}, &engageRuntime{runner: runner, trace: trace, store: d.Store, policy: roe.Policy, cancel: cancel, staged: newVulnScanQueue()})
			out, err := runExecutor(ctx, d, task.ID)
			if err != nil || calls == 0 {
				t.Fatalf("local model path: calls=%d output=%q err=%v", calls, out, err)
			}
		})
	}
}
