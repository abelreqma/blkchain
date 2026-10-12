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

func TestApprovedCloudIdentityLocalLLM(t *testing.T) {
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
		provider, binary, file, objective, output, want, env string
		surface                                              secgate.Surface
	}{
		{"aws", "aws", "/srv/keys/aws", "Call aws sts get-caller-identity once with the approved AWS credential file on the foothold. Report the returned Account field only.", `{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/fixture"}`, "123456789012", "AWS_SHARED_CREDENTIALS_FILE=/srv/keys/aws", secgate.SurfaceCloudAWS},
		{"gcp", "gcloud", "/srv/keys/gcp.json", "Call gcloud projects list once with the approved GCP credential file on the foothold. Report the project ID only.", `{"projectId":"fixture-project","name":"Fixture Project"}`, "fixture-project", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=/srv/keys/gcp.json", secgate.SurfaceCloudGCP},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			roe, err := ParseRoE(strings.NewReader("## In Scope\n203.0.113.10\n\n## Foothold\n203.0.113.10 user=svc key=/unused surfaces=cloud-" + tc.provider + "\n"))
			if err != nil {
				t.Fatal(err)
			}
			g := &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, Policy: roe.Policy, Allow: secgate.NewAllowlist(),
				CloudIdentities: map[secgate.Surface]secgate.CloudIdentity{
					tc.surface: {Provider: tc.provider, CredentialFile: tc.file},
				}}
			if err := g.Start(); err != nil {
				t.Fatal(err)
			}
			d := testDeps(t, model)
			d.Cfg, d.RC, d.Gate, d.Runs, d.WorkDir = cfg, rc, g, NewRunOutputs(), t.TempDir()
			d.ReconTiers = true
			task := engagement.Task{ID: "cloud-identity-fixture", Kind: "cloud", Target: tc.provider,
				Objective: tc.objective,
				DoneWhen:  "The provider identity is observed", Status: engagement.StatusTodo,
				Phase: engagement.PhaseRecon, Surface: engagement.Surface(tc.surface)}
			if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{task}}); err != nil {
				t.Fatal(err)
			}
			workspace := t.TempDir()
			trace := newActionTranscript(workspace, "off", roe.Policy.RunnerID, 10, 65536, nil)
			if err := os.WriteFile(filepath.Join(workspace, "actions.jsonl"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			runner := &engageRunner{workers: map[string]string{}, foothold: &footholdTransport{name: "ssh", prefix: []string{"ssh", "svc@203.0.113.10", "--"}},
				runFn: func(_ context.Context, stages []pipelineStage, _ string, _ int, _ time.Duration) (runResult, []isolatedStageResult) {
					if len(stages) != 1 || stages[0].Binary != "ssh" || !strings.Contains(strings.Join(stages[0].Args, " "), tc.env) || !strings.Contains(strings.Join(stages[0].Args, " "), tc.binary) {
						return runResult{Err: context.Canceled}, nil
					}
					calls++
					return runResult{Output: tc.output}, []isolatedStageResult{{Stdout: tc.output}}
				}}
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
			defer cancel()
			ctx = context.WithValue(ctx, engageRuntimeKey{}, &engageRuntime{runner: runner, trace: trace, store: d.Store, policy: roe.Policy, cancel: cancel, staged: newVulnScanQueue()})
			out, err := runExecutor(ctx, d, task.ID)
			if err != nil || calls == 0 {
				t.Fatalf("approved cloud model path: calls=%d output=%q err=%v", calls, out, err)
			}
			rows, err := d.Store.EvidenceRowsFor(task.ID)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, row := range rows {
				found = found || strings.Contains(row.Quote, tc.want)
			}
			if !found {
				t.Fatalf("provider identity output was not captured as evidence: rows=%d summary=%q", len(rows), out)
			}
		})
	}
}
