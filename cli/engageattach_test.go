package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

func TestAttachFootholdResumesThroughCommandCarrier(t *testing.T) {
	previous := newEngageRunnerForRun
	var probe []pipelineStage
	failProbe := false
	newEngageRunnerForRun = func(_ context.Context, roe *RoE) (*engageRunner, error) {
		carrier, err := newFootholdTransport(roe.Policy.Foothold)
		if err != nil {
			return nil, err
		}
		return &engageRunner{
			workers: map[string]string{}, foothold: carrier,
			runFn: func(_ context.Context, stages []pipelineStage, _ string, _ int, _ time.Duration) (runResult, []isolatedStageResult) {
				probe = append(probe, stages...)
				if failProbe {
					return runResult{Err: errors.New("fixture probe failure")}, []isolatedStageResult{{ExitCode: 1}}
				}
				if len(stages) == 1 && strings.Contains(strings.Join(stages[0].Args, " "), "getent ahosts app.internal.test") {
					return runResult{}, []isolatedStageResult{{Stdout: "10.7.0.8 STREAM app.internal.test\n", ExitCode: 0}}
				}
				return runResult{}, []isolatedStageResult{{ExitCode: 0}}
			},
		}, nil
	}
	t.Cleanup(func() { newEngageRunnerForRun = previous })
	project, workspace := t.TempDir(), t.TempDir()
	roePath := filepath.Join(project, "ROE.md")
	const roeText = "## In Scope\n203.0.113.10\n"
	if err := os.WriteFile(roePath, []byte(roeText), 0600); err != nil {
		t.Fatal(err)
	}
	var evidenceID, cloudEvidenceID int64
	first := engageRunInput{Opts: engageOpts{workspace: workspace}, Cwd: project, Goal: "fixture", Run: func(_ context.Context, d engageDeps, _ string) (string, error) {
		if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{
			{ID: "exploit-1", Kind: "exploit", Phase: engagement.PhaseExploit,
				Surface: engagement.SurfaceNetwork, Target: "203.0.113.10", Armed: true, Status: engagement.StatusTodo},
			{ID: "cloud-1", Kind: "cloud", Surface: engagement.SurfaceCloudAWS, Status: engagement.StatusTodo},
		}}); err != nil {
			return "", err
		}
		var err error
		evidenceID, err = d.Store.RecordEvidence("exploit-1", "session opened on test host")
		if err != nil {
			return "", err
		}
		cloudEvidenceID, err = d.Store.RecordEvidence("cloud-1", "credential file observed")
		return "", errors.Join(err, errors.New("pause fixture"))
	}}
	if _, err := runEngageSession(context.Background(), first); err == nil {
		t.Fatal("fixture did not pause")
	}
	if err := runEngageApproveNetwork([]string{"--workspace", workspace, "10.7.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	badEntry := "10.7.0.7 transport=command surfaces=local,network,web,ad,container,cloud-aws,cloud-gcp exec=sh -c true"
	if err := runEngageAttachFoothold([]string{"--workspace", workspace, "--task", "exploit-1", "--evidence", strconv.FormatInt(evidenceID, 10), "--entry", badEntry}); err == nil {
		t.Fatal("disallowed carrier binary was attached")
	}
	entry := "10.7.0.7 transport=command surfaces=local,network,web,ad,container,cloud-aws,cloud-gcp exec=kubectl exec -i fixture --"
	if err := runEngageAttachFoothold([]string{"--workspace", workspace, "--task", "exploit-1", "--evidence", strconv.FormatInt(evidenceID, 10), "--entry", entry}); err != nil {
		t.Fatal(err)
	}
	if err := runEngageAttachFoothold([]string{"--workspace", workspace, "--task", "exploit-1", "--evidence", strconv.FormatInt(evidenceID, 10), "--entry", entry}); err == nil {
		t.Fatal("second attachment overwrote the first")
	}
	if err := runEngageApproveCloudIdentity([]string{"--workspace", workspace, "--provider", "aws", "--file", "/srv/keys/aws", "--task", "cloud-1", "--evidence", strconv.FormatInt(cloudEvidenceID, 10)}); err != nil {
		t.Fatal(err)
	}
	failProbe = true
	if _, err := runEngageSession(context.Background(), engageRunInput{Opts: engageOpts{resume: workspace}, Run: func(context.Context, engageDeps, string) (string, error) {
		t.Fatal("orchestrator ran after carrier probe failed")
		return "", nil
	}}); err == nil {
		t.Fatal("failed carrier probe allowed resume")
	}
	ws, err := engagement.OpenWorkspace(workspace)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ws.Store.Vantage(context.Background())
	if err != nil || v != engagement.VantageExternalUnauth {
		t.Fatalf("vantage after failed probe = %q, err=%v", v, err)
	}
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	failProbe = false
	second := engageRunInput{Opts: engageOpts{resume: workspace}, Run: func(ctx context.Context, d engageDeps, _ string) (string, error) {
		v, err := d.Store.Vantage(context.Background())
		if err != nil || v != engagement.VantageInternalFoothold {
			t.Fatalf("resumed vantage = %q, err=%v", v, err)
		}
		if d.Gate.Scope.InScope("10.7.0.8") || d.Gate.PivotScope == nil || !d.Gate.PivotScope.InScope("10.7.0.8") {
			t.Fatal("attached network widened worker scope or did not reach the foothold gate")
		}
		for _, command := range []secgate.Command{
			{Binary: "nmap", Args: []string{"-p", "80", "10.8.0.8"}, Phase: secgate.PhaseRecon, Surface: secgate.SurfaceNetwork},
			{Binary: "nmap", Args: []string{"-p", "80", "10.8.0.8"}, Phase: secgate.PhaseRecon, Surface: secgate.SurfaceWeb},
		} {
			if decision := d.Gate.Authorize(ctx, command); decision.Allowed {
				t.Fatalf("out-of-scope command allowed: %+v", command)
			}
		}
		if f := d.Gate.EffectiveFoothold(); f == nil || f.Transport != "command" || f.Host != "10.7.0.7" {
			t.Fatalf("resumed foothold = %+v", f)
		}
		networkTask, err := d.Store.GetTask(approvedNetworkTaskID("10.7.0.0/24"))
		if err != nil || networkTask.Target != "10.7.0.0/24" || networkTask.Surface != engagement.SurfaceNetwork ||
			len(networkTask.BasisIDs) != 1 || networkTask.BasisIDs[0] != "exploit-1" {
			t.Fatalf("approved network task = %+v, err=%v", networkTask, err)
		}
		networkTask.Status = engagement.StatusDone
		if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{networkTask}}); err != nil {
			t.Fatal(err)
		}
		if identity, ok := d.Gate.CloudIdentities[secgate.SurfaceCloudAWS]; !ok || identity.CredentialFile != "/srv/keys/aws" {
			t.Fatalf("resumed cloud identity = %+v", identity)
		}
		command := secgate.Command{Binary: "nmap", Args: []string{"-p", "80", "10.7.0.8"}, Phase: secgate.PhaseRecon, Surface: secgate.SurfaceNetwork}
		if decision := d.Gate.Authorize(ctx, command); !decision.Allowed {
			t.Fatalf("approved private target denied: %s", decision.Reason)
		}
		result := runAuthorized(ctx, d.Gate, command.Binary, command.Args, d.WorkDir, 512, 10*time.Second,
			actionOrigin{Surface: secgate.SurfaceNetwork, SkipVulnIngest: true})
		if result.Err != nil || result.ExitCode != 0 {
			t.Fatalf("pivoted command failed: %+v", result)
		}
		cloudCommand := secgate.Command{Binary: "aws", Args: []string{"ec2", "describe-instances"}, Phase: secgate.PhaseRecon, Surface: secgate.SurfaceCloudAWS}
		if decision := d.Gate.Authorize(ctx, cloudCommand); !decision.Allowed {
			t.Fatalf("approved cloud command denied: %s", decision.Reason)
		}
		result = runAuthorized(ctx, d.Gate, cloudCommand.Binary, cloudCommand.Args, d.WorkDir, 512, 10*time.Second,
			actionOrigin{Surface: secgate.SurfaceCloudAWS, SkipVulnIngest: true})
		if result.Err != nil || result.ExitCode != 0 {
			t.Fatalf("pivoted cloud command failed: %+v", result)
		}
		if d.Gate.WebLookup == nil {
			t.Fatal("resumed foothold has no web resolver")
		}
		ips, err := d.Gate.WebLookup("app.internal.test")
		if err != nil || len(ips) != 1 || ips[0].String() != "10.7.0.8" {
			t.Fatalf("resumed foothold web lookup = %v, err=%v", ips, err)
		}
		return "", errors.New("pause after attach")
	}}
	if _, err := runEngageSession(context.Background(), second); err == nil {
		t.Fatal("fixture did not pause after attach")
	}
	third := engageRunInput{Opts: engageOpts{resume: workspace}, Run: func(_ context.Context, d engageDeps, _ string) (string, error) {
		v, err := d.Store.Vantage(context.Background())
		if err != nil || v != engagement.VantageInternalFoothold {
			t.Fatalf("second resume vantage = %q, err=%v", v, err)
		}
		networkTask, err := d.Store.GetTask(approvedNetworkTaskID("10.7.0.0/24"))
		if err != nil || networkTask.Status != engagement.StatusDone {
			t.Fatalf("approved network task was reset on resume: %+v, err=%v", networkTask, err)
		}
		return "done", nil
	}}
	if _, err := runEngageSession(context.Background(), third); err != nil {
		t.Fatal(err)
	}
	if len(probe) != 6 || probe[0].Binary != "kubectl" || probe[1].Binary != "kubectl" || probe[2].Binary != "kubectl" || probe[3].Binary != "kubectl" || probe[4].Binary != "kubectl" || probe[5].Binary != "kubectl" {
		t.Fatalf("carrier probe = %+v", probe)
	}
	if got := probe[2].Args; len(got) == 0 || got[len(got)-1] != "10.7.0.8" {
		t.Fatalf("pivoted target did not reach carrier: %+v", probe[2])
	}
	cloudArgs := strings.Join(probe[3].Args, " ")
	if !strings.Contains(cloudArgs, "AWS_SHARED_CREDENTIALS_FILE=/srv/keys/aws") || !strings.Contains(cloudArgs, "aws ec2 describe-instances") {
		t.Fatalf("approved cloud identity did not reach carrier: %+v", probe[3])
	}
	if data, err := os.ReadFile(roePath); err != nil || string(data) != roeText {
		t.Fatal(err)
	}
}

func TestAttachFootholdRejectsUnapprovedNetwork(t *testing.T) {
	project, workspace := t.TempDir(), t.TempDir()
	roePath := filepath.Join(project, "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n203.0.113.10\n"), 0600); err != nil {
		t.Fatal(err)
	}
	roe, _, err := loadEngageRoE(engageOpts{roe: roePath}, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	metadata := engageRunMetadata{Goal: "fixture", Mode: "auto", ProjectDir: project, RoE: roePath,
		PolicyHash: roe.Policy.Hash, Started: time.Now().UTC().Format(time.RFC3339Nano), Status: "paused"}
	if err := writeEngageMetadata(workspace, metadata); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(workspace, "policy.json"), []byte(roe.Policy.Canonical)); err != nil {
		t.Fatal(err)
	}
	ws, err := engagement.OpenWorkspace(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ws.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "e1", Kind: "exploit", Phase: engagement.PhaseExploit,
		Surface: engagement.SurfaceNetwork, Target: "203.0.113.10", Armed: true, Status: engagement.StatusTodo}}}); err != nil {
		t.Fatal(err)
	}
	id, err := ws.Store.RecordEvidence("e1", "session opened")
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	entry := "10.7.0.7 transport=command surfaces=local,network,web,ad,container,cloud-aws,cloud-gcp exec=kubectl exec -i fixture --"
	args := []string{"--workspace", workspace, "--task", "e1", "--evidence", strconv.FormatInt(id, 10), "--entry", entry}
	if err := runEngageAttachFoothold(args); err == nil {
		t.Fatal("unapproved private foothold was attached")
	}
	if record, err := readAttachedFoothold(workspace); err != nil || record != nil {
		t.Fatalf("rejected foothold was stored: record=%+v err=%v", record, err)
	}
}

func TestAttachedFootholdRecordValidation(t *testing.T) {
	valid := attachedFoothold{
		Entry:      "10.7.0.7 transport=command surfaces=local,network,web,ad,container,cloud-aws,cloud-gcp exec=kubectl exec -i fixture --",
		TaskID:     "e1",
		EvidenceID: 1,
		At:         time.Now().UTC().Format(time.RFC3339),
	}
	sshRecord := valid
	sshRecord.Entry = "10.7.0.7 transport=ssh user=svc key=/tmp/key knownhosts=/tmp/known-hosts surfaces=local,network,web,ad,container,cloud-aws,cloud-gcp"
	if _, err := parseAttachedFoothold(&sshRecord); err != nil {
		t.Fatalf("pinned SSH attachment rejected: %v", err)
	}
	for name, change := range map[string]func(*attachedFoothold){
		"hostname":         func(r *attachedFoothold) { r.Entry = strings.Replace(r.Entry, "10.7.0.7", "host.internal", 1) },
		"missing surface":  func(r *attachedFoothold) { r.Entry = strings.Replace(r.Entry, ",cloud-gcp", "", 1) },
		"missing evidence": func(r *attachedFoothold) { r.EvidenceID = 0 },
		"oversize":         func(r *attachedFoothold) { r.Entry = strings.Repeat("x", 4097) },
		"unpinned SSH": func(r *attachedFoothold) {
			r.Entry = "10.7.0.7 user=svc key=/tmp/key surfaces=local,network,web,ad,container,cloud-aws,cloud-gcp"
		},
	} {
		t.Run(name, func(t *testing.T) {
			record := valid
			change(&record)
			if _, err := parseAttachedFoothold(&record); err == nil {
				t.Fatal("invalid attachment accepted")
			}
		})
	}
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, attachedFootholdPath(dir)); err != nil {
		t.Fatal(err)
	}
	if _, err := readAttachedFoothold(dir); err == nil {
		t.Fatal("attached foothold symlink was followed")
	}
}

func TestAttachFootholdRequiresRoECommandAction(t *testing.T) {
	project, workspace := t.TempDir(), t.TempDir()
	roePath := filepath.Join(project, "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n203.0.113.10\n\n## Allowed Actions\napi-read\n"), 0600); err != nil {
		t.Fatal(err)
	}
	roe, _, err := loadEngageRoE(engageOpts{roe: roePath}, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	metadata := engageRunMetadata{Goal: "fixture", Mode: "auto", ProjectDir: project, RoE: roePath,
		PolicyHash: roe.Policy.Hash, Started: time.Now().UTC().Format(time.RFC3339Nano), Status: "paused"}
	if err := writeEngageMetadata(workspace, metadata); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(workspace, "policy.json"), []byte(roe.Policy.Canonical)); err != nil {
		t.Fatal(err)
	}
	entry := "203.0.113.10 transport=command surfaces=local,network,web,ad,container,cloud-aws,cloud-gcp exec=kubectl exec -i fixture --"
	err = runEngageAttachFoothold([]string{"--workspace", workspace, "--task", "e1", "--evidence", "1", "--entry", entry})
	if err == nil || !strings.Contains(err.Error(), "command execution") {
		t.Fatalf("attachment bypassed RoE action policy: %v", err)
	}
}
