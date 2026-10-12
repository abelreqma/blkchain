package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

func TestResumeLoadsPivotNetworkAndCloudIdentityWithoutWideningBaseScope(t *testing.T) {
	previous := newEngageRunnerForRun
	newEngageRunnerForRun = func(context.Context, *RoE) (*engageRunner, error) {
		return &engageRunner{workers: map[string]string{}, foothold: &footholdTransport{name: "ssh"}}, nil
	}
	t.Cleanup(func() { newEngageRunnerForRun = previous })
	project, workspace := t.TempDir(), t.TempDir()
	roe := "## In Scope\n203.0.113.10\n\n## Foothold\n203.0.113.10 user=svc key=/unused surfaces=network,cloud-aws,cloud-gcp\n"
	if err := os.WriteFile(filepath.Join(project, "ROE.md"), []byte(roe), 0600); err != nil {
		t.Fatal(err)
	}
	var evidenceID, gcpEvidenceID int64
	first := engageRunInput{Opts: engageOpts{workspace: workspace}, Cwd: project, Goal: "fixture", Run: func(_ context.Context, d engageDeps, _ string) (string, error) {
		if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{
			{ID: "cloud-1", Kind: "cloud", Surface: engagement.SurfaceCloudAWS, Status: engagement.StatusTodo},
			{ID: "cloud-2", Kind: "cloud", Surface: engagement.SurfaceCloudGCP, Status: engagement.StatusTodo},
		}}); err != nil {
			return "", err
		}
		var err error
		evidenceID, err = d.Store.RecordEvidence("cloud-1", "credential file observed")
		if err != nil {
			return "", err
		}
		gcpEvidenceID, err = d.Store.RecordEvidence("cloud-2", "GCP credential file observed")
		if err != nil {
			return "", err
		}
		return "", errors.New("pause fixture")
	}}
	if _, err := runEngageSession(context.Background(), first); err == nil {
		t.Fatal("fixture did not stop")
	}
	if evidenceID == 0 || gcpEvidenceID == 0 {
		t.Fatal("credential evidence was not recorded")
	}
	if err := runEngageApproveNetwork([]string{"--workspace", workspace, "10.7.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := runEngageApproveCloudIdentity([]string{"--workspace", workspace, "--provider", "aws", "--file", "/srv/keys/aws", "--task", "cloud-1", "--evidence", strconv.FormatInt(evidenceID, 10)}); err != nil {
		t.Fatal(err)
	}
	if err := runEngageApproveCloudIdentity([]string{"--workspace", workspace, "--provider", "gcp", "--file", "/srv/keys/gcp.json", "--task", "cloud-2", "--evidence", strconv.FormatInt(gcpEvidenceID, 10)}); err != nil {
		t.Fatal(err)
	}
	second := engageRunInput{Opts: engageOpts{resume: workspace}, Run: func(_ context.Context, d engageDeps, _ string) (string, error) {
		cloudTask, err := d.Store.GetTask("approved-cloud-aws-" + strconv.FormatInt(evidenceID, 10))
		if err != nil || cloudTask.Surface != engagement.SurfaceCloudAWS || len(cloudTask.BasisIDs) != 1 || cloudTask.BasisIDs[0] != "cloud-1" {
			t.Fatalf("approved cloud task was not seeded from evidence: task=%+v err=%v", cloudTask, err)
		}
		gcpTask, err := d.Store.GetTask("approved-cloud-gcp-" + strconv.FormatInt(gcpEvidenceID, 10))
		if err != nil || gcpTask.Surface != engagement.SurfaceCloudGCP || len(gcpTask.BasisIDs) != 1 || gcpTask.BasisIDs[0] != "cloud-2" {
			t.Fatalf("approved GCP task was not seeded from evidence: task=%+v err=%v", gcpTask, err)
		}
		if d.Gate.Scope.InScope("10.7.0.7") || d.Gate.PivotScope == nil || !d.Gate.PivotScope.InScope("10.7.0.7") {
			t.Fatal("resumed approval widened the worker or missed the foothold")
		}
		identity, ok := d.Gate.CloudIdentities[secgate.SurfaceCloudAWS]
		if !ok || identity.CredentialFile != "/srv/keys/aws" {
			t.Fatalf("resumed identity = %+v", identity)
		}
		gcpIdentity, ok := d.Gate.CloudIdentities[secgate.SurfaceCloudGCP]
		if !ok || gcpIdentity.CredentialFile != "/srv/keys/gcp.json" {
			t.Fatalf("resumed GCP identity = %+v", gcpIdentity)
		}
		return "done", nil
	}}
	if _, err := runEngageSession(context.Background(), second); err != nil {
		t.Fatal(err)
	}
}
