package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
)

func TestApproveCloudIdentityRequiresRecordedEvidence(t *testing.T) {
	project := t.TempDir()
	workspace := t.TempDir()
	roePath := filepath.Join(project, "ROE.md")
	source := "## In Scope\n203.0.113.10\n\n## Foothold\n203.0.113.10 user=svc key=/unused surfaces=cloud-aws,cloud-gcp\n"
	if err := os.WriteFile(roePath, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	roe, _, err := loadEngageRoE(engageOpts{roe: roePath}, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	metadata := engageRunMetadata{
		Goal: "fixture", Mode: "auto", ProjectDir: project, RoE: roePath,
		PolicyHash: roe.Policy.Hash, Started: time.Now().UTC().Format(time.RFC3339Nano), Status: "paused",
	}
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
	if _, err := ws.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "cloud-1", Kind: "cloud", Surface: engagement.SurfaceCloudAWS, Status: engagement.StatusTodo}}}); err != nil {
		t.Fatal(err)
	}
	id, err := ws.Store.RecordEvidence("cloud-1", "credential file observed on declared foothold")
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	args := []string{"--workspace", workspace, "--provider", "aws", "--file", "/srv/keys/aws", "--task", "cloud-1", "--evidence", strconv.FormatInt(id, 10)}
	if err := runEngageApproveCloudIdentity(args); err != nil {
		t.Fatal(err)
	}
	records, err := readApprovedCloudIdentities(workspace)
	if err != nil || len(records) != 1 || records[0].Provider != "aws" || records[0].EvidenceID != id {
		t.Fatalf("identities = %+v, err=%v", records, err)
	}
	bad := append([]string(nil), args...)
	bad[len(bad)-1] = strconv.FormatInt(id+1, 10)
	if err := runEngageApproveCloudIdentity(bad); err == nil {
		t.Fatal("unrecorded evidence was approved")
	}
	ws, err = engagement.OpenWorkspace(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	found, err := cloudApprovalHasEvidence(ws.Store, records[0])
	if err != nil || !found {
		t.Fatalf("approved evidence was not found: found=%t err=%v", found, err)
	}
}
