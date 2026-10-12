package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestApproveNetworkPersistsWithoutChangingRoE(t *testing.T) {
	project := t.TempDir()
	workspace := t.TempDir()
	roePath := filepath.Join(project, "ROE.md")
	source := "## In Scope\n203.0.113.10\n\n## Foothold\n203.0.113.10 user=svc key=/unused surfaces=network\n"
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
	args := []string{"--workspace", workspace, "10.7.0.0/24"}
	if err := runEngageApproveNetwork(args); err != nil {
		t.Fatal(err)
	}
	if err := runEngageApproveNetwork(args); err != nil {
		t.Fatal(err)
	}
	records, err := readApprovedNetworks(workspace)
	if err != nil || len(records) != 1 || records[0].CIDR != "10.7.0.0/24" {
		t.Fatalf("approved networks = %+v, err=%v", records, err)
	}
	if roe.Scope.InScope("10.7.0.7") {
		t.Fatal("the sealed RoE scope was widened")
	}
	if err := runEngageApproveNetwork([]string{"--workspace", workspace, "8.8.8.0/24"}); err == nil {
		t.Fatal("public network approval succeeded")
	}
}

func TestReadApprovedNetworksRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "networks.json")
	if err := os.WriteFile(target, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, approvedNetworksPath(dir)); err != nil {
		t.Fatal(err)
	}
	if _, err := readApprovedNetworks(dir); err == nil {
		t.Fatal("approved networks followed a symlink")
	}
}
