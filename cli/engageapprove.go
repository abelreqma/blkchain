package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

func approvedNetworkTaskID(cidr string) string {
	return "approved-network-" + reconTaskID(cidr)
}

func seedApprovedNetworkTasks(ctx context.Context, store *engagement.Store, networks []approvedNetwork, basisTaskID string) error {
	var tasks []engagement.Task
	for _, network := range networks {
		id := approvedNetworkTaskID(network.CIDR)
		existing, err := store.GetTask(id)
		if err == nil {
			if existing.Target != network.CIDR || existing.Surface != engagement.SurfaceNetwork {
				return fmt.Errorf("approved network task id collision for %s", network.CIDR)
			}
			continue
		}
		if !errors.Is(err, engagement.ErrNotFound) {
			return err
		}
		task := engagement.Task{
			ID: id, Kind: "recon", Target: network.CIDR,
			Objective: "enumerate the operator-approved private network through the foothold",
			DoneWhen:  "bounded service inventory or a documented access gap",
			Status:    engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
		}
		if basisTaskID != "" {
			task.BasisIDs = []string{basisTaskID}
		}
		tasks = append(tasks, task)
	}
	if len(tasks) == 0 {
		return nil
	}
	_, err := store.Apply(engagement.Delta{Kind: "approved-network", Detail: "operator-approved private networks", Upserts: tasks})
	return err
}

type approvedNetwork struct {
	CIDR string `json:"cidr"`
	At   string `json:"at"`
}

func approvedNetworksPath(dir string) string {
	return filepath.Join(dir, "approved-networks.json")
}

func readApprovedNetworks(dir string) ([]approvedNetwork, error) {
	f, err := os.OpenFile(approvedNetworksPath(dir), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<16 {
		return nil, fmt.Errorf("approved networks must be a regular file under 64 KiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<16+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<16 {
		return nil, fmt.Errorf("approved networks exceed 64 KiB")
	}
	var records []approvedNetwork
	if err := json.Unmarshal(data, &records); err != nil || len(records) > 64 {
		return nil, fmt.Errorf("invalid approved networks file")
	}
	seen := map[string]bool{}
	for _, record := range records {
		if _, err := secgate.PrivateNetwork(record.CIDR); err != nil || seen[record.CIDR] {
			return nil, fmt.Errorf("invalid approved network record")
		}
		if _, err := time.Parse(time.RFC3339, record.At); err != nil {
			return nil, fmt.Errorf("invalid approved network time")
		}
		seen[record.CIDR] = true
	}
	return records, nil
}

func runEngageApproveNetwork(args []string) error {
	fs := newFlagSet("engage approve-network")
	var dir string
	fs.StringVar(&dir, "workspace", "", "engagement workspace directory")
	if err := parseFlags(fs, reorder(args, map[string]bool{"workspace": true})); err != nil {
		return err
	}
	if dir == "" || len(fs.Args()) != 1 {
		return usageErr("engage approve-network requires --workspace DIR and one private CIDR")
	}
	cidr, err := secgate.PrivateNetwork(strings.TrimSpace(fs.Args()[0]))
	if err != nil {
		return err
	}
	var metadata engageRunMetadata
	if err := readEngageMetadata(filepath.Join(dir, "run.json"), &metadata); err != nil {
		return err
	}
	roe, _, err := loadEngageRoE(engageOpts{roe: metadata.RoE}, metadata.ProjectDir, nil)
	if err != nil {
		return err
	}
	if roe.Policy.Hash != metadata.PolicyHash {
		return fmt.Errorf("approved networks require the checkpoint's RoE policy")
	}
	if err := verifyEngagePolicy(filepath.Join(dir, "policy.json"), roe.Policy.Canonical); err != nil {
		return err
	}
	lease, err := acquireEngageLock(dir)
	if err != nil {
		return err
	}
	defer lease.Close()
	ws, err := engagement.OpenWorkspace(dir)
	if err != nil {
		return err
	}
	defer ws.Close()
	records, err := readApprovedNetworks(dir)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.CIDR == cidr {
			return nil
		}
	}
	if len(records) == 64 {
		return fmt.Errorf("approved network limit reached")
	}
	records = append(records, approvedNetwork{CIDR: cidr, At: time.Now().UTC().Format(time.RFC3339)})
	data, err := json.Marshal(records)
	if err != nil {
		return err
	}
	if err := atomicWrite(approvedNetworksPath(dir), data); err != nil {
		return err
	}
	if err := ws.AuditLine("operator", "approve-network", cidr); err != nil {
		return fmt.Errorf("network approval was saved but audit logging failed: %w", err)
	}
	return nil
}
