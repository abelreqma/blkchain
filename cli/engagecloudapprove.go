package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

func approvedCloudIdentitiesPath(dir string) string {
	return filepath.Join(dir, "approved-cloud-identities.json")
}

func cloudApprovalSurface(provider string) (secgate.Surface, bool) {
	switch provider {
	case "aws":
		return secgate.SurfaceCloudAWS, true
	case "gcp":
		return secgate.SurfaceCloudGCP, true
	}
	return "", false
}

func validRemoteCredentialFile(path string) bool {
	if len(path) == 0 || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for _, ch := range path {
		if ch < 0x20 || ch == 0x7f {
			return false
		}
	}
	return true
}

func readApprovedCloudIdentities(dir string) ([]secgate.CloudIdentity, error) {
	f, err := os.OpenFile(approvedCloudIdentitiesPath(dir), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<16 {
		return nil, fmt.Errorf("approved cloud identities must be a regular file under 64 KiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<16+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<16 {
		return nil, fmt.Errorf("approved cloud identities exceed 64 KiB")
	}
	var records []secgate.CloudIdentity
	if err := json.Unmarshal(data, &records); err != nil || len(records) > 2 {
		return nil, fmt.Errorf("invalid approved cloud identities file")
	}
	seen := map[string]bool{}
	for _, record := range records {
		if _, ok := cloudApprovalSurface(record.Provider); !ok || seen[record.Provider] ||
			!validRemoteCredentialFile(record.CredentialFile) || record.TaskID == "" || record.EvidenceID <= 0 {
			return nil, fmt.Errorf("invalid approved cloud identity record")
		}
		if _, err := time.Parse(time.RFC3339, record.At); err != nil {
			return nil, fmt.Errorf("invalid approved cloud identity time")
		}
		seen[record.Provider] = true
	}
	return records, nil
}

func cloudApprovalHasEvidence(store *engagement.Store, identity secgate.CloudIdentity) (bool, error) {
	return store.HasEvidenceRow(identity.TaskID, identity.EvidenceID)
}

func seedApprovedCloudTasks(ctx context.Context, store *engagement.Store, identities map[secgate.Surface]secgate.CloudIdentity) error {
	var tasks []engagement.Task
	for _, surface := range []secgate.Surface{secgate.SurfaceCloudAWS, secgate.SurfaceCloudGCP} {
		identity, ok := identities[surface]
		if !ok {
			continue
		}
		id := fmt.Sprintf("approved-cloud-%s-%d", identity.Provider, identity.EvidenceID)
		if _, err := store.GetTask(id); err == nil {
			continue
		} else if !errors.Is(err, engagement.ErrNotFound) {
			return err
		}
		tasks = append(tasks, engagement.Task{
			ID: id, Kind: "cloud", Target: identity.Provider,
			Objective: "enumerate cloud identity and resources with the operator-approved " + identity.Provider + " credential file on the declared foothold",
			Status:    engagement.StatusTodo, Phase: engagement.PhaseRecon,
			Surface: engagement.Surface(surface), BasisIDs: []string{identity.TaskID},
		})
	}
	if len(tasks) == 0 {
		return nil
	}
	_, err := store.Apply(engagement.Delta{Kind: "cloud-identity", Detail: "operator-approved credential sources", Upserts: tasks})
	return err
}

func runEngageApproveCloudIdentity(args []string) error {
	fs := newFlagSet("engage approve-cloud-identity")
	var dir, provider, file, task, evidence string
	fs.StringVar(&dir, "workspace", "", "engagement workspace directory")
	fs.StringVar(&provider, "provider", "", "aws or gcp")
	fs.StringVar(&file, "file", "", "absolute credential file path on the foothold")
	fs.StringVar(&task, "task", "", "task that recorded credential evidence")
	fs.StringVar(&evidence, "evidence", "", "credential evidence row id")
	if err := parseFlags(fs, reorder(args, map[string]bool{"workspace": true, "provider": true, "file": true, "task": true, "evidence": true})); err != nil {
		return err
	}
	surface, known := cloudApprovalSurface(provider)
	id, parseErr := strconv.ParseInt(evidence, 10, 64)
	if len(fs.Args()) != 0 || dir == "" || !known || !validRemoteCredentialFile(file) || strings.TrimSpace(task) == "" || parseErr != nil || id <= 0 {
		return usageErr("engage approve-cloud-identity requires --workspace DIR --provider aws|gcp --file REMOTE_PATH --task ID --evidence ID")
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
		return fmt.Errorf("cloud identity requires the checkpoint's RoE policy")
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
	foothold, err := workspaceFoothold(roe, dir, ws.Store)
	if err != nil {
		return err
	}
	if !foothold.Covers(surface) {
		return fmt.Errorf("cloud identity requires an approved foothold to cover %s", surface)
	}
	identity := secgate.CloudIdentity{Provider: provider, CredentialFile: file, TaskID: task, EvidenceID: id, At: time.Now().UTC().Format(time.RFC3339)}
	found, err := cloudApprovalHasEvidence(ws.Store, identity)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("credential evidence %d is not recorded for task %s", id, task)
	}
	records, err := readApprovedCloudIdentities(dir)
	if err != nil {
		return err
	}
	replaced := false
	for i := range records {
		if records[i].Provider == provider {
			records[i] = identity
			replaced = true
			break
		}
	}
	if !replaced {
		records = append(records, identity)
	}
	data, err := json.Marshal(records)
	if err != nil {
		return err
	}
	if err := atomicWrite(approvedCloudIdentitiesPath(dir), data); err != nil {
		return err
	}
	if err := ws.AuditLine("operator", "approve-cloud-identity", fmt.Sprintf("%s task=%s evidence=%d", provider, task, id)); err != nil {
		return fmt.Errorf("cloud identity approval was saved but audit logging failed: %w", err)
	}
	return nil
}
