package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

type attachedFoothold struct {
	Entry      string `json:"entry"`
	TaskID     string `json:"task_id"`
	EvidenceID int64  `json:"evidence_id"`
	At         string `json:"at"`
}

func probeAttachedFoothold(ctx context.Context, gate *secgate.Gate, dir string) error {
	if err := gate.ClaimPolicyAction("command"); err != nil {
		return err
	}
	result := runIsolatedAction(ctx, gate, []pipelineStage{{Binary: "true"}}, dir, 512, 10*time.Second,
		actionOrigin{Surface: secgate.SurfaceLocal, SkipVulnIngest: true})
	if result.Err != nil || result.TimedOut || result.ExitCode != 0 {
		return fmt.Errorf("attached foothold carrier probe failed")
	}
	return nil
}

func attachedFootholdPath(dir string) string {
	return filepath.Join(dir, "attached-foothold.json")
}

func parseAttachedFoothold(record *attachedFoothold) (*secgate.Foothold, error) {
	if record == nil || len(record.Entry) == 0 || len(record.Entry) > 4096 ||
		strings.TrimSpace(record.TaskID) == "" || record.EvidenceID <= 0 {
		return nil, fmt.Errorf("invalid attached foothold record")
	}
	if _, err := time.Parse(time.RFC3339, record.At); err != nil {
		return nil, fmt.Errorf("invalid attached foothold time")
	}
	f, err := secgate.ParseFoothold(record.Entry)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(f.Host) == nil {
		return nil, fmt.Errorf("attached foothold host must be an IP address")
	}
	if f.Transport == "ssh" && f.KnownHosts == "" {
		return nil, fmt.Errorf("attached SSH foothold requires knownhosts=")
	}
	for _, name := range secgate.FootholdSurfaces() {
		if (f.Transport == "raw-session" || f.Transport == "msf-rpc" || f.Transport == "http-form") && name == string(secgate.SurfaceWeb) {
			continue
		}
		if !f.Covers(secgate.Surface(name)) {
			return nil, fmt.Errorf("attached foothold must cover %s", name)
		}
	}
	return f, nil
}

func readAttachedFoothold(dir string) (*attachedFoothold, error) {
	f, err := os.OpenFile(attachedFootholdPath(dir), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<14 {
		return nil, fmt.Errorf("attached foothold must be a regular file under 16 KiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<14+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<14 {
		return nil, fmt.Errorf("attached foothold exceeds 16 KiB")
	}
	var record attachedFoothold
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("invalid attached foothold file: %w", err)
	}
	if _, err := parseAttachedFoothold(&record); err != nil {
		return nil, err
	}
	return &record, nil
}

func attachedFootholdScope(roe *RoE, dir string) (*secgate.Scope, error) {
	approved, err := readApprovedNetworks(dir)
	if err != nil {
		return nil, err
	}
	if len(approved) == 0 {
		return roe.Scope, nil
	}
	networks := make([]string, 0, len(approved))
	for _, record := range approved {
		networks = append(networks, record.CIDR)
	}
	return roe.Scope.WithApprovedPrivateNetworks(networks)
}

func workspaceFoothold(roe *RoE, dir string, store *engagement.Store) (*secgate.Foothold, error) {
	record, err := readAttachedFoothold(dir)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return roe.Policy.Foothold, nil
	}
	if roe.Policy.Foothold != nil {
		return nil, fmt.Errorf("attached foothold conflicts with declared foothold")
	}
	scope, err := attachedFootholdScope(roe, dir)
	if err != nil {
		return nil, err
	}
	f, _, err := validateAttachedFoothold(store, scope, record, dir, roe.Policy.Hash)
	return f, err
}

func validateAttachedFoothold(store *engagement.Store, scope *secgate.Scope, record *attachedFoothold, dir, policyHash string) (*secgate.Foothold, engagement.Task, error) {
	f, err := parseAttachedFoothold(record)
	if err != nil {
		return nil, engagement.Task{}, err
	}
	if err := secgate.FootholdInScope(scope, f); err != nil {
		return nil, engagement.Task{}, err
	}
	if f.Transport == "raw-session" {
		if f.Session != rawSessionRecordPath(dir) {
			return nil, engagement.Task{}, errors.New("raw session record must belong to this workspace")
		}
		raw, rawErr := readRawSessionRecord(dir)
		if rawErr != nil || raw == nil || raw.PolicyHash != policyHash {
			return nil, engagement.Task{}, errors.New("raw session does not match the engagement policy")
		}
		expires, _ := time.Parse(time.RFC3339Nano, raw.ExpiresAt)
		if !time.Now().Before(expires) {
			return nil, engagement.Task{}, errors.New("raw session expired")
		}
		checkCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		connected, checkErr := rawBrokerStatus(checkCtx, raw.ControlAddress, raw.Token)
		if checkErr != nil || !connected {
			return nil, engagement.Task{}, errors.New("raw session is not connected")
		}
	}
	if f.Transport == "msf-rpc" {
		carrier, buildErr := buildFootholdMSFRPC(f)
		if buildErr != nil {
			return nil, engagement.Task{}, buildErr
		}
		checkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := carrier.msf.active(checkCtx); err != nil {
			return nil, engagement.Task{}, err
		}
	}
	task, err := store.GetTask(record.TaskID)
	if err != nil {
		return nil, engagement.Task{}, err
	}
	if task.Phase != engagement.PhaseExploit || !task.Armed {
		return nil, engagement.Task{}, fmt.Errorf("attached foothold requires evidence from an armed exploit task")
	}
	found, err := store.HasEvidenceRow(record.TaskID, record.EvidenceID)
	if err != nil {
		return nil, engagement.Task{}, err
	}
	if !found {
		return nil, engagement.Task{}, fmt.Errorf("foothold evidence %d is not recorded for task %s", record.EvidenceID, record.TaskID)
	}
	return f, task, nil
}

func runEngageAttachFoothold(args []string) error {
	fs := newFlagSet("engage attach-foothold")
	var dir, task, evidence, entry string
	fs.StringVar(&dir, "workspace", "", "engagement workspace directory")
	fs.StringVar(&task, "task", "", "armed exploit task that recorded access")
	fs.StringVar(&evidence, "evidence", "", "access evidence row id")
	fs.StringVar(&entry, "entry", "", "foothold transport entry")
	if err := parseFlags(fs, reorder(args, map[string]bool{"workspace": true, "task": true, "evidence": true, "entry": true})); err != nil {
		return err
	}
	id, parseErr := strconv.ParseInt(evidence, 10, 64)
	if len(fs.Args()) != 0 || dir == "" || strings.TrimSpace(task) == "" || parseErr != nil || id <= 0 || entry == "" {
		return usageErr("engage attach-foothold requires --workspace DIR --task ID --evidence ID --entry 'HOST transport=command ...'")
	}
	var metadata engageRunMetadata
	if err := readEngageMetadata(filepath.Join(dir, "run.json"), &metadata); err != nil {
		return err
	}
	roe, _, err := loadEngageRoE(engageOpts{roe: metadata.RoE}, metadata.ProjectDir, nil)
	if err != nil {
		return err
	}
	if roe.Policy.Hash != metadata.PolicyHash || roe.Policy.Foothold != nil {
		return fmt.Errorf("attachment requires the checkpoint's RoE without a declared foothold")
	}
	if !roe.Policy.Allows("command") {
		return fmt.Errorf("foothold attachment requires command execution in the RoE")
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
	if existing, err := readAttachedFoothold(dir); err != nil {
		return err
	} else if existing != nil {
		return fmt.Errorf("workspace already has an attached foothold")
	}
	scope, err := attachedFootholdScope(roe, dir)
	if err != nil {
		return err
	}
	record := &attachedFoothold{Entry: entry, TaskID: task, EvidenceID: id, At: time.Now().UTC().Format(time.RFC3339)}
	f, _, err := validateAttachedFoothold(ws.Store, scope, record, dir, roe.Policy.Hash)
	if err != nil {
		return err
	}
	transport, err := newFootholdTransport(f)
	if err != nil {
		return err
	}
	allowBins := append(externalEngageAllowlist(), roe.Scope.AllowedBins()...)
	if err := authorizeFootholdCarrier(&secgate.Gate{Allow: secgate.NewAllowlist(allowBins...)}, transport); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := atomicWrite(attachedFootholdPath(dir), data); err != nil {
		return err
	}
	if err := ws.AuditLine("operator", "attach-foothold", f.Host+" "+f.Transport+" task="+task); err != nil {
		return fmt.Errorf("foothold attachment was saved but audit logging failed: %w", err)
	}
	return nil
}
