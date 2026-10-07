package main

import (
	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/skillcat"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

func loadEngageRoE(o engageOpts, cwd string, db *sql.DB) (*RoE, string, error) {
	if o.scope != "" || o.autoOverride {
		return nil, "", usageErr("engage: use one ROE.md with in-scope targets; --scope and scope overrides are retired")
	}
	if _, err := os.Stat(filepath.Join(cwd, ".blkchain", "config.yaml")); err == nil {
		return nil, "", errors.New("engage: migrate .blkchain/config.yaml into ROE.md with blk engage migrate --write before starting")
	} else if !os.IsNotExist(err) {
		return nil, "", err
	}
	path := o.roe
	if path == "" {
		path = filepath.Join(cwd, "ROE.md")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if recalled, ok := recallRoE(db, cwd); ok {
				path = recalled
			}
		}
	}
	f, err := os.Open(path)
	if err != nil {
		// No policy to run under. roeTemplate exists precisely for this moment and
		// had no caller, so an operator was told to create the file and left to write
		// a scope policy from scratch. Write the commented template instead, which is
		// idempotent and never clobbers an existing ROE.md, and still refuse to run:
		// the template parses to an empty scope, so it authorizes nothing until it is
		// filled in. A write failure is not fatal to the message the operator needs.
		if o.roe == "" {
			if written, werr := writeRoETemplate(cwd); werr == nil && written {
				return nil, "", usageErr("engage: scope requires ROE.md, so a commented template was written to %s; fill in Targets and In Scope, then run engage again",
					filepath.Join(cwd, "ROE.md"))
			}
		}
		return nil, "", usageErr("engage: scope requires ROE.md; supply --roe PATH or create the file in this directory")
	}
	defer f.Close()
	roe, err := ParseRoE(f)
	if err != nil {
		return nil, "", err
	}
	if roe.Scope.Empty() && !roe.Scope.Local() {
		return nil, "", usageErr("engage: ROE.md needs in-scope targets or an isolated local runner")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	return roe, abs, nil
}

func parseEngageArgs(args []string) (engageOpts, string, error) {
	var o engageOpts
	fs := newFlagSet("engage")
	defineEngageFlags(fs, &o)
	values := map[string]bool{"scope": true, "workspace": true, "model": true, "roe": true, "transcript": true, "resume": true}
	if err := parseFlags(fs, reorder(args, values)); err != nil {
		return o, "", err
	}
	if o.safe && o.auto {
		return o, "", usageErr("engage: cannot combine --safe and --auto")
	}
	if !validTranscriptMode(o.transcript) {
		return o, "", usageErr("engage: transcript must be off, important, or full")
	}
	goal := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if goal == "" && o.resume == "" {
		return o, "", missingArg("engage", "missing goal", `engage --roe ROE.md "assess the lab"`)
	}
	return o, goal, nil
}

type engageRunInput struct {
	Opts      engageOpts
	Cwd, Goal string
	Model     toolLoopModel
	RC        searcher
	Cfg       ragconfig.Config
	Prefs     modelPrefs
	Catalog   *skillcat.Catalog
	Confirm   secgate.Confirmer
	Asker     askuser.Asker
	DB        *sql.DB
	Progress  func(int64, engagement.Engagement)
	Output    io.Writer
	OnAction  func(actionRecord)
	Run       func(context.Context, engageDeps, string) (string, error)
	Views     bool
}

type engageRunMetadata struct {
	CommandAttempts int    `json:"command_attempts"`
	ByteUsage       int64  `json:"byte_usage"`
	Goal            string `json:"goal"`
	Mode            string `json:"mode"`
	ProjectDir      string `json:"project_dir"`
	RoE             string `json:"roe"`
	PolicyHash      string `json:"policy_hash"`
	Started         string `json:"started"`
	Status          string `json:"status"`
}

var newEngageRunnerForRun = newEngageRunner

func runEngageSession(ctx context.Context, input engageRunInput) (final string, retErr error) {
	if input.Cwd == "" {
		input.Cwd, _ = os.Getwd()
	}
	o := input.Opts
	var metadata engageRunMetadata
	if o.resume != "" {
		if o.workspace != "" && o.workspace != o.resume {
			return "", usageErr("engage: --resume and --workspace must select the same workspace")
		}
		o.workspace = o.resume
		if err := readEngageMetadata(filepath.Join(o.resume, "run.json"), &metadata); err != nil {
			return "", err
		}
		input.Cwd = metadata.ProjectDir
		if o.roe == "" {
			o.roe = metadata.RoE
		}
		if input.Goal == "" {
			input.Goal = metadata.Goal
		} else if input.Goal != metadata.Goal {
			return "", errors.New("engage: resumed goal differs from the checkpoint")
		}
		o.safe = metadata.Mode == "safe"
	}
	mode := secgate.Auto
	if o.safe {
		mode = secgate.Safe
	}
	if mode == secgate.Safe && input.Confirm == nil {
		return "", errors.New("engage: --safe requires an interactive approval channel")
	}
	roe, roePath, err := loadEngageRoE(o, input.Cwd, input.DB)
	if err != nil {
		return "", err
	}
	if metadata.PolicyHash != "" && metadata.PolicyHash != roe.Policy.Hash {
		return "", errors.New("engage: resumed ROE policy differs from the checkpoint; start a new engagement")
	}
	if o.transcript == "" {
		o.transcript = "important"
	}
	if !validTranscriptMode(o.transcript) {
		return "", usageErr("engage: invalid transcript mode")
	}
	started := time.Now()
	if metadata.Started != "" {
		started, err = time.Parse(time.RFC3339Nano, metadata.Started)
		if err != nil {
			return "", errors.New("engage: invalid checkpoint start time")
		}
	}
	deadline := started.Add(time.Duration(roe.Policy.WallSeconds) * time.Second)
	if !time.Now().Before(deadline) {
		return "", errors.New("engage: checkpoint engagement budget expired")
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	wsDir, err := engageWorkspaceDir(o.workspace)
	if err != nil {
		return "", err
	}
	if o.resume == "" {
		if entries, statErr := os.ReadDir(wsDir); statErr == nil && len(entries) > 0 {
			if len(entries) != 1 || entries[0].Name() != "ROE.md" || o.roe != filepath.Join(wsDir, "ROE.md") {
				return "", errors.New("engage: workspace is not empty; use --resume or a new workspace")
			}
		} else if statErr != nil && !os.IsNotExist(statErr) {
			return "", statErr
		}
	} else if err := verifyEngagePolicy(filepath.Join(wsDir, "policy.json"), roe.Policy.Canonical); err != nil {
		return "", err
	}
	scratch, err := os.MkdirTemp("", "blkengage-")
	if err != nil {
		return "", err
	}
	defer func() {
		if err := os.RemoveAll(scratch); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("engage: scratch cleanup failed: %w", err))
		}
	}()
	runner, err := newEngageRunnerForRun(ctx, roe)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := runner.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("engage: isolated runner cleanup failed: %w", err))
		}
	}()
	ws, err := engagement.OpenWorkspace(wsDir)
	if err != nil {
		return "", err
	}
	defer ws.Close()
	lease, err := acquireEngageLock(ws.Dir)
	if err != nil {
		return "", err
	}
	defer lease.Close()
	trace := newActionTranscript(ws.Dir, o.transcript, roe.Policy.RunnerID, roe.Policy.MaxActions, roe.Policy.TotalBytes, input.Output)
	trace.onStore = func(data []byte) error { return ws.Store.RecordActionDocument(context.Background(), data) }
	trace.otherRunner = "web-broker"
	trace.onEvent = input.OnAction
	if o.resume != "" {
		if err = trace.restore(); err != nil {
			return "", err
		}
		if metadata.CommandAttempts < trace.actions || metadata.ByteUsage < int64(trace.used) {
			return "", errors.New("engage: checkpoint usage is less than recorded actions")
		}
	} else {
		file, err := os.OpenFile(trace.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return "", err
		}
		if err := file.Close(); err != nil {
			return "", err
		}
	}
	runtime := &engageRuntime{runner: runner, trace: trace, policy: roe.Policy, cancel: cancel}
	ctx = context.WithValue(ctx, engageRuntimeKey{}, runtime)
	var failureMu sync.Mutex
	var writeFailure error
	auditEvents := make(chan actionRecord, 128)
	recordWriteFailure := func(kind string, writeErr error) {
		failureMu.Lock()
		writeFailure = errors.Join(writeFailure, fmt.Errorf("engage: %s write failed: %w", kind, writeErr))
		failureMu.Unlock()
		cancel()
	}
	gate := buildEngageGate(ws, roe.Scope, mode, input.Confirm, secgate.NewSessionApprovals(), scratch, gatePolicy{RoE: roe}, func(action, detail string) {
		if err := ws.AuditLine("secgate", action, redactEngageText(detail)); err != nil {
			recordWriteFailure("audit", err)
		}
		status := "allowed"
		if strings.HasPrefix(action, "deny") {
			status = "denied"
		}
		select {
		case auditEvents <- actionRecord{Kind: "policy", Command: detail, Status: status, Reason: action}:
		default:
			recordWriteFailure("audit queue", errors.New("action transcript queue is full"))
		}
	})
	// The carrier is a binary that runs inside the worker, so it clears the same
	// reachability allowlist as any other command. Without this check an RoE
	// could nominate any binary in the image as its carrier.
	if err = authorizeFootholdCarrier(gate, runner.foothold); err != nil {
		return "", err
	}
	if err = gate.Start(); err != nil {
		return "", err
	}
	if err = gate.RestorePolicyUsage(metadata.CommandAttempts, deadline, metadata.ByteUsage); err != nil {
		return "", err
	}
	rw := newReportWriter(ws.Store, ws.Dir, input.Goal, roePath, mode.String())
	if o.resume != "" {
		if err = rw.RestoreFinal(); err != nil {
			return "", fmt.Errorf("engage: prior report: %w", err)
		}
	}
	if o.resume != "" {
		if err = os.Remove(filepath.Join(ws.Dir, "STOP")); err != nil && !os.IsNotExist(err) {
			return "", err
		}
	} else if err = atomicWrite(filepath.Join(ws.Dir, "policy.json"), []byte(roe.Policy.Canonical)); err != nil {
		return "", err
	}
	metadata.Goal = input.Goal
	metadata.Mode = mode.String()
	metadata.ProjectDir = input.Cwd
	metadata.RoE = roePath
	metadata.PolicyHash = roe.Policy.Hash
	metadata.Started = started.UTC().Format(time.RFC3339Nano)
	metadata.Status = "in-progress"
	if err = writeEngageMetadata(ws.Dir, metadata); err != nil {
		return "", err
	}
	_ = rememberRoE(input.DB, input.Cwd, roePath)
	var checkpointMu sync.Mutex
	trace.onPersist = func() error {
		checkpointMu.Lock()
		defer checkpointMu.Unlock()
		metadata.CommandAttempts = gate.PolicyUsage()
		metadata.ByteUsage = gate.PolicyByteUsage()
		if err := writeEngageMetadata(ws.Dir, metadata); err != nil {
			recordWriteFailure("checkpoint", err)
			return err
		}
		return nil
	}
	auditDone := make(chan struct{})
	go func() {
		defer close(auditDone)
		for event := range auditEvents {
			if err := trace.record(event); err != nil {
				recordWriteFailure("action transcript", err)
			}
		}
	}()
	var auditOnce sync.Once
	finishAudit := func() {
		auditOnce.Do(func() { close(auditEvents) })
		<-auditDone
	}
	defer finishAudit()
	stopWatcher := watchEngageStop(ctx, ws.Dir, cancel)
	defer stopWatcher()
	if input.Model == nil && input.Run == nil {
		input.Model, err = newOMLX(input.Cfg, o.model)
		if err != nil {
			return "", err
		}
	}
	if input.RC == nil && input.Run == nil {
		rc, e := newRetrievalClient(input.Cfg)
		if e != nil {
			return "", e
		}
		input.RC = rc
		defer rc.Close()
	}
	if input.Catalog == nil && input.Run == nil {
		input.Catalog, err = loadEngageCatalog()
		if err != nil {
			return "", err
		}
	}
	if mode == secgate.Auto {
		input.Asker = askuser.AutoAsker{}
		input.Confirm = nil
	} else if input.Asker == nil {
		input.Asker = askuser.AutoAsker{}
	}
	deps := buildEngageDeps(input.Model, input.RC, input.Cfg, input.Prefs, ws.Store, gate, scratch, input.Catalog, input.Asker, input.Confirm, input.Progress)
	toolHelp, closeHelp := openToolHelpCache()
	defer closeHelp()
	deps.ToolHelp = toolHelp
	if input.Views {
		SetEngageEvidenceSource(ws.Store.EvidenceRowsFor)
		defer SetEngageEvidenceSource(nil)
		SetEngageGraphSource(func(q engagement.GraphQuery) (kgView, error) { return engageGraphOnStore(ws.Store, q) })
		defer SetEngageGraphSource(nil)
	}
	if o.resume == "" {
		if err = seedInitialVantage(ctx, ws.Store, roe.Scope, roe.Policy.Foothold); err != nil {
			return "", err
		}
	} else if err = reopenInterruptedTasks(ctx, ws.Store); err != nil {
		return "", err
	}
	if err = rw.Flush("in-progress"); err != nil {
		return "", err
	}
	stopReport := rw.Start()
	defer stopReport()
	if input.Output != nil {
		fmt.Fprintf(input.Output, "mode=%s transcript=%s ROE=%s policy=%s workspace=%s\n", mode, o.transcript, roePath, roe.Policy.Hash, ws.Dir)
	}
	run := input.Run
	if run == nil {
		run = runOrchestrator
	}
	final, runErr := run(ctx, deps, effectiveEngagePrompt(gate, input.Goal))
	finishAudit()
	if err := ctx.Err(); err != nil {
		runErr = errors.Join(runErr, err)
	}
	failureMu.Lock()
	runErr = errors.Join(runErr, writeFailure)
	failureMu.Unlock()
	stopReport()
	status := "complete"
	if runErr != nil {
		status = "interrupted"
		if _, stopErr := os.Stat(filepath.Join(ws.Dir, "STOP")); stopErr == nil {
			status = "stopped"
		}
	} else if strings.HasPrefix(final, "Engagement paused:") {
		status = "paused"
	} else if strings.HasPrefix(final, "Stopped:") {
		status = "stopped"
	}
	checkpointMu.Lock()
	metadata.Status = status
	metadata.CommandAttempts = gate.PolicyUsage()
	metadata.ByteUsage = gate.PolicyByteUsage()
	if runErr == nil {
		rw.SetFinal(final)
	}
	reportErr := rw.Flush(status)
	if reportErr != nil {
		runErr = errors.Join(runErr, fmt.Errorf("engage: final report write failed: %w", reportErr))
	}
	if err = writeEngageMetadata(ws.Dir, metadata); err != nil {
		runErr = errors.Join(runErr, fmt.Errorf("engage: checkpoint write failed: %w", err))
	}
	checkpointMu.Unlock()
	_ = ingestEngageRun(ws.Dir)
	md, js := reportPaths(ws.Dir)
	if reportErr == nil {
		final += "\n\nReport: " + md + "\n        " + js + "\nTranscript: " + trace.path
	}
	return final, runErr
}

func readEngageMetadata(path string, metadata *engageRunMetadata) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return errors.New("engage: checkpoint metadata must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return err
	}
	if len(data) > 65536 {
		return errors.New("engage: checkpoint metadata exceeds limit")
	}
	if err := uniqueJSONFields(data); err != nil {
		return fmt.Errorf("engage: invalid checkpoint metadata: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(metadata); err != nil {
		return fmt.Errorf("engage: invalid checkpoint metadata: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("engage: checkpoint metadata has trailing content")
	}
	if strings.TrimSpace(metadata.Goal) == "" || metadata.RoE == "" || metadata.ProjectDir == "" || metadata.Mode != "auto" && metadata.Mode != "safe" || metadata.CommandAttempts < 0 || metadata.ByteUsage < 0 || metadata.Status != "in-progress" && metadata.Status != "complete" && metadata.Status != "paused" && metadata.Status != "stopped" && metadata.Status != "interrupted" {
		return errors.New("engage: checkpoint metadata is incomplete or invalid")
	}
	if !filepath.IsAbs(metadata.ProjectDir) || !filepath.IsAbs(metadata.RoE) {
		return errors.New("engage: checkpoint paths must be absolute")
	}
	if len(metadata.PolicyHash) != 64 {
		return errors.New("engage: checkpoint policy hash is invalid")
	}
	for _, char := range metadata.PolicyHash {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return errors.New("engage: checkpoint policy hash is invalid")
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, metadata.Started); err != nil {
		return errors.New("engage: checkpoint start time is invalid")
	}
	return nil
}

func uniqueJSONFields(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("JSON object required")
	}
	seen := map[string]bool{}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return errors.New("duplicate or invalid JSON field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return errors.New("unterminated JSON object")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON content")
	}
	return nil
}

func verifyEngagePolicy(path, expected string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("engage: saved policy unavailable: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return errors.New("engage: saved policy must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return err
	}
	if string(data) != expected {
		return errors.New("engage: saved policy differs from the checkpoint")
	}
	return nil
}

func acquireEngageLock(dir string) (*os.File, error) {
	path := filepath.Join(dir, "running.lock")
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("engage: cannot open running lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("engage: running lock must be a regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("engage: workspace already has an active run")
	}
	if err := file.Truncate(0); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := fmt.Fprintln(file, os.Getpid()); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
func writeEngageMetadata(dir string, metadata engageRunMetadata) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, "run.json"), data)
}

func watchEngageStop(ctx context.Context, dir string, cancel context.CancelFunc) func() {
	done := make(chan struct{})
	quit := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-quit:
				return
			case <-ticker.C:
				if _, err := os.Stat(filepath.Join(dir, "STOP")); err == nil {
					cancel()
					return
				}
			}
		}
	}()
	return func() { close(quit); <-done }
}

func reopenInterruptedTasks(ctx context.Context, store *engagement.Store) error {
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return err
	}
	var tasks []engagement.Task
	for _, task := range snapshot.Tasks {
		if task.Status == engagement.StatusActive {
			task.Status = engagement.StatusTodo
			tasks = append(tasks, task)
		}
	}
	if len(tasks) > 0 {
		_, err = store.Apply(engagement.Delta{Upserts: tasks})
	}
	return err
}
