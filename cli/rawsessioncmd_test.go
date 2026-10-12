package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
)

func TestCloseShellRemovesOnlyStaleRecord(t *testing.T) {
	dir := t.TempDir()
	record := rawSessionRecord{PolicyHash: strings.Repeat("a", 64), ShellAddress: "127.0.0.1:1",
		ControlAddress: "127.0.0.1:1", Token: strings.Repeat("b", 64), PID: os.Getpid(), ExpiresAt: time.Now().UTC().Format(time.RFC3339Nano)}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rawSessionRecordPath(dir), data, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRawSessionRecord(dir); err == nil {
		t.Fatal("public raw session token was accepted")
	}
	if err := os.Chmod(rawSessionRecordPath(dir), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runEngageCloseShell([]string{"--workspace", dir}); err != nil {
		t.Fatal(err)
	}
	if saved, err := readRawSessionRecord(dir); err != nil || saved != nil {
		t.Fatalf("stale record remained: %+v err=%v", saved, err)
	}
}

func TestRawSessionDaemonSurvivesEngagementStop(t *testing.T) {
	project, workspace := t.TempDir(), t.TempDir()
	roePath := filepath.Join(project, "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	roe, _, err := loadEngageRoE(engageOpts{roe: roePath}, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	metadata := engageRunMetadata{Goal: "fixture", Mode: "auto", ProjectDir: project, RoE: roePath,
		PolicyHash: roe.Policy.Hash, Started: time.Now().UTC().Format(time.RFC3339Nano), Status: "in-progress"}
	if err := writeEngageMetadata(workspace, metadata); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(workspace, "policy.json"), []byte(roe.Policy.Canonical)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runRawSessionDaemon(ctx, workspace, 0) }()
	var record *rawSessionRecord
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		record, err = readRawSessionRecord(workspace)
		if err == nil && record != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || record == nil {
		t.Fatalf("raw session daemon did not start: record=%+v err=%v", record, err)
	}
	conn, err := net.Dial("tcp", record.ShellAddress)
	if err != nil {
		t.Fatal(err)
	}
	shell := exec.CommandContext(ctx, "/bin/sh")
	shell.Stdin, shell.Stdout, shell.Stderr = conn, conn, conn
	if err := shell.Start(); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	defer func() {
		_ = conn.Close()
		_ = shell.Wait()
	}()
	for time.Now().Before(deadline) {
		connected, statusErr := rawBrokerStatus(ctx, record.ControlAddress, record.Token)
		if statusErr == nil && connected {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := stopEngageWorkspace([]string{"--workspace", workspace}); err != nil {
		t.Fatal(err)
	}
	response, err := rawBrokerRequest(ctx, record.ControlAddress, record.Token, []string{"printf", "retained"}, 4096, 3*time.Second)
	if err != nil || response.Output != "retained" {
		t.Fatalf("stopped engagement lost the shell: response=%+v err=%v", response, err)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if saved, err := readRawSessionRecord(workspace); err != nil || saved != nil {
		t.Fatalf("daemon record remained after shutdown: record=%+v err=%v", saved, err)
	}
	if !strings.HasPrefix(record.ShellAddress, "127.0.0.1:") {
		t.Fatal("raw listener left loopback")
	}
}

func TestAttachedRawSessionAdvancesOnlyAfterLiveProbe(t *testing.T) {
	previous := newEngageRunnerForRun
	newEngageRunnerForRun = func(_ context.Context, roe *RoE) (*engageRunner, error) {
		carrier, err := newFootholdTransport(roe.Policy.Foothold)
		if err != nil {
			return nil, err
		}
		return &engageRunner{workers: map[string]string{}, foothold: carrier}, nil
	}
	t.Cleanup(func() { newEngageRunnerForRun = previous })
	project, workspace := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "ROE.md"), []byte("## In Scope\n127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var evidenceID int64
	first := engageRunInput{Opts: engageOpts{workspace: workspace}, Cwd: project, Goal: "fixture", Run: func(_ context.Context, d engageDeps, _ string) (string, error) {
		if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "e1", Kind: "exploit", Phase: engagement.PhaseExploit,
			Surface: engagement.SurfaceNetwork, Target: "127.0.0.1", Status: engagement.StatusTodo, Armed: true}}}); err != nil {
			return "", err
		}
		var err error
		evidenceID, err = d.Store.RecordEvidence("e1", "local fixture shell connected")
		return "", errors.Join(err, errors.New("pause fixture"))
	}}
	if _, err := runEngageSession(context.Background(), first); err == nil {
		t.Fatal("initial fixture did not pause")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runRawSessionDaemon(ctx, workspace, 0) }()
	var record *rawSessionRecord
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		record, err = readRawSessionRecord(workspace)
		if err == nil && record != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if record == nil {
		t.Fatal("raw broker did not start")
	}
	conn, err := net.Dial("tcp", record.ShellAddress)
	if err != nil {
		t.Fatal(err)
	}
	shell := exec.CommandContext(ctx, "/bin/sh")
	shell.Stdin, shell.Stdout, shell.Stderr = conn, conn, conn
	if err := shell.Start(); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(); _ = shell.Wait() }()
	for time.Now().Before(deadline) {
		connected, statusErr := rawBrokerStatus(ctx, record.ControlAddress, record.Token)
		if statusErr == nil && connected {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	probe, err := rawBrokerRequest(ctx, record.ControlAddress, record.Token, []string{"true"}, 512, 10*time.Second)
	if err != nil || probe.ExitCode != 0 {
		t.Fatalf("raw broker pre-attachment probe=%+v err=%v", probe, err)
	}
	entry := "127.0.0.1 transport=raw-session session=" + rawSessionRecordPath(workspace) + " surfaces=local,network,ad,container,cloud-aws,cloud-gcp"
	if err := runEngageAttachFoothold([]string{"--workspace", workspace, "--task", "e1", "--evidence", fmt.Sprint(evidenceID), "--entry", entry}); err != nil {
		t.Fatal(err)
	}
	second := engageRunInput{Opts: engageOpts{resume: workspace}, Run: func(_ context.Context, d engageDeps, _ string) (string, error) {
		vantage, err := d.Store.Vantage(context.Background())
		if err != nil || vantage != engagement.VantageInternalFoothold || d.Gate.EffectiveFoothold().Transport != "raw-session" {
			t.Fatalf("raw attachment did not advance: vantage=%q err=%v", vantage, err)
		}
		return "done", nil
	}}
	if _, err := runEngageSession(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
}

func TestRawSessionCLIDetachesAndCloses(t *testing.T) {
	if os.Getenv("BLKCHAIN_RAW_SESSION_E2E") != "1" {
		t.Skip("requires a local blk binary build")
	}
	project, workspace := t.TempDir(), t.TempDir()
	roePath := filepath.Join(project, "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	roe, _, err := loadEngageRoE(engageOpts{roe: roePath}, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	metadata := engageRunMetadata{Goal: "fixture", Mode: "auto", ProjectDir: project, RoE: roePath,
		PolicyHash: roe.Policy.Hash, Started: time.Now().UTC().Format(time.RFC3339Nano), Status: "in-progress"}
	if err := writeEngageMetadata(workspace, metadata); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(workspace, "policy.json"), []byte(roe.Policy.Canonical)); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "blk")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture binary: %v %s", err, out)
	}
	listen := exec.CommandContext(ctx, binary, "engage", "listen-shell", "--workspace", workspace)
	out, err := listen.CombinedOutput()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(out)), "127.0.0.1:") {
		t.Fatalf("listener did not detach: output=%q err=%v", out, err)
	}
	record, err := readRawSessionRecord(workspace)
	if err != nil || record == nil {
		t.Fatalf("daemon record missing: %+v err=%v", record, err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		_ = exec.CommandContext(closeCtx, binary, "engage", "close-shell", "--workspace", workspace).Run()
		if current, err := readRawSessionRecord(workspace); err == nil && current != nil && current.PID == record.PID && current.Token == record.Token {
			_ = syscall.Kill(record.PID, syscall.SIGTERM)
		}
	})
	connected, err := rawBrokerStatus(context.Background(), record.ControlAddress, record.Token)
	if err != nil || connected {
		t.Fatalf("listener was not waiting for a shell: connected=%t err=%v", connected, err)
	}
	closeCmd := exec.CommandContext(ctx, binary, "engage", "close-shell", "--workspace", workspace)
	if out, err := closeCmd.CombinedOutput(); err != nil {
		t.Fatalf("close-shell failed: %v %s", err, out)
	}
	if remaining, err := readRawSessionRecord(workspace); err != nil || remaining != nil {
		t.Fatalf("daemon record persisted: %+v err=%v", remaining, err)
	}
}
