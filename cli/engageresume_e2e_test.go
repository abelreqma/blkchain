package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
)

func TestEngageResumeLocalLLM(t *testing.T) {
	if os.Getenv("BLKCHAIN_ENGAGE_LLM_E2E") != "1" {
		t.Skip("requires the local LLM stack and a built blk binary")
	}
	project, wsDir := t.TempDir(), t.TempDir()
	roePath := filepath.Join(project, "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	binary, err := filepath.Abs("blk")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_ENGAGE_MAX_ROUNDS", "1")
	t.Setenv("BLKCHAIN_COLLECTION", "blkchain_dwq")
	t.Setenv("BLK_ENABLE_THINKING", "0")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Dir = project
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("blk %v: %v\n%s", args, err, output)
		}
		return string(output)
	}
	first := run("engage", "--auto", "--workspace", wsDir,
		"Create one web inspection task for 192.0.2.1. Do not dispatch or run commands. Return a report.")
	if !strings.Contains(first, "Engagement paused:") {
		t.Fatalf("first report=%q", first)
	}
	ws, err := engagement.OpenWorkspace(wsDir)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := ws.Store.Snapshot(ctx)
	ws.Close()
	if err != nil || len(snap.Tasks) != 1 || snap.Tasks[0].Status != engagement.StatusTodo {
		t.Fatalf("initial tasks=%+v err=%v", snap.Tasks, err)
	}
	if err := os.WriteFile(roePath, []byte("## In Scope\n198.51.100.2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_ENGAGE_MAX_ACTIONS", "1")
	second := run("engage", "resume", "--workspace", wsDir)
	if !strings.Contains(second, "Report:") {
		t.Fatalf("resume report=%q", second)
	}
	ws, err = engagement.OpenWorkspace(wsDir)
	if err != nil {
		t.Fatal(err)
	}
	snap, err = ws.Store.Snapshot(ctx)
	ws.Close()
	if err != nil || len(snap.Tasks) != 1 || snap.Tasks[0].ID != "t1" {
		t.Fatalf("resumed tasks=%+v err=%v", snap.Tasks, err)
	}
	saved, err := os.ReadFile(filepath.Join(wsDir, "ROE.md"))
	if err != nil || !strings.Contains(string(saved), "192.0.2.1") || strings.Contains(string(saved), "198.51.100.2") {
		t.Fatalf("saved RoE=%q err=%v", saved, err)
	}
	t.Logf("first:\n%s\nresumed:\n%s", first, second)
}

func TestEngageExternalStopFlushesReport(t *testing.T) {
	if os.Getenv("BLKCHAIN_ENGAGE_LLM_E2E") != "1" {
		t.Skip("requires a built blk binary")
	}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	project, wsDir := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "ROE.md"), []byte("## In Scope\n192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	binary, err := filepath.Abs("blk")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "engage", "--auto", "--workspace", wsDir, "--model", "test-model", "plan one web task for 192.0.2.1")
	cmd.Dir = project
	cmd.Env = append(os.Environ(), "OMLX_BASE_URL="+server.URL+"/v1", "XDG_CONFIG_HOME="+t.TempDir())
	var output bytes.Buffer
	writer := &lockedWriter{w: &output}
	cmd.Stdout, cmd.Stderr = writer, writer
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatalf("model request did not start: %s", output.String())
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("stopped engagement exited successfully")
	}
	data, err := os.ReadFile(filepath.Join(wsDir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "interrupted" || !strings.Contains(output.String(), filepath.Join(wsDir, "report.md")) {
		t.Fatalf("status=%q output=%q", report.Status, output.String())
	}
}
