package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChatTerminalBoundsAndExplicitLocalHost(t *testing.T) {
	root := t.TempDir()
	if _, err := chatTerminalCall(context.Background(), root, chatToolHostLocal, chatTerminalArgs{Command: strings.Repeat("x", chatTerminalMaxCommand+1)}); err == nil {
		t.Fatal("oversized command accepted")
	}
	if _, err := chatTerminalCall(context.Background(), root, chatToolHostLocal, chatTerminalArgs{Command: "pwd", TimeoutSeconds: 61}); err == nil {
		t.Fatal("oversized timeout accepted")
	}
	out, err := chatTerminalCall(context.Background(), root, chatToolHostLocal, chatTerminalArgs{Command: "printf local-check > local.txt"})
	if err != nil || !strings.Contains(out, "UNTRUSTED") {
		t.Fatalf("local terminal failed: out=%q err=%v", out, err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "local.txt")); err != nil || string(data) != "local-check" {
		t.Fatalf("local command did not write selected root: data=%q err=%v", data, err)
	}
}

func TestChatTerminalPersistentDockerSandbox(t *testing.T) {
	if os.Getenv("BLKCHAIN_CHAT_SANDBOX_E2E") != "1" {
		t.Skip("set BLKCHAIN_CHAT_SANDBOX_E2E=1 with Docker running")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	project := t.TempDir()
	t.Chdir(project)
	root, err := chatWorkspaceRoot("")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	name := chatContainerName(root)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_, _ = chatDocker(cleanup, nil, "rm", "-f", name)
	})
	first, err := chatTerminalCall(ctx, root, chatToolHostSandbox, chatTerminalArgs{Command: "printf sandbox-check > note.txt"})
	if err != nil || strings.Contains(first, "exit:") {
		t.Fatalf("sandbox write failed: out=%q err=%v", first, err)
	}
	second, err := chatTerminalCall(ctx, root, chatToolHostSandbox, chatTerminalArgs{Command: "cat note.txt"})
	if err != nil || !strings.Contains(second, "sandbox-check") {
		t.Fatalf("sandbox did not persist between calls: out=%q err=%v", second, err)
	}
	if _, err := os.Stat(filepath.Join(project, "note.txt")); !os.IsNotExist(err) {
		t.Fatalf("sandbox write reached project directory: %v", err)
	}
}
