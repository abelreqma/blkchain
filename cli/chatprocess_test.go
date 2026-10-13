package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestChatProcessRejectsUnknownHandles(t *testing.T) {
	if _, err := chatProcessCall(context.Background(), t.TempDir(), chatProcessArgs{Action: "kill", SessionID: "../../123"}); err == nil {
		t.Fatal("path-like process handle accepted")
	}
}

func TestChatProcessRetainsInputOutputAndKill(t *testing.T) {
	if os.Getenv("BLKCHAIN_CHAT_PROCESS_E2E") != "1" {
		t.Skip("set BLKCHAIN_CHAT_PROCESS_E2E=1 with Docker running")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	root, err := chatWorkspaceRoot("")
	if err != nil {
		t.Fatal(err)
	}
	name := chatContainerName(root)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = chatDocker(ctx, nil, "rm", "-f", name)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := chatTerminalCall(ctx, root, chatToolHostSandbox, chatTerminalArgs{Command: `read line; printf 'got:%s\n' "$line"`, Background: true})
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimPrefix(out, "background process ")
	id = strings.TrimSuffix(id, " started")
	if !chatProcessIDPattern.MatchString(id) {
		t.Fatalf("background handle = %q", out)
	}
	if out, err := chatProcessCall(ctx, root, chatProcessArgs{Action: "write", SessionID: id, Data: "hello\n"}); err != nil || out != "input sent" {
		t.Fatalf("process input failed: out=%q err=%v", out, err)
	}
	if out, err := chatProcessCall(ctx, root, chatProcessArgs{Action: "wait", SessionID: id, TimeoutSeconds: 10}); err != nil || !strings.Contains(out, "exited with code 0") {
		t.Fatalf("process wait failed: out=%q err=%v", out, err)
	}
	if out, err := chatProcessCall(ctx, root, chatProcessArgs{Action: "log", SessionID: id}); err != nil || !strings.Contains(out, "got:hello") {
		t.Fatalf("process log failed: out=%q err=%v", out, err)
	}
	out, err = chatTerminalCall(ctx, root, chatToolHostSandbox, chatTerminalArgs{Command: "sleep 30", Background: true})
	if err != nil {
		t.Fatal(err)
	}
	id = strings.TrimSuffix(strings.TrimPrefix(out, "background process "), " started")
	if out, err := chatProcessCall(ctx, root, chatProcessArgs{Action: "kill", SessionID: id}); err != nil || out != "termination requested" {
		t.Fatalf("process kill failed: out=%q err=%v", out, err)
	}
	if out, err := chatProcessCall(ctx, root, chatProcessArgs{Action: "wait", SessionID: id, TimeoutSeconds: 10}); err != nil || !strings.Contains(out, "exited") {
		t.Fatalf("killed process remained running: out=%q err=%v", out, err)
	}
}
