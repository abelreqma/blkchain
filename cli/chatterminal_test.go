package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// Concurrent turns share one workspace container: the inspect-then-run must
// happen once, because a second docker run with the same name is a conflict the
// loser surfaces as a terminal-tool failure.
func TestEnsureChatContainerCreatesOneContainerForConcurrentTurns(t *testing.T) {
	root := t.TempDir()
	name := chatContainerName(root)
	prev := chatDocker
	t.Cleanup(func() { chatDocker = prev })

	var mu sync.Mutex
	runs, exists := 0, false
	chatDocker = func(_ context.Context, _ []byte, args ...string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case len(args) > 1 && args[0] == "image":
			return "sha256:image", nil
		case args[0] == "inspect":
			if !exists {
				// Hold the miss open so unserialized callers both see it.
				mu.Unlock()
				time.Sleep(50 * time.Millisecond)
				mu.Lock()
				return "", fmt.Errorf("no such object")
			}
			return name + " sha256:image true", nil
		case args[0] == "run":
			runs++
			if exists {
				return "", fmt.Errorf("conflict: the container name %q is already in use", name)
			}
			exists = true
			return "created", nil
		}
		return "", fmt.Errorf("unexpected docker call %v", args)
	}

	var wg sync.WaitGroup
	got, errs := make([]string, 2), make([]error, 2)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], errs[i] = ensureChatContainer(context.Background(), root)
		}(i)
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("turn %d could not reach the sandbox: %v", i, errs[i])
		}
		if got[i] != name {
			t.Fatalf("turn %d container = %q, want %q", i, got[i], name)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if runs != 1 {
		t.Fatalf("docker run was called %d times, want 1", runs)
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
