package main

import (
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isolatedHermesExecutable(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "hermes"), []byte("#!/bin/sh\nprintf 'hermes-default-fixture\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("HERMES_HOME", t.TempDir())
}

func TestUnselectedInteractiveDefaultIsHermes(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	isolatedHermesExecutable(t)
	m := initialModel()
	if m.hist != nil {
		defer m.hist.Close()
	}
	if m.rc != nil {
		defer m.rc.Close()
	}
	if m.mode != "agent" || !strings.Contains(m.answerAgentStatus(), "Hermes") {
		t.Fatalf("unselected backend is %q: %s", m.mode, m.answerAgentStatus())
	}
	if err := m.selectAnswerAgent("auto"); err != nil {
		t.Fatal(err)
	}
	if m.mode != "rag" || m.answerAgent != "" {
		t.Fatal("explicit auto did not select native dynamic routing")
	}
}

func TestUnselectedCLIAskDefaultsToHermes(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	isolatedHermesExecutable(t)
	var err error
	out := captureStdout(t, func() { _, err = askWith(nil, nil, []string{"a question"}) })
	if err != nil || !strings.Contains(out, "hermes-default-fixture") {
		t.Fatalf("default CLI bypassed Hermes: %q, %v", out, err)
	}
}

func TestNativeOutputRequiresExplicitAgent(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	isolatedHermesExecutable(t)
	for _, args := range [][]string{
		{"--json", "question"},
		{"--sources", "question"},
		{"--rag", "--json", "question"},
		{"--web", "--sources", "question"},
		{"--json", "--context", filepath.Join(t.TempDir(), "missing"), "question"},
	} {
		_, err := askWith(nil, nil, args)
		if _, ok := err.(*usageError); !ok || !strings.Contains(err.Error(), "--agent auto") {
			t.Fatalf("native output did not require explicit selection for %v: %v", args, err)
		}
	}
}

func TestPlainDefaultHermesThenExplicitNative(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	isolatedHermesExecutable(t)
	t.Chdir(t.TempDir())
	previous := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = previous })
	calls := 0
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		calls++
		if opts.Stream != nil {
			opts.Stream([]byte("native-fixture"))
		}
		return "native-fixture", nil, false, nil, 1, "skip", nil
	}
	input := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(input, []byte("first question\n/agent auto\nsecond question\n/quit\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	old := os.Stdin
	os.Stdin = file
	t.Cleanup(func() { os.Stdin = old })
	out := captureStdout(t, func() {
		if err := plainREPL(); err != nil {
			t.Fatal(err)
		}
	})
	if calls != 1 || !strings.Contains(out, "hermes-default-fixture") || !strings.Contains(out, "native-fixture") {
		t.Fatalf("plain default/override diverged: calls=%d out=%q", calls, out)
	}
}
