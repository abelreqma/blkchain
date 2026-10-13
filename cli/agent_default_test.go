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

// isolatedHermesExecutable puts a fake hermes on PATH that answers both of the
// invocations blk makes: the one-shot `hermes -z <prompt>` the stateless CLI ask
// uses, which prints the answer as plain text, and the `hermes chat --format
// stream-json` the REPL agent turn uses, which emits the JSONL event stream so
// the answer is captured rather than streamed past.
func isolatedHermesExecutable(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = chat ]; then\n" +
		"  printf '{\"type\":\"text\",\"text\":\"hermes-default-fixture\"}\\n'\n" +
		"  printf '{\"type\":\"result\",\"exit_code\":0}\\n'\n" +
		"else\n" +
		"  printf 'hermes-default-fixture\\n'\n" +
		"fi\n"
	if err := os.WriteFile(filepath.Join(bin, "hermes"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("HERMES_HOME", t.TempDir())
}

func TestUnselectedInteractiveDefaultIsNativeAuto(t *testing.T) {
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
	if m.mode != "rag" || !m.prefs.Web || !strings.Contains(m.answerAgentStatus(), "Auto") {
		t.Fatalf("unselected backend is %q: %s", m.mode, m.answerAgentStatus())
	}
	if err := m.selectAnswerAgent("auto"); err != nil {
		t.Fatal(err)
	}
	if m.mode != "rag" || m.answerAgent != "" {
		t.Fatal("explicit auto did not select native dynamic routing")
	}
}

func TestUnselectedCLIAskDefaultsToNativeAuto(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	isolatedHermesExecutable(t)
	old := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = old })
	calls := 0
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		calls++
		if opts.Agent != "" {
			t.Errorf("default agent = %q, want auto", opts.Agent)
		}
		if opts.Stream != nil {
			opts.Stream([]byte("native-default-fixture"))
		}
		return "native-default-fixture", nil, false, nil, 1, "skip", nil
	}
	var err error
	out := captureStdout(t, func() { _, err = askWith(nil, nil, []string{"a question"}) })
	if err != nil || calls != 1 || !strings.Contains(out, "native-default-fixture") || strings.Contains(out, "hermes-default-fixture") {
		t.Fatalf("default CLI did not use native auto: calls=%d out=%q err=%v", calls, out, err)
	}
}

func TestDefaultCLIOutputFlagsUseNative(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	isolatedHermesExecutable(t)
	old := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = old })
	calls := 0
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		calls++
		if opts.Stream != nil {
			opts.Stream([]byte("native-default-fixture"))
		}
		return "native-default-fixture", nil, false, nil, 1, "skip", nil
	}
	for _, args := range [][]string{
		{"--json", "question"},
		{"--sources", "question"},
		{"--rag", "--json", "question"},
		{"--web", "--sources", "question"},
	} {
		out := captureStdout(t, func() {
			if _, err := askWith(nil, nil, args); err != nil {
				t.Fatalf("default native output failed for %v: %v", args, err)
			}
		})
		if !strings.Contains(out, "native-default-fixture") || strings.Contains(out, "hermes-default-fixture") {
			t.Fatalf("default native output for %v: %q", args, out)
		}
	}
	if calls != 4 {
		t.Fatalf("native answer calls = %d, want 4", calls)
	}
}

func TestExplicitHermesCLIAsk(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	isolatedHermesExecutable(t)
	var err error
	out := captureStdout(t, func() { _, err = askWith(nil, nil, []string{"--hermes", "a question"}) })
	if err != nil || !strings.Contains(out, "hermes-default-fixture") {
		t.Fatalf("explicit Hermes failed: out=%q err=%v", out, err)
	}
	for _, flag := range []string{"--json", "--sources"} {
		_, err := askWith(nil, nil, []string{"--hermes", flag, "a question"})
		if _, ok := err.(*usageError); !ok {
			t.Fatalf("Hermes accepted unsupported %s: %v", flag, err)
		}
	}
}

func TestPlainDefaultNativeThenExplicitHermes(t *testing.T) {
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
	if err := os.WriteFile(input, []byte("first question\n/hermes second question\n/quit\n"), 0600); err != nil {
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
	if !loadPrefs().Web {
		t.Fatal("plain REPL did not enable web on the fresh profile")
	}
}
