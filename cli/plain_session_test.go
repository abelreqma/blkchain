package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/histstore"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

func TestPlainREPLCommandsAndContext(t *testing.T) {
	useDeadServices(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	if err := os.Mkdir(".blk", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(initContextPath, []byte("project context"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := adaptiveAnswerFn
	defer func() { adaptiveAnswerFn = old }()
	calls := 0
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, q string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		calls++
		if q != "hello" || !strings.Contains(opts.Preface, "project context") {
			t.Errorf("answer received q=%q, context=%q", q, opts.Preface)
		}
		opts.Stream([]byte("saved answer"))
		return "saved answer", nil, false, nil, 2, "skip", nil
	}
	p := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(p, []byte("/unknown\n/model\n/engage\n/init\nhello\n/history\n/quit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stdin := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = stdin }()
	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			if err := plainREPL(); err != nil {
				t.Fatal(err)
			}
		})
	})
	if calls != 1 {
		t.Fatalf("slash commands reached the answer loop: %d calls", calls)
	}
	for _, want := range []string{"unknown command /unknown", "/model requires the interactive TUI", "missing goal"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("missing command error %q: %q", want, stderr)
		}
	}
	if !strings.Contains(stdout, "loaded .blk/context.md") || !strings.Contains(stdout, "2 messages") {
		t.Fatalf("context or persistent history missing: %q", stdout)
	}
	h := histstore.OpenDefault()
	if h == nil {
		t.Fatal("history unavailable")
	}
	defer h.Close()
	hs, err := h.Sessions(context.Background())
	if err != nil || len(hs) != 1 {
		t.Fatalf("history sessions: %v, %v", hs, err)
	}
	m := model{hist: h}
	var turns []priorTurn
	captureStdout(t, func() { turns, err = plainHistory(&m, "1", nil) })
	if err != nil || len(turns) != 2 || turns[0].Content != "hello" || m.lastAnswer != "saved answer" || m.sess.id != hs[0].ID {
		t.Fatalf("history resume: %+v, %v", turns, err)
	}
}

func TestPlainEditorRetainsEditableDraftAndRemovesFile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir := t.TempDir()
	editor := filepath.Join(dir, "editor")
	if err := os.WriteFile(editor, []byte("#!/bin/sh\nprintf 'edited draft\\nsecond line' > \"$1\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", editor)
	var draft string
	var err error
	out := captureStdout(t, func() { draft, err = plainEditor("before") })
	if err != nil || draft != "edited draft\nsecond line" || !strings.Contains(out, "Enter submits") {
		t.Fatalf("editor draft = %q, %v, output %q", draft, err, out)
	}
	private, err := draftDir()
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(private, "blk-draft-*.md"))
	if err != nil || len(files) != 0 {
		t.Fatalf("editor left private drafts: %v, %v", files, err)
	}
}
