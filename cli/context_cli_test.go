package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

func TestCLIContextUsesSharedFileAndURLPreparation(t *testing.T) {
	useDeadServices(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "context.txt")
	if err := os.WriteFile(path, []byte("reference notes"), 0600); err != nil {
		t.Fatal(err)
	}
	old := adaptiveAnswerFn
	defer func() { adaptiveAnswerFn = old }()
	called := false
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, q string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		called = true
		if q != "hello" || !strings.Contains(opts.Preface, "reference notes") || !strings.Contains(opts.Preface, "URL reference") {
			t.Errorf("context not delivered: %q", opts.Preface)
		}
		opts.Stream([]byte("answer"))
		return "answer", nil, false, nil, 1, "skip", nil
	}
	var err error
	captureStdout(t, func() {
		_, err = askWith(nil, nil, []string{"--agent", "auto", "--context", path, "--context", "https://example.test/reference", "hello"})
	})
	if err != nil || !called {
		t.Fatalf("context flags failed: %v", err)
	}
}
