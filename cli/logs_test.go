package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeRoot makes a temp project root (marker file present) and points
// BLKCHAIN_ROOT at it.
func fakeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, rootMarker), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_ROOT", root)
	return root
}

// fakeAPILog creates <root>/.run/api.log under a fake project root.
func fakeAPILog(t *testing.T) {
	t.Helper()
	root := fakeRoot(t)
	if err := os.MkdirAll(filepath.Join(root, ".run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".run", "api.log"), []byte("line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunLogsFollowCtrlCIsNotAnError(t *testing.T) {
	skipIfSigintIgnored(t)
	fakeAPILog(t)
	fakeBinOnPath(t, "tail", interruptScript)
	var err error
	var stdout string
	runWithin(t, 10*time.Second, func() {
		stdout = captureStdout(t, func() {
			captureStderr(t, func() { err = runLogs([]string{"-f"}) })
		})
	})
	if err != nil {
		t.Errorf("runLogs(-f) after ctrl+c error = %v, want nil", err)
	}
	if !strings.Contains(stdout, "relayed") {
		t.Errorf("stdout = %q, want output relayed before the interrupt", stdout)
	}
}

func TestRunLogsFollowSanitizesTailOutput(t *testing.T) {
	fakeAPILog(t)
	fakeBinOnPath(t, "tail", evilScriptBody)

	var err error
	stdout, stderr := captureBoth(t, func() { err = runLogs([]string{"-f"}) })
	if err != nil {
		t.Fatalf("runLogs(-f) error = %v", err)
	}
	assertClean(t, "stdout", stdout, "out-visible-tail")
	assertClean(t, "stderr", stderr, "err-visible-tail")
}
