package main

import (
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// evilScriptBody prints terminal control sequences plus visible text to both
// streams: an OSC 0 retitle, a CSI 2J clear, and an OSC 52 clipboard write.
const evilScriptBody = `printf 'out-visible\033]0;evil\007\033[2J-tail\n'
printf 'err-visible\033]52;c;eA==\007\033[2J-tail\n' >&2
`

// writeFakeBin writes an executable shell script named name into dir.
func writeFakeBin(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	return p
}

// fakeBinOnPath installs a fake executable first on PATH for the test.
func fakeBinOnPath(t *testing.T, name, body string) {
	t.Helper()
	dir := t.TempDir()
	writeFakeBin(t, dir, name, body)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// captureStderr runs fn with os.Stderr redirected, returning everything written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	// Read while fn runs so a large write cannot block on a full pipe.
	got := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(r)
		got <- b
	}()

	fn()

	w.Close()
	return string(<-got)
}

// captureBoth runs fn and returns what it wrote to stdout and stderr.
func captureBoth(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	stderr = captureStderr(t, func() {
		stdout = captureStdout(t, fn)
	})
	return stdout, stderr
}

// assertClean fails when s holds ESC or BEL, or lacks any of the wanted text.
func assertClean(t *testing.T, label, s string, want ...string) {
	t.Helper()
	if strings.ContainsAny(s, "\x1b\x07") {
		t.Errorf("%s holds a control byte: %q", label, s)
	}
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Errorf("%s = %q, want it to contain %q", label, s, w)
		}
	}
}

func TestRunHermesSanitizesChildOutput(t *testing.T) {
	fakeBinOnPath(t, "hermes", evilScriptBody+`echo "argc=$# arg1=$1 arg2=$2"`+"\n")
	var err error
	stdout, stderr := captureBoth(t, func() {
		err = runHermes([]string{"summarize", "the", "notes"})
	})
	if err != nil {
		t.Fatalf("runHermes() error = %v", err)
	}
	assertClean(t, "stdout", stdout, "out-visible-tail", "argc=2 arg1=-z arg2=summarize the notes")
	assertClean(t, "stderr", stderr, "err-visible-tail")
}

func TestRunHermesExitError(t *testing.T) {
	fakeBinOnPath(t, "hermes", "echo partial\nexit 7\n")
	var err error
	stdout := captureStdout(t, func() {
		captureStderr(t, func() { err = runHermes([]string{"hi"}) })
	})
	if err == nil || !strings.Contains(err.Error(), "exit status 7") {
		t.Errorf("runHermes() error = %v, want exit status 7", err)
	}
	if !strings.Contains(stdout, "partial") {
		t.Errorf("stdout = %q, want the child's output relayed before the error", stdout)
	}
}

// An inherited PYTHONUNBUFFERED must never win over the value blk forces: the
// built env carries exactly one PYTHONUNBUFFERED entry, and it is "1".
func TestPythonUnbufferedEnvForcesOurValue(t *testing.T) {
	t.Setenv("PYTHONUNBUFFERED", "0")
	var seen []string
	for _, e := range pythonUnbufferedEnv() {
		if strings.HasPrefix(e, "PYTHONUNBUFFERED=") {
			seen = append(seen, e)
		}
	}
	if len(seen) != 1 || seen[0] != "PYTHONUNBUFFERED=1" {
		t.Fatalf("PYTHONUNBUFFERED entries = %v, want exactly [PYTHONUNBUFFERED=1]", seen)
	}
}

func TestRunHermesSetsUnbuffered(t *testing.T) {
	fakeBinOnPath(t, "hermes", `echo "unbuffered=$PYTHONUNBUFFERED"`+"\n")
	var err error
	stdout := captureStdout(t, func() {
		captureStderr(t, func() { err = runHermes([]string{"hi"}) })
	})
	if err != nil || !strings.Contains(stdout, "unbuffered=1") {
		t.Errorf("runHermes() = %v, stdout %q, want PYTHONUNBUFFERED=1 in the child", err, stdout)
	}
}

// interruptScript simulates ctrl+c: it signals its parent (blk, which catches
// SIGINT while a piped child runs), then dies of SIGINT itself. The pauses let
// the parent's handler run before the child exits.
const interruptScript = `echo relayed
sleep 0.3
kill -INT $PPID
sleep 0.3
kill -INT $$
`

// sigintIgnoredAtStart is read during package init, before any test calls
// signal.Notify. After a Notify and Stop, signal.Ignored reports false even
// though the OS disposition is back to ignored.
var sigintIgnoredAtStart = signal.Ignored(os.Interrupt)

// skipIfSigintIgnored skips tests that raise SIGINT: with it ignored the
// child inherits the ignore and kill -INT does nothing.
func skipIfSigintIgnored(t *testing.T) {
	t.Helper()
	if sigintIgnoredAtStart {
		t.Skip("SIGINT is ignored in this process")
	}
}

// runWithin runs fn and fails the test, instead of hanging, if it takes longer
// than d. fn must not call t.Fatal.
func runWithin(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("timed out after %v", d)
	}
}

func TestRunHermesCanceledOnCtrlC(t *testing.T) {
	skipIfSigintIgnored(t)
	fakeBinOnPath(t, "hermes", interruptScript)
	var err error
	var stdout string
	runWithin(t, 10*time.Second, func() {
		stdout = captureStdout(t, func() {
			captureStderr(t, func() { err = runHermes([]string{"hi"}) })
		})
	})
	if err == nil || err.Error() != "hermes: canceled" {
		t.Errorf("runHermes() error = %v, want hermes: canceled", err)
	}
	if !strings.Contains(stdout, "relayed") {
		t.Errorf("stdout = %q, want output relayed before the interrupt", stdout)
	}
}
