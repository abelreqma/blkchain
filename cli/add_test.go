package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAddArgsBasic(t *testing.T) {
	a, err := parseAddArgs([]string{"./notes.md"})
	if err != nil {
		t.Fatalf("parseAddArgs() error = %v", err)
	}
	if a.path != "./notes.md" || a.source != "" || a.typ != "" {
		t.Errorf("parseAddArgs() = %+v, want path=./notes.md source= typ=", a)
	}
}

func TestParseAddArgsFlagsBeforeAndAfterPath(t *testing.T) {
	a, err := parseAddArgs([]string{"--source", "mydocs", "--type", "md", "./notes.md"})
	if err != nil {
		t.Fatalf("parseAddArgs() error = %v", err)
	}
	if a.path != "./notes.md" || a.source != "mydocs" || a.typ != "md" {
		t.Errorf("parseAddArgs() = %+v, want path=./notes.md source=mydocs typ=md", a)
	}

	// Flags after the positional path must also work (reorder handles this,
	// same as search/ask).
	a2, err := parseAddArgs([]string{"./notes.md", "--source", "mydocs", "--type", "md"})
	if err != nil {
		t.Fatalf("parseAddArgs() error = %v", err)
	}
	if a2 != a {
		t.Errorf("parseAddArgs() with trailing flags = %+v, want %+v", a2, a)
	}
}

func TestParseAddArgsRejectsUnknownType(t *testing.T) {
	_, err := parseAddArgs([]string{"--type", "exe", "./notes.md"})
	if err == nil {
		t.Fatal("expected error for unknown --type, got nil")
	}
	if !strings.Contains(err.Error(), "md, txt, or pdf") {
		t.Errorf("error = %v, want message naming the allowed types", err)
	}
}

func TestParseAddArgsAcceptsEachKnownType(t *testing.T) {
	for typ := range addTypeMap {
		a, err := parseAddArgs([]string{"--type", typ, "path"})
		if err != nil {
			t.Fatalf("parseAddArgs(--type %s) error = %v", typ, err)
		}
		if a.typ != typ {
			t.Errorf("parseAddArgs(--type %s).typ = %q", typ, a.typ)
		}
	}
}

func TestParseAddArgsRequiresExactlyOnePath(t *testing.T) {
	if _, err := parseAddArgs(nil); err == nil {
		t.Error("expected error for missing path, got nil")
	}
	if _, err := parseAddArgs([]string{"a", "b"}); err == nil {
		t.Error("expected error for two positional args, got nil")
	}
}

func TestParseAddArgsAcceptsURL(t *testing.T) {
	a, err := parseAddArgs([]string{"https://example.com/doc"})
	if err != nil {
		t.Fatalf("parseAddArgs() error = %v", err)
	}
	if a.path != "https://example.com/doc" {
		t.Errorf("parseAddArgs().path = %q", a.path)
	}
}

func TestLastNonEmptyLine(t *testing.T) {
	got, err := lastNonEmptyLine(strings.NewReader("line one\n\n{\"indexed\":1}\n\n"))
	if err != nil {
		t.Fatalf("lastNonEmptyLine() error = %v", err)
	}
	if got != `{"indexed":1}` {
		t.Errorf("lastNonEmptyLine() = %q", got)
	}
}

func TestRunAddSanitizesTerminalStderrOnly(t *testing.T) {
	root := fakeRoot(t)
	py := filepath.Join(root, ".venv", "bin")
	if err := os.MkdirAll(py, 0o755); err != nil {
		t.Fatal(err)
	}
	// The fake python reports a refused connection on stderr, wrapped in a
	// control sequence, and exits nonzero. The raw buffer must still match.
	writeFakeBin(t, py, "python", `printf 'err-visible\033]0;evil\007 ConnectionError\033[2J\n' >&2
exit 1
`)

	var err error
	stderr := captureStderr(t, func() { err = runAdd([]string{"./notes.md"}) })
	if err == nil || !strings.Contains(err.Error(), "aren't reachable") {
		t.Errorf("runAdd() error = %v, want the services-unreachable error (raw stderr buffer inspected)", err)
	}
	assertClean(t, "stderr", stderr, "err-visible")
}

// fakeAddPython installs a fake <root>/.venv/bin/python running body.
func fakeAddPython(t *testing.T, body string) {
	t.Helper()
	dir := filepath.Join(fakeRoot(t), ".venv", "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeBin(t, dir, "python", body)
}

func TestRunAddDrainsStdoutAfterOversizedLine(t *testing.T) {
	// A stdout line past the scanner cap stops the read. Without a drain the
	// child blocks on a full pipe and Wait never returns.
	fakeAddPython(t, "head -c 2500000 /dev/zero | tr '\\0' a\necho\nhead -c 500000 /dev/zero | tr '\\0' b\necho\n")
	var err error
	runWithin(t, 20*time.Second, func() {
		captureStderr(t, func() { err = runAdd([]string{"./notes.md"}) })
	})
	if err == nil || !strings.Contains(err.Error(), "reading python output") {
		t.Errorf("runAdd() error = %v, want the reading-python-output error", err)
	}
}

func TestRunAddUnreachableAfterLargeStderr(t *testing.T) {
	// More than the retained tail, with the telling line last.
	fakeAddPython(t, "head -c 300000 /dev/zero | tr '\\0' x >&2\necho >&2\necho 'ConnectionError: refused' >&2\nexit 1\n")
	var err error
	runWithin(t, 20*time.Second, func() {
		captureStderr(t, func() { err = runAdd([]string{"./notes.md"}) })
	})
	if err == nil || !strings.Contains(err.Error(), "aren't reachable") {
		t.Errorf("runAdd() error = %v, want the services-unreachable error", err)
	}
}

func TestTailBufferKeepsBoundedTail(t *testing.T) {
	tb := &tailBuffer{max: 100}
	for i := 0; i < 1000; i++ {
		if n, err := tb.Write([]byte("0123456789")); n != 10 || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	tb.Write([]byte("LAST"))
	got := tb.String()
	if len(got) != 100 || !strings.HasSuffix(got, "89LAST") {
		t.Errorf("String() = %q (len %d), want the last 100 bytes", got, len(got))
	}
	if cap(tb.buf) > 4*tb.max {
		t.Errorf("retained capacity %d exceeds the bound", cap(tb.buf))
	}
	small := &tailBuffer{max: 100}
	small.Write([]byte("short"))
	if small.String() != "short" {
		t.Errorf("String() = %q, want short", small.String())
	}
}

func TestIsConnectionRefused(t *testing.T) {
	cases := map[string]bool{
		"requests.exceptions.ConnectionError: HTTPConnectionPool":             true,
		"Failed to establish a new connection: [Errno 61] Connection refused": true,
		"Max retries exceeded with url: /embed":                               true,
		"error: no such file or directory: /tmp/nope.md":                      false,
		"": false,
	}
	for s, want := range cases {
		if got := isConnectionRefused(s); got != want {
			t.Errorf("isConnectionRefused(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestRunAddPreservesCallerRelativePathAndReportsDeletions(t *testing.T) {
	fakeAddPython(t, `printf '%s\n' "$3" >&2
printf '{"indexed":1,"deleted":2,"source":"notes"}\n'
`)
	caller := t.TempDir()
	t.Chdir(caller)
	var err error
	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() { err = runAdd([]string{"./notes.md"}) })
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, filepath.Join(caller, "notes.md")) {
		t.Fatalf("caller-relative path was lost: %q", stderr)
	}
	if !strings.Contains(stdout, "2 deleted") {
		t.Fatalf("deletions omitted: %q", stdout)
	}
}
