package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func historyFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return filepath.Join(dir, "blkchain", "history")
}

// An entry at the draft cap is kept, and so are the entries around it.
func TestHistoryKeepsEntriesAroundADraftAtTheCap(t *testing.T) {
	historyFile(t)
	big := strings.Repeat("a", inputCharLimit)
	for _, e := range []string{"first", big, "last"} {
		if err := appendHistory(e); err != nil {
			t.Fatal(err)
		}
	}
	if got := loadHistory(); !reflect.DeepEqual(got, []string{"first", big, "last"}) {
		t.Fatalf("loadHistory kept %d entries, want 3 with the big one intact", len(got))
	}
}

// A line too long to be an entry, and a line that is not a valid entry, never
// cost the other entries.
func TestHistorySkipsOversizedAndCorruptLines(t *testing.T) {
	p := historyFile(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	huge := `"` + strings.Repeat("x", historyMaxEntryBytes) + `"`
	data := `"before"` + "\n" + huge + "\n" + `"unterminated` + "\n" + `"after"` + "\n"
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	got := loadHistory()
	if len(got) == 0 || got[0] != "before" || got[len(got)-1] != "after" {
		t.Fatalf("loadHistory = %q, want the entries before and after the bad lines", got)
	}
	for _, e := range got {
		if len(e) > historyMaxEntryBytes {
			t.Fatalf("an oversized line came back as an entry (%d bytes)", len(e))
		}
	}
}

// A multi-line draft is one entry, not one per line.
func TestHistoryRoundTripsAMultiLineEntry(t *testing.T) {
	historyFile(t)
	if err := appendHistory("line one\nline two"); err != nil {
		t.Fatal(err)
	}
	if got := loadHistory(); !reflect.DeepEqual(got, []string{"line one\nline two"}) {
		t.Fatalf("loadHistory = %q, want one two-line entry", got)
	}
}

// A file written before entries were encoded still loads, one entry per line.
func TestHistoryReadsPlainLines(t *testing.T) {
	p := historyFile(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("ask what is ssrf\nsearch xss\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadHistory(); !reflect.DeepEqual(got, []string{"ask what is ssrf", "search xss"}) {
		t.Fatalf("loadHistory = %q", got)
	}
}

// The file itself stays within the entry and byte caps, keeping the newest.
func TestHistoryFileStaysBounded(t *testing.T) {
	p := historyFile(t)
	for i := 0; i < historyMaxEntries+200; i++ {
		if err := appendHistory(fmt.Sprintf("line %d", i)); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "\n"); n > historyMaxEntries {
		t.Errorf("history file has %d entries, want at most %d", n, historyMaxEntries)
	}
	got := loadHistory()
	if len(got) > historyMaxEntries || len(got) < historyTrimEntries || got[len(got)-1] != fmt.Sprintf("line %d", historyMaxEntries+199) {
		t.Errorf("loadHistory kept %d entries ending %q, want between %d and %d ending with the newest", len(got), got[len(got)-1], historyTrimEntries, historyMaxEntries)
	}

	big := strings.Repeat("b", 60000)
	for i := 0; i < 40; i++ {
		if err := appendHistory(fmt.Sprintf("%d %s", i, big)); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > historyMaxBytes {
		t.Errorf("history file is %d bytes, want at most %d", fi.Size(), historyMaxBytes)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("history file mode = %v, want 0600", fi.Mode().Perm())
	}
	if got := loadHistory(); !strings.HasPrefix(got[len(got)-1], "39 ") {
		t.Errorf("the newest entry was not kept")
	}
}

// At the cap the file is trimmed well below it, so appends go on for at least
// 100 entries before the next rewrite.
func TestHistoryRewritesRarelyAtTheCap(t *testing.T) {
	p := historyFile(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for i := 0; i < historyMaxEntries; i++ {
		fmt.Fprintf(&b, "%q\n", fmt.Sprint("old ", i))
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	rewrites := 0
	for i := 0; i < 300; i++ {
		before, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := appendHistory(fmt.Sprint("new ", i)); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before, after) {
			rewrites++
		}
	}
	if rewrites > 3 {
		t.Errorf("300 appends at the cap rewrote the file %d times, want at most 3", rewrites)
	}
	got := loadHistory()
	if len(got) > historyMaxEntries || got[len(got)-1] != "new 299" {
		t.Errorf("history has %d entries ending %q", len(got), got[len(got)-1])
	}
}

// A history path that is a symlink is neither read nor chmod-ed, and nothing
// is appended through it.
func TestHistoryIgnoresASymlink(t *testing.T) {
	p := historyFile(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("\"secret entry\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if got := loadHistory(); len(got) != 0 {
		t.Errorf("loadHistory read through the symlink: %q", got)
	}
	appendHistory("new entry")
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("the symlink target's mode changed to %v", fi.Mode().Perm())
	}
	if data, _ := os.ReadFile(target); string(data) != "\"secret entry\"\n" {
		t.Errorf("the symlink target was written: %q", data)
	}
}
