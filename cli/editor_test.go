package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/charmbracelet/bubbles/textarea"
)

func TestDraftDirHonorsXDGConfigHome(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	dir, err := draftDir()
	if err != nil {
		t.Fatalf("draftDir: %v", err)
	}
	want := filepath.Join(base, "blkchain")
	if dir != want {
		t.Fatalf("draftDir = %q, want %q", dir, want)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("dir not created: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %o, want 700", fi.Mode().Perm())
	}
}

// The draft is written under the private config dir, not world-readable /tmp.
func TestEditorCmdWritesDraftUnderConfigDir(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	m := model{ta: textarea.New()}
	m.ta.SetValue("my draft")

	_ = m.editorCmd() // creates the draft file synchronously, before returning the cmd

	matches, _ := filepath.Glob(filepath.Join(base, "blkchain", "blk-draft-*.md"))
	if len(matches) != 1 {
		t.Fatalf("draft files in config dir = %v, want exactly one", matches)
	}
	b, err := os.ReadFile(matches[0])
	if err != nil || string(b) != "my draft" {
		t.Fatalf("draft content = %q err %v, want %q", b, err, "my draft")
	}
}

// Cleanup happens on every path, not only the happy one: an editor that exited
// with an error still has its draft removed.
func TestApplyEditorResultRemovesDraftEvenWhenEditorErrored(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "blk-draft-*.md")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()

	m := model{ta: textarea.New()}
	m.applyEditorResult(editorDoneMsg{path: path, before: "x", err: errors.New("editor failed")})

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("draft not removed after editor error: %v", err)
	}
}
