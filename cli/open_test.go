package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureViewer replaces runViewer for the test and returns a pointer to the
// argv the viewer would receive.
func captureViewer(t *testing.T) *[]string {
	t.Helper()
	var got []string
	orig := runViewer
	runViewer = func(bin string, args []string) error {
		got = args
		return nil
	}
	t.Cleanup(func() { runViewer = orig })
	return &got
}

func TestOpenFilePassesAbsolutePath(t *testing.T) {
	for _, name := range []string{"-oX", "+cmd", "plain.md"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Chdir(dir)
			t.Setenv("PAGER", "sh")
			got := captureViewer(t)

			if err := openFile(name, false); err != nil {
				t.Fatalf("openFile(%q) error = %v", name, err)
			}
			if len(*got) != 1 || !filepath.IsAbs((*got)[0]) || !strings.HasSuffix((*got)[0], string(filepath.Separator)+name) {
				t.Errorf("viewer argv = %q, want one absolute path ending in %q", *got, name)
			}
			if strings.HasPrefix((*got)[0], "-") || strings.HasPrefix((*got)[0], "+") {
				t.Errorf("viewer argv %q can be parsed as an option", *got)
			}
		})
	}
}
