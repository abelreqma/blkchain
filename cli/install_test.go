package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndReadRoot(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)

	saved, err := saveRoot("/projects/blkChain")
	if err != nil {
		t.Fatalf("saveRoot: %v", err)
	}
	if want := filepath.Join(cfg, "blkchain", "root"); saved != want {
		t.Errorf("saved path = %q, want %q", saved, want)
	}
	if got := readSavedRoot(); got != "/projects/blkChain" {
		t.Errorf("readSavedRoot = %q, want %q", got, "/projects/blkChain")
	}
}

func TestValidRoot(t *testing.T) {
	root := t.TempDir()
	if validRoot(root) {
		t.Fatal("empty dir should not be a valid root")
	}
	if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte("[project]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !validRoot(root) {
		t.Error("dir with pyproject.toml should be a valid root")
	}
}

func TestCopyExecutableReplacesSymlink(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Pre-existing symlink at dest must be replaced by a real file.
	dest := filepath.Join(dir, "blk")
	if err := os.Symlink(src, dest); err != nil {
		t.Fatal(err)
	}

	if err := copyExecutable(src, dest); err != nil {
		t.Fatalf("copyExecutable: %v", err)
	}
	fi, err := os.Lstat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Error("dest is still a symlink")
	}
	if fi.Mode().Perm()&0o100 == 0 {
		t.Error("dest is not executable")
	}
	if data, _ := os.ReadFile(dest); string(data) != "BINARY" {
		t.Errorf("dest contents = %q, want %q", data, "BINARY")
	}
}

func TestOnPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+"/usr/bin")
	if !onPath(dir) {
		t.Errorf("onPath(%q) = false, want true", dir)
	}
	if onPath("/nowhere/at/all") {
		t.Error("onPath(/nowhere/at/all) = true, want false")
	}
}

func TestExpandTilde(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	if got := expandTilde("~/bin"); got != "/home/tester/bin" {
		t.Errorf("expandTilde(~/bin) = %q, want /home/tester/bin", got)
	}
	if got := expandTilde("/abs/path"); got != "/abs/path" {
		t.Errorf("expandTilde left an absolute path unchanged incorrectly: %q", got)
	}
}
