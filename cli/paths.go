package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// rootMarker is the file whose presence identifies a blkChain project root.
// It is a stable, always-present root file so the marker survives even after
// scripts/ is removed (the stack is now orchestrated natively in stack.go).
const rootMarker = "pyproject.toml"

func privateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

// validRoot reports whether dir looks like the blkChain project root.
func validRoot(dir string) bool {
	if dir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, rootMarker))
	return err == nil
}

// candidateRoots returns possible project roots, best first. When includeSaved
// is true the path saved by `blk install` is consulted; install itself passes
// false so it never depends on a stale config while (re)installing.
func candidateRoots(includeSaved bool) []string {
	var roots []string
	if r := os.Getenv("BLKCHAIN_ROOT"); r != "" {
		roots = append(roots, r)
	}
	if includeSaved {
		if r := readSavedRoot(); r != "" {
			roots = append(roots, r)
		}
	}
	// Resolve the real binary (os.Executable returns the symlink itself) and
	// look at its dir and parent: <root>/cli/blk, or a binary beside the root.
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		d := filepath.Dir(exe)
		roots = append(roots, filepath.Dir(d), d)
	}
	// Walk up from the working dir so blk works anywhere inside the tree.
	if wd, err := os.Getwd(); err == nil {
		for dir := wd; ; {
			roots = append(roots, dir)
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return roots
}

var errNoRoot = errors.New(
	"cannot locate the blkChain project: install once with `blk install` from the project, " +
		"or set BLKCHAIN_ROOT to the project root")

// projectRoot finds the blkChain project root using every strategy, including
// the saved config, and validates it still exists (self-healing if it moved).
func projectRoot() (string, error) {
	for _, r := range candidateRoots(true) {
		if validRoot(r) {
			return filepath.Clean(r), nil
		}
	}
	return "", errNoRoot
}

// discoverRoot is projectRoot without the saved config — used by `blk install`
// to record where the binary was installed from.
func discoverRoot() (string, error) {
	for _, r := range candidateRoots(false) {
		if validRoot(r) {
			return filepath.Clean(r), nil
		}
	}
	return "", errNoRoot
}

// configPath returns ~/.config/blkchain/root (honoring XDG_CONFIG_HOME).
func configPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "blkchain", "root"), nil
}

// readSavedRoot returns the project root saved by `blk install`, or "".
func readSavedRoot() string {
	p, err := configPath()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// saveRoot persists the project root for later invocations from anywhere.
func saveRoot(root string) (string, error) {
	p, err := configPath()
	if err != nil {
		return "", err
	}
	if err := privateDir(filepath.Dir(p)); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, []byte(root+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.Chmod(p, 0o600); err != nil {
		return "", err
	}
	return p, nil
}
