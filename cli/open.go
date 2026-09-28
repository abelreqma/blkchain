package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// runOpen opens a source file in a pager (or $EDITOR with --edit). The path may
// be absolute or relative to the project root, so a `Path` printed by
// `blk search` (e.g. sources/foo.md) can be opened verbatim.
func runOpen(args []string) error {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	edit := fs.Bool("edit", false, "open in $EDITOR instead of the pager")
	if err := fs.Parse(reorder(args, nil)); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("open: give me a file path, e.g.  blk open sources/notes/ssrf.md")
	}
	return openFile(fs.Arg(0), *edit)
}

// openFile resolves path (absolute, or relative to CWD then project root) and
// opens it. When edit is true it uses $EDITOR; otherwise $PAGER, falling back
// to less. The file path is passed as an argv element, never via a shell.
func openFile(path string, edit bool) error {
	resolved, err := resolveSourcePath(path)
	if err != nil {
		return err
	}

	var viewer string
	if edit {
		viewer = firstNonEmpty(os.Getenv("EDITOR"), os.Getenv("VISUAL"), "vi")
	} else {
		viewer = firstNonEmpty(os.Getenv("PAGER"), "less")
	}

	bin, lookErr := exec.LookPath(viewer)
	if lookErr != nil {
		return fmt.Errorf("open: %q not found — set $%s", viewer, pagerOrEditor(edit))
	}
	c := exec.Command(bin, resolved)
	c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
	return c.Run()
}

// resolveSourcePath returns an existing file path for the given input, trying it
// as-is (absolute or CWD-relative) and then relative to the project root.
func resolveSourcePath(path string) (string, error) {
	if filepath.IsAbs(path) {
		if fileExists(path) {
			return path, nil
		}
		return "", fmt.Errorf("open: no such file: %s", path)
	}
	if fileExists(path) {
		return path, nil
	}
	if root, err := projectRoot(); err == nil {
		cand := filepath.Join(root, path)
		if fileExists(cand) {
			return cand, nil
		}
	}
	return "", fmt.Errorf("open: no such file: %s", path)
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func pagerOrEditor(edit bool) string {
	if edit {
		return "EDITOR"
	}
	return "PAGER"
}
