package main

import (
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
	var edit bool
	fs := newFlagSet("open")
	defineOpenFlags(fs, &edit)
	if err := parseFlags(fs, reorder(args, nil)); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return missingArg("open", "missing file path", "open sources/notes/ssrf.md")
	}
	return openFile(fs.Arg(0), edit)
}

// defineOpenFlags declares `blk open`'s flags.
func defineOpenFlags(fs *flag.FlagSet, edit *bool) {
	fs.BoolVar(edit, "edit", false, "open in your editor ($EDITOR) instead of the pager")
}

// openFile resolves path (absolute, or relative to CWD then project root) and
// opens it. An http(s) URL only prints the web notice. When edit is true it uses $EDITOR; otherwise $PAGER, falling back
// to less. The file path is passed as an argv element, never via a shell.
func openFile(path string, edit bool) error {
	// A web result is never launched or fetched: say so and show the URL, the
	// same answer the TUI /open gives.
	if isWebURL(path) {
		fmt.Println(openWebNotice(path))
		return nil
	}
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
		return fmt.Errorf("open: %q not found, set $%s", viewer, pagerOrEditor(edit))
	}
	// A CWD-relative path can start with "-" or "+" and would reach the viewer
	// as an option (less -oX, vi +cmd). An absolute path always starts with "/".
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	return runViewer(bin, []string{abs})
}

// runViewer runs the pager or editor on the terminal. It is a variable so tests
// can capture the argv.
var runViewer = func(bin string, args []string) error {
	c := exec.Command(bin, args...)
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
