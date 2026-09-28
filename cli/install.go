package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// runInstall copies the running binary onto PATH as a real file (not a symlink)
// and records the project root so `blk` works from any directory afterward.
func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	dir := fs.String("dir", defaultBinDir(), "directory to install into (should be on PATH)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root, err := discoverRoot()
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}

	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("install: locating current binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(src); err == nil {
		src = resolved
	}

	destDir := expandTilde(*dir)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	dest := filepath.Join(destDir, "blk")
	if err := copyExecutable(src, dest); err != nil {
		return fmt.Errorf("install: %w", err)
	}

	saved, err := saveRoot(root)
	if err != nil {
		return fmt.Errorf("install: saving project root: %w", err)
	}

	fmt.Printf("%s installed %s\n", OK.Render(Glyph(GlyphOK)), Key.Render(dest))
	fmt.Printf("%s project root %s\n", OK.Render(Glyph(GlyphOK)), root)
	fmt.Printf("  %s\n", Meta.Render("(saved to "+saved+")"))
	if !onPath(destDir) {
		fmt.Printf("\n%s %s is not on your PATH. Add it:\n    %s\n",
			Caut.Render(Glyph(GlyphWarn)), destDir, Key.Render(`export PATH="`+destDir+`:$PATH"`))
	} else {
		fmt.Printf("\nRun %s from anywhere.\n", Key.Render("blk help"))
	}
	return nil
}

// defaultBinDir is ~/.local/bin, the conventional user bin directory.
func defaultBinDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".local/bin"
	}
	return filepath.Join(home, ".local", "bin")
}

func expandTilde(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// copyExecutable writes src to dest atomically (temp file + rename), replacing
// any existing file or symlink, so overwriting the running binary's path is safe.
func copyExecutable(src, dest string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".blk-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}
	return os.Rename(tmpName, dest)
}

// onPath reports whether dir is one of the PATH entries.
func onPath(dir string) bool {
	dir = filepath.Clean(dir)
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if filepath.Clean(expandTilde(p)) == dir {
			return true
		}
	}
	return false
}
