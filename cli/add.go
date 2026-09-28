package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// addTypeMap validates and documents the --type values accepted by `blk add`;
// the value is passed straight through to `python -m blkchain.add --type`.
var addTypeMap = map[string]bool{"md": true, "txt": true, "pdf": true}

// addStats is the JSON line printed by `python -m blkchain.add` on success:
// the index.add_path stats plus a "source" label for the success message.
type addStats struct {
	Indexed int    `json:"indexed"`
	Updated int    `json:"updated"`
	Skipped int    `json:"skipped"`
	Batches int    `json:"batches"`
	Source  string `json:"source"`
}

// addArgs is the parsed, validated form of `blk add`'s arguments.
type addArgs struct {
	path   string
	source string
	typ    string // "" (infer), "md", "txt", or "pdf"
}

// parseAddArgs parses and validates `blk add`'s flags/positional (flags may
// appear before or after the path, like every other blk command). It is pure
// (no filesystem or process access) so argument handling can be unit tested
// without shelling out to python.
func parseAddArgs(args []string) (addArgs, error) {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	source := fs.String("source", "", "source label (default: derived from the path)")
	typ := fs.String("type", "", "force chunking as md, txt, or pdf instead of inferring it")
	valueFlags := map[string]bool{"source": true, "type": true}
	if err := fs.Parse(reorder(args, valueFlags)); err != nil {
		return addArgs{}, err
	}

	if fs.NArg() != 1 {
		return addArgs{}, errors.New("add: give me exactly one file, directory, or URL, e.g.  blk add ./my-notes.md")
	}
	if *typ != "" && !addTypeMap[*typ] {
		return addArgs{}, fmt.Errorf("add: --type must be md, txt, or pdf, got %q", *typ)
	}
	return addArgs{path: fs.Arg(0), source: *source, typ: *typ}, nil
}

// runAdd implements `blk add <path|url> [--source NAME] [--type md|txt|pdf]`:
// it loads a file, directory, or http(s) URL into the live Qdrant collection
// by shelling out to the venv's `python -m blkchain.add`, which reuses the
// same chunkers + resumable upsert path as the corpus indexer.
func runAdd(args []string) error {
	a, err := parseAddArgs(args)
	if err != nil {
		return err
	}

	root, err := projectRoot()
	if err != nil {
		return err
	}
	python := filepath.Join(root, ".venv", "bin", "python")
	if _, err := os.Stat(python); err != nil {
		return fmt.Errorf("add: venv python not found at %s — set up the project venv first", python)
	}

	pyArgs := []string{"-m", "blkchain.add", a.path}
	if a.source != "" {
		pyArgs = append(pyArgs, "--source", a.source)
	}
	if a.typ != "" {
		pyArgs = append(pyArgs, "--type", a.typ)
	}

	fmt.Fprintf(os.Stderr, "%s %s\n", Meta.Render(Glyph(GlyphArrow)), Meta.Render("indexing "+a.path+" ..."))

	c := exec.Command(python, pyArgs...)
	c.Dir = root
	c.Env = append(os.Environ(), "PYTHONPATH="+root)
	c.Stderr = os.Stderr // stream progress/errors straight through
	stdout, err := c.StdoutPipe()
	if err != nil {
		return fmt.Errorf("add: %w", err)
	}
	if err := c.Start(); err != nil {
		return fmt.Errorf("add: %w", err)
	}
	line, readErr := lastNonEmptyLine(stdout)
	runErr := c.Wait()

	if runErr != nil {
		if isConnectionRefused(line) || isConnectionRefused(fmt.Sprint(runErr)) {
			return fmt.Errorf("add: the blkChain services aren't reachable — start them with `blk up`")
		}
		return fmt.Errorf("add: %w", runErr)
	}
	if readErr != nil {
		return fmt.Errorf("add: reading python output: %w", readErr)
	}

	var stats addStats
	if err := json.Unmarshal([]byte(line), &stats); err != nil {
		return fmt.Errorf("add: unexpected output from blkchain.add: %s", line)
	}

	fmt.Printf("%s added %d chunk(s) (%d updated, %d skipped) from %s\n",
		OK.Render(Glyph(GlyphOK)), stats.Indexed, stats.Updated, stats.Skipped, Body.Render(stats.Source))
	return nil
}

// lastNonEmptyLine reads all of r and returns its last non-empty line (the
// single JSON stats line blkchain.add prints on success).
func lastNonEmptyLine(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	last := ""
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			last = t
		}
	}
	return last, sc.Err()
}

// isConnectionRefused reports whether s looks like the stack (qdrant / embed
// server) is down, so `blk add` can point at `blk up` instead of a raw
// traceback.
func isConnectionRefused(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, "connection refused") ||
		strings.Contains(low, "connectionerror") ||
		strings.Contains(low, "failed to establish a new connection") ||
		strings.Contains(low, "max retries exceeded")
}
