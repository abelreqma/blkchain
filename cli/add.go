package main

import (
	"bufio"
	"encoding/json"
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
	var source, typ string
	fs := newFlagSet("add")
	defineAddFlags(fs, &source, &typ)
	valueFlags := map[string]bool{"source": true, "type": true}
	if err := parseFlags(fs, reorder(args, valueFlags)); err != nil {
		return addArgs{}, err
	}

	if fs.NArg() == 0 {
		return addArgs{}, missingArg("add", "missing file, folder, or URL", "add ./my-notes.md")
	}
	if fs.NArg() > 1 {
		return addArgs{}, missingArg("add", fmt.Sprintf("expected one file, folder, or URL, got %d", fs.NArg()), "add ./my-notes.md")
	}
	if typ != "" && !addTypeMap[typ] {
		return addArgs{}, usageErr(`add: --type must be md, txt, or pdf, got %q. Example: blk add ./notes.txt --type txt. See "blk help add".`, typ)
	}
	return addArgs{path: fs.Arg(0), source: source, typ: typ}, nil
}

// defineAddFlags declares `blk add`'s flags.
func defineAddFlags(fs *flag.FlagSet, source, typ *string) {
	fs.StringVar(source, "source", "", "use `NAME` as the source label (default: taken from the path)")
	fs.StringVar(typ, "type", "", "read the input as `TYPE` (md, txt, or pdf) instead of guessing from its name")
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
		return fmt.Errorf("add: venv python not found at %s, set up the project venv first", python)
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
	c.Env = stripEnv(os.Environ(), "PYTHONPATH")
	c.Env = append(c.Env, "PYTHONPATH="+root)
	stderrBuf := &tailBuffer{max: stderrTailBytes}
	// Stream to the operator through the sanitizer, keep a raw tail to inspect.
	stderrTerm := newSanitizingWriter(os.Stderr)
	c.Stderr = io.MultiWriter(stderrTerm, stderrBuf)
	stdout, err := c.StdoutPipe()
	if err != nil {
		return fmt.Errorf("add: %w", err)
	}
	if err := c.Start(); err != nil {
		return fmt.Errorf("add: %w", err)
	}
	line, readErr := lastNonEmptyLine(stdout)
	// The scanner stops early on an over-long line. Drain the rest so the child
	// cannot block on a full pipe and deadlock Wait.
	io.Copy(io.Discard, stdout)
	runErr := c.Wait()
	stderrTerm.Flush()

	if runErr != nil {
		if isConnectionRefused(line) || isConnectionRefused(fmt.Sprint(runErr)) || isConnectionRefused(stderrBuf.String()) {
			return fmt.Errorf("add: the blkChain services aren't reachable, start them with `blk up`")
		}
		return fmt.Errorf("add: %w", runErr)
	}
	if readErr != nil {
		return fmt.Errorf("add: reading python output: %w", readErr)
	}

	var stats addStats
	if err := json.Unmarshal([]byte(line), &stats); err != nil {
		return fmt.Errorf("add: unexpected output from blkchain.add: %s", sanitizeTerminal(line))
	}

	fmt.Printf("%s added %d chunk(s) (%d updated, %d skipped) from %s\n",
		OK.Render(Glyph(GlyphOK)), stats.Indexed, stats.Updated, stats.Skipped, Body.Render(sanitizeTerminal(stats.Source)))
	return nil
}

// stderrTailBytes is how much of the child's stderr runAdd keeps to inspect.
const stderrTailBytes = 64 << 10

// tailBuffer keeps the last max bytes written to it. It holds at most 2*max
// between trims, so memory stays bounded however much the child writes.
type tailBuffer struct {
	max int
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > 2*t.max {
		t.buf = append(t.buf[:0], t.buf[len(t.buf)-t.max:]...)
	}
	return len(p), nil
}

// String returns at most the last max bytes written.
func (t *tailBuffer) String() string {
	if len(t.buf) > t.max {
		return string(t.buf[len(t.buf)-t.max:])
	}
	return string(t.buf)
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

// stripEnv returns a copy of env with any existing "key=..." entry removed,
// so callers can append a fresh value without duplicating it.
func stripEnv(env []string, key string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env))
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return out
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
