package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// hermesBin is the Hermes CLI name; resolved on PATH at call time.
const hermesBin = "hermes"

// pythonUnbufferedEnv returns the current environment with PYTHONUNBUFFERED
// forced to "1" for a Hermes child, which block-buffers its piped stdout
// otherwise. Any inherited PYTHONUNBUFFERED is stripped first so ours wins
// regardless of which duplicate key execve resolves.
func pythonUnbufferedEnv() []string {
	return append(stripEnv(os.Environ(), "PYTHONUNBUFFERED"), "PYTHONUNBUFFERED=1")
}

// runHermes runs a one-shot Hermes agent turn with the given prompt. The agent
// has the blkChain KB tools (via the `blkchain` MCP server) plus its own tools,
// so this is the "full agent" counterpart to blk ask's single-shot RAG answer.
//
// The prompt is passed as a single argv element (never through a shell), so
// query text cannot inject shell commands.
func runHermes(args []string) error {
	prompt := strings.TrimSpace(strings.Join(args, " "))
	if prompt == "" {
		return missingArg("hermes", "missing prompt", `hermes "summarize the SSRF notes"`)
	}

	path, err := exec.LookPath(hermesBin)
	if err != nil {
		return fmt.Errorf("hermes: %q not found on PATH, install Hermes Agent or add it to PATH", hermesBin)
	}

	fmt.Fprintf(os.Stderr, "%s %s\n", Meta.Render(Glyph(GlyphArrow)+" hermes -z"), Meta.Render(ellipsize(prompt, 60)))
	c := exec.Command(path, "-z", prompt)
	c.Stdin = os.Stdin
	// A piped Python child block-buffers stdout, so its output would arrive only
	// at exit and out of order with stderr.
	c.Env = pythonUnbufferedEnv()
	// -z is one-shot and non-interactive, so its output is safe to pipe through
	// the sanitizer.
	canceled, err := runSanitized(c)
	if canceled {
		return errors.New("hermes: canceled")
	}
	if err != nil {
		return fmt.Errorf("hermes: %w", err)
	}
	return nil
}
