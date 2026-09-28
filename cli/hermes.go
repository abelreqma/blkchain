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

// runHermes runs a one-shot Hermes agent turn with the given prompt. The agent
// has the blkChain KB tools (via the `blkchain` MCP server) plus its own tools,
// so this is the "full agent" counterpart to the API's single-shot RAG answer.
//
// The prompt is passed as a single argv element (never through a shell), so
// query text cannot inject shell commands.
func runHermes(args []string) error {
	prompt := strings.TrimSpace(strings.Join(args, " "))
	if prompt == "" {
		return errors.New("hermes: give me a prompt, e.g.  blk hermes summarize the SSRF notes")
	}

	path, err := exec.LookPath(hermesBin)
	if err != nil {
		return fmt.Errorf("hermes: %q not found on PATH — install Hermes Agent or add it to PATH", hermesBin)
	}

	fmt.Fprintf(os.Stderr, "%s %s\n", dim("→ hermes -z"), dim(truncate(prompt, 60)))
	c := exec.Command(path, "-z", prompt)
	c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := c.Run(); err != nil {
		return fmt.Errorf("hermes: %w", err)
	}
	return nil
}
