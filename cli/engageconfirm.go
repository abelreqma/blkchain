package main

import (
	"strings"

	"blkchain/cli/internal/secgate"
)

// commandLine renders a Command as a single editable argv line (binary then its
// literal args, space-joined) for the terminal prompt.
func commandLine(c secgate.Command) string {
	return strings.TrimSpace(c.Binary + " " + strings.Join(c.Args, " "))
}

// parseEditedCommand splits a typed line into a bare binary and literal args,
// shell-free (plain whitespace, no quoting or metacharacter interpretation, the
// same structured shape run_command takes). ok is false for a blank line. It sets
// no tier context: the gate inherits the original command's Phase/Surface/Armed on
// an edit, and re-validates the result (metacharacters and scope included).
func parseEditedCommand(line string) (secgate.Command, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return secgate.Command{}, false
	}
	return secgate.Command{Binary: fields[0], Args: fields[1:]}, true
}

// confirmContextLine summarizes the engagement tier context the gate derived the
// command under: phase, surface, and whether exploitation is armed. Empty when
// there is nothing to show (recon, no surface, unarmed).
func confirmContextLine(c secgate.Command) string {
	var parts []string
	if p := string(c.Phase); p != "" {
		parts = append(parts, "phase "+p)
	}
	if s := string(c.Surface); s != "" {
		parts = append(parts, "surface "+s)
	}
	if c.Armed {
		parts = append(parts, "armed")
	}
	return strings.Join(parts, "  ")
}
