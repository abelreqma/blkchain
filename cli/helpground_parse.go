package main

import (
	"regexp"
	"strings"
)

// reHelpFlag matches a normalized flag token: one or two leading dashes, then a
// letter, then letters/digits/dashes. A bare "-" or a numeric-only token does
// not match.
var reHelpFlag = regexp.MustCompile(`^--?[A-Za-z][A-Za-z0-9-]*$`)

// reHelpSubHeader matches a help line that introduces a subcommand list.
var reHelpSubHeader = regexp.MustCompile(`(?i)^((sub)?commands|available commands):?$`)

// reHelpSubWord matches a lowercase subcommand name.
var reHelpSubWord = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// parseToolHelp scans help text and returns the flag tokens and subcommands it
// can recover. It is permissive by design: any flag the tool documents anywhere
// in its help becomes "known", so a real flag is rarely rejected while an
// invented one (absent from help) is caught. Flag recovery tokenizes on
// whitespace (so adjacent flags like "-a -b" are both seen) and strips wrapping
// brackets, an attached "=value", and trailing punctuation. Subcommand recovery
// is best-effort: it reads the indented words under a "Commands:"-style header.
func parseToolHelp(help string) toolInterface {
	var iface toolInterface

	seenFlag := map[string]bool{}
	for _, tok := range strings.Fields(help) {
		// Split slash-grouped flag tokens (nmap documents "-oN/-oX/-oS/-oG <file>"
		// as one token) so each grouped flag is recovered, not rejected whole.
		for _, piece := range strings.Split(tok, "/") {
			f := normalizeHelpFlagToken(piece)
			if f == "" || seenFlag[f] {
				continue
			}
			seenFlag[f] = true
			iface.Flags = append(iface.Flags, f)
		}
	}

	seenSub := map[string]bool{}
	inSection := false
	for _, ln := range strings.Split(help, "\n") {
		trimmed := strings.TrimSpace(ln)
		if !inSection {
			if reHelpSubHeader.MatchString(trimmed) {
				inSection = true
			}
			continue
		}
		if trimmed == "" {
			break
		}
		if ln[0] != ' ' && ln[0] != '\t' {
			break // a non-indented line ends the section
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		w := fields[0]
		if reHelpSubWord.MatchString(w) && !seenSub[w] {
			seenSub[w] = true
			iface.Subcommands = append(iface.Subcommands, w)
		}
	}
	return iface
}

// normalizeHelpFlagToken turns a raw help token into a flag token, or "" when it
// is not a flag. It strips wrapping "([" / "]).,:;", cuts an attached "=value",
// and validates the remainder as a flag.
func normalizeHelpFlagToken(tok string) string {
	tok = strings.TrimLeft(tok, "([")
	if i := strings.IndexByte(tok, '='); i >= 0 {
		tok = tok[:i]
	}
	tok = strings.TrimRight(tok, ").,:;]")
	if !strings.HasPrefix(tok, "-") {
		return ""
	}
	if !reHelpFlag.MatchString(tok) {
		return ""
	}
	return tok
}
