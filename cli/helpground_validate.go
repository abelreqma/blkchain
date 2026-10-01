package main

import "strings"

// proposedOptions is the flag/subcommand surface of a proposed command. Flags
// are value-stripped at "="; Subcommand is the first non-flag positional (""
// when there is none).
type proposedOptions struct {
	Flags      []string
	Subcommand string
}

// extractProposedOptions walks args and separates flags from the subcommand.
// A token starting with "-" (but not bare "-" or "--") is a flag (taken up to
// the first "="); tokens after a bare "--" are positionals, never flags. The
// subcommand candidate is ONLY the first argument, and only when it is a
// non-flag token: a subcommand-style tool leads with its subcommand
// (`git status`, `docker run`). A positional that follows a flag may be that
// flag's value (`docker -H host run`, `git -C /p status`), so it is NOT treated
// as a subcommand, which avoids false-rejecting a value as an unknown
// subcommand. (The cost is that subcommand grounding does not fire when a global
// flag precedes the subcommand; that fails safe.)
func extractProposedOptions(args []string) proposedOptions {
	var p proposedOptions
	if len(args) > 0 && args[0] != "-" && args[0] != "--" && !strings.HasPrefix(args[0], "-") {
		p.Subcommand = args[0]
	}
	afterDashDash := false
	for _, a := range args {
		if afterDashDash {
			continue
		}
		if a == "--" {
			afterDashDash = true
			continue
		}
		if a == "-" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			tok := a
			if i := strings.IndexByte(tok, '='); i >= 0 {
				tok = tok[:i]
			}
			p.Flags = append(p.Flags, tok)
		}
	}
	return p
}

func flagKnown(tok string, flags []string) bool {
	known := func(f string) bool {
		for _, x := range flags {
			if x == f {
				return true
			}
		}
		return false
	}
	if known(tok) {
		return true
	}
	if len(tok) < 2 || !strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, "--") {
		return false
	}
	rest := tok[1:]
	// Bundle: every character is a known short flag.
	allShort := true
	for _, c := range rest {
		if !known("-" + string(c)) {
			allShort = false
			break
		}
	}
	if allShort {
		return true
	}
	// Attached value: -X<value> where -X is known and value has a non-letter
	// (digits/punctuation), which distinguishes a value from a flag bundle.
	prefix := "-" + rest[:1]
	if known(prefix) {
		value := rest[1:]
		if value != "" && hasNonLetter(value) {
			return true
		}
	}
	return false
}

func hasNonLetter(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return true
		}
	}
	return false
}

// validateAgainstInterface returns the proposed flags not known per flagKnown,
// and the subcommand when iface lists subcommands and the proposed one is not
// among them. When iface has no subcommands, the positional is never rejected
// (it is a target/operand, not a subcommand).
func validateAgainstInterface(p proposedOptions, iface toolInterface) (unknownFlags []string, unknownSub string) {
	for _, f := range p.Flags {
		if !flagKnown(f, iface.Flags) {
			unknownFlags = append(unknownFlags, f)
		}
	}
	if len(iface.Subcommands) > 0 && p.Subcommand != "" {
		known := false
		for _, s := range iface.Subcommands {
			if s == p.Subcommand {
				known = true
				break
			}
		}
		if !known {
			unknownSub = p.Subcommand
		}
	}
	return unknownFlags, unknownSub
}
