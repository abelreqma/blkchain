package main

import (
	"context"
	"path"
	"strings"
	"time"

	"blkchain/cli/internal/secgate"
)

// Help-grounding (anti-hallucination). Before an executor runs a binary with a
// flag or subcommand it has not verified, the run_command tool grounds the
// command against the tool's real interface read from its own help output and
// cached by binary+version. A proposed flag absent from the tool's help is
// rejected and re-grounded rather than executed. This file holds the shared
// types and seams; the sqlite cache, the help parser, the version fingerprint,
// the validation logic, and the grounder orchestration live in the sibling
// helpground_*.go files.

// toolInterface is a tool's learned interface: the flag tokens and subcommands
// seen in its help output. Flags include their leading dashes (for example
// "--script", "-sV"); subcommands are bare words (for example "clone").
type toolInterface struct {
	Flags       []string
	Subcommands []string
}

// groundOutcome is the grounding verdict for one proposed command. Reject==true
// means do not execute; Msg carries the re-ground message (the real interface).
// Reject==false with a non-empty Msg is an advisory note to prepend to the
// allowed command's output (grounding could not verify the command but fails
// open to the gate). The zero value means allow silently.
type groundOutcome struct {
	Reject bool
	Msg    string
}

// toolHelpCache stores and retrieves learned tool interfaces keyed by binary and
// version, so a tool's help is read once and reused across engagements. The
// sqlite backing is sqlToolHelpCache in helpground_cache.go.
type toolHelpCache interface {
	Lookup(binary, version string) (iface toolInterface, hit bool, err error)
	Store(binary, version string, iface toolInterface) error
}

// helpSideEffectBinaries is the per-binary escape hatch: binaries whose --help
// (or help) run has side effects and therefore must NOT be executed for
// grounding. It is empty by default (no known offenders); the mechanism
// exists so a risky binary can be added here. Keyed by base name.
var helpSideEffectBinaries = map[string]bool{}

// isHelpSideEffect reports whether binary is in the escape-hatch set, matching on
// the base name so a path-qualified binary is covered too.
func isHelpSideEffect(binary string) bool {
	return helpSideEffectBinaries[path.Base(binary)]
}

// maxListedFlags caps how many of a tool's flags a reject message lists, to keep
// the re-ground message readable.
const maxListedFlags = 40

// Help capture is bounded tightly: help should be near-instant, so a short
// timeout and a modest output cap keep a misbehaving binary from stalling or
// flooding the grounder.
const (
	helpCaptureTimeout  = 20 * time.Second
	helpCaptureCapBytes = 256 << 10
)

// helpCaptureForms are the help invocations tried in order. -h is deliberately
// omitted: for some tools it means "host" (nikto) rather than help, so --help
// (then the help subcommand) is the safe universal.
var helpCaptureForms = [][]string{{"--help"}, {"help"}}

// newTaskGrounder builds the help-grounder for one executor task. It returns nil
// (grounding disabled) when the cache or gate is nil. Capture runs each help
// form through the gate (authorizeCommand honors LOCAL HITL and the denylists)
// and execRunner, returning the first non-empty output. The help command
// carries the task's phase/surface/armed so it tiers like the task.
func newTaskGrounder(cache toolHelpCache, g *secgate.Gate, workDir string, cmdCtx secgate.Command) *helpGrounder {
	if cache == nil || g == nil {
		return nil
	}
	capture := func(ctx context.Context, binary string) (string, bool) {
		for _, form := range helpCaptureForms {
			hc := secgate.Command{Binary: binary, Args: form, Phase: cmdCtx.Phase, Surface: cmdCtx.Surface, Armed: cmdCtx.Armed, Kind: cmdCtx.Kind, Target: cmdCtx.Target}
			// authorizeCommand now returns the authorized (possibly operator-edited)
			// command; a help read is not edited in practice, so run the form as
			// authorized and ignore any substitution.
			if _, msg := authorizeCommand(ctx, g, hc); msg != "" {
				continue // this help form was gate-denied; try the next
			}
			if g.Audit != nil {
				g.Audit("exec", secgate.Signature(hc))
			}
			res := execRunner(ctx, binary, form, workDir, helpCaptureCapBytes, helpCaptureTimeout)
			if res.TimedOut {
				continue
			}
			if strings.TrimSpace(res.Output) != "" {
				return res.Output, true
			}
		}
		return "", false
	}
	return &helpGrounder{
		Cache:          cache,
		Capture:        capture,
		ResolveVersion: resolveBinVersion,
		Parse:          parseToolHelp,
	}
}

// helpGrounder grounds a proposed command against a tool's real interface before
// it executes. Every field is a seam: Capture runs the tool's help through the
// gate (set by the executor), while ResolveVersion and Parse default to the
// package functions and are overridable in tests.
type helpGrounder struct {
	Cache          toolHelpCache
	Capture        func(ctx context.Context, binary string) (string, bool)
	ResolveVersion func(binary string) string
	Parse          func(string) toolInterface
}

// ground returns the grounding verdict for one command. A nil grounder (or nil
// cache) returns the zero outcome (allow; grounding disabled). The flow: skip
// the escape-hatch binaries and commands with nothing to validate; resolve the
// version; look the interface up; on a miss, capture and parse help (caching a
// parseable result); then validate the proposed flags/subcommand. An invented
// flag or subcommand is rejected with the real interface so the next proposal is
// grounded. A cache error, a failed help read, or unparseable help fails open to
// the gate with an advisory note rather than blocking a legitimate command.
func (hg *helpGrounder) ground(ctx context.Context, cmd secgate.Command) groundOutcome {
	if hg == nil || hg.Cache == nil {
		return groundOutcome{}
	}
	base := path.Base(cmd.Binary)
	if isHelpSideEffect(cmd.Binary) {
		return groundOutcome{}
	}
	p := extractProposedOptions(cmd.Args)
	if len(p.Flags) == 0 && p.Subcommand == "" {
		return groundOutcome{}
	}

	ver := hg.ResolveVersion(cmd.Binary)
	iface, hit, err := hg.Cache.Lookup(cmd.Binary, ver)
	if err != nil {
		return groundOutcome{Msg: "tool-help cache unavailable for " + base + "; proceeding ungrounded"}
	}
	if !hit {
		if len(p.Flags) == 0 {
			// Only a positional and the tool is unknown: do not read help just to
			// check a target/operand. Subcommand grounding applies once the tool
			// is cached (seen via a flagged command).
			return groundOutcome{}
		}
		out, ok := hg.Capture(ctx, cmd.Binary)
		if !ok {
			return groundOutcome{Msg: "could not read --help for " + base + " (gate denied or no output); proceeding ungrounded - verify the flags are real or add it to the help escape hatch"}
		}
		iface = hg.Parse(out)
		if len(iface.Flags) == 0 && len(iface.Subcommands) == 0 {
			return groundOutcome{Msg: "help for " + base + " produced no parseable interface; proceeding ungrounded - review the command, try '" + base + " help', or inspect the tool manually"}
		}
		// Best-effort cache; a store error does not block validation.
		_ = hg.Cache.Store(cmd.Binary, ver, iface)
	}

	unknownFlags, unknownSub := validateAgainstInterface(p, iface)
	if len(unknownFlags) == 0 && unknownSub == "" {
		return groundOutcome{}
	}
	return groundOutcome{Reject: true, Msg: groundRejectMessage(base, unknownFlags, unknownSub, iface)}
}

// groundRejectMessage builds the re-ground message: it names the offending
// flags/subcommand and lists the tool's real interface so the model's next
// proposal uses only options the tool accepts.
func groundRejectMessage(base string, unknownFlags []string, unknownSub string, iface toolInterface) string {
	var b strings.Builder
	b.WriteString("run_command grounded-reject: ")
	b.WriteString(base)
	if len(unknownFlags) > 0 {
		b.WriteString(" does not accept flag(s) ")
		b.WriteString(strings.Join(unknownFlags, " "))
		b.WriteString(".")
	}
	if unknownSub != "" {
		b.WriteString(" ")
		b.WriteString(base)
		b.WriteString(" has no subcommand ")
		b.WriteString(unknownSub)
		b.WriteString(".")
	}
	if len(iface.Flags) > 0 {
		listed := iface.Flags
		if len(listed) > maxListedFlags {
			listed = listed[:maxListedFlags]
		}
		b.WriteString(" Known flags: ")
		b.WriteString(strings.Join(listed, " "))
		b.WriteString(".")
	}
	if len(iface.Subcommands) > 0 {
		b.WriteString(" Known subcommands: ")
		b.WriteString(strings.Join(iface.Subcommands, " "))
		b.WriteString(".")
	}
	b.WriteString(" Re-propose using only options this tool accepts.")
	return b.String()
}
