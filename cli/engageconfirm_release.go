package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"blkchain/cli/internal/askuser"
	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

// engageconfirm_release.go is a terminal-release HITL confirmer for the TUI
// engagement. A Bubble Tea overlay depends on key events reaching the event loop
// while the engagement runs as a long command, which is unreliable in some
// terminals. This confirmer instead releases the program's terminal hold, prints
// the command and a y/e/n/q prompt, reads the operator's answer with a plain
// blocking stdin line-read (the mechanism the standalone `blk engage` confirmer
// uses), then restores the TUI. The engagement keeps running inside the TUI; only
// the confirmation is a plain prompt.

// terminalReleaser is the subset of *tea.Program the release confirmer needs.
type terminalReleaser interface {
	ReleaseTerminal() error
	RestoreTerminal() error
}

// releaseConfirmer is the TUI secgate.EditConfirmer that reads over a released
// terminal. stop cancels the engagement on a deny-and-stop answer; a nil prog or
// stop degrades safely (deny, no cancel).
type releaseConfirmer struct {
	prog terminalReleaser
	in   io.Reader
	out  io.Writer
	stop func()
}

var _ secgate.EditConfirmer = releaseConfirmer{}

func (c releaseConfirmer) Confirm(ctx context.Context, cmd secgate.Command) bool {
	allow, _ := c.ConfirmOrEdit(ctx, cmd)
	return allow
}

func (c releaseConfirmer) ConfirmOrEdit(_ context.Context, cmd secgate.Command) (bool, *secgate.Command) {
	if c.prog == nil {
		return false, nil
	}
	_ = c.prog.ReleaseTerminal()
	defer func() { _ = c.prog.RestoreTerminal() }()
	in := c.in
	if in == nil {
		in = os.Stdin
	}
	out := c.out
	if out == nil {
		out = os.Stdout
	}
	allow, edited, stop := promptConfirm(bufio.NewReader(in), out, cmd)
	if stop && c.stop != nil {
		c.stop()
	}
	return allow, edited
}

// promptConfirm prints the command and reads one line: y allows, e edits (reads a
// second line; a blank or unparsable edit denies), n denies, q denies and stops.
// EOF or anything else denies. The command is sanitized before printing (model
// args are untrusted). It returns (allow, edited, stop).
func promptConfirm(r *bufio.Reader, out io.Writer, cmd secgate.Command) (bool, *secgate.Command, bool) {
	fmt.Fprintf(out, "\nconfirm command: %s\n", sanitizeTerminal(commandLine(cmd)))
	if cl := confirmContextLine(cmd); cl != "" {
		fmt.Fprintf(out, "  %s\n", sanitizeTerminal(cl))
	}
	if cmd.PoCIsInterpreter {
		fmt.Fprintf(out, "  interpreter PoC sha256 %s\n", sanitizeTerminal(cmd.PoCHash))
	}
	fmt.Fprint(out, "[y] allow  [e] edit  [n] deny  [q] deny & stop: ")
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return false, nil, false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil, false
	case "e", "edit":
		fmt.Fprintf(out, "edit command, then enter: %s\n> ", sanitizeTerminal(commandLine(cmd)))
		el, _ := r.ReadString('\n')
		if c, ok := parseEditedCommand(strings.TrimRight(el, "\r\n")); ok {
			return true, &c, false
		}
		return false, nil, false
	case "q", "stop":
		return false, nil, true
	default:
		return false, nil, false
	}
}

// releaseAsker reads a mid-engagement clarification over a released terminal, the
// same reliable line-input path as releaseConfirmer. It is the Safe-mode asker so
// the orchestrator's follow-up questions work in any terminal; a nil prog cancels.
type releaseAsker struct {
	prog terminalReleaser
	in   io.Reader
	out  io.Writer
}

var _ askuser.Asker = releaseAsker{}

func (a releaseAsker) Ask(_ context.Context, c askuser.Clarification) askuser.ClarifyResult {
	if a.prog == nil {
		return askuser.ClarifyResult{Canceled: true}
	}
	_ = a.prog.ReleaseTerminal()
	defer func() { _ = a.prog.RestoreTerminal() }()
	in := a.in
	if in == nil {
		in = os.Stdin
	}
	out := a.out
	if out == nil {
		out = os.Stdout
	}
	return newTerminalAsker(in, out).Ask(context.Background(), c)
}

// releaseArmRequester puts the at-exploit arm decision to the operator over a
// released terminal. A nil prog fails safe to ArmSkip (do not arm).
type releaseArmRequester struct {
	prog terminalReleaser
	in   io.Reader
	out  io.Writer
}

var _ ArmRequester = releaseArmRequester{}

func (a releaseArmRequester) RequestArm(_ context.Context, task eng.Task) ArmDecision {
	if a.prog == nil {
		return ArmSkip
	}
	_ = a.prog.ReleaseTerminal()
	defer func() { _ = a.prog.RestoreTerminal() }()
	in := a.in
	if in == nil {
		in = os.Stdin
	}
	out := a.out
	if out == nil {
		out = os.Stdout
	}
	return promptArm(bufio.NewReader(in), out, task)
}

// promptArm prints the unarmed exploit task and reads one line: y arms, q stops
// the engagement, anything else (including EOF) skips. Arming is operator-only.
func promptArm(r *bufio.Reader, out io.Writer, task eng.Task) ArmDecision {
	label := strings.TrimSpace(task.Kind + ": " + task.Objective)
	fmt.Fprintf(out, "\narm exploit task: %s\n", sanitizeTerminal(label))
	fmt.Fprint(out, "the engagement reached armed exploitation; arming is operator-only\n[y] arm  [n] skip  [q] stop: ")
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return ArmSkip
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return ArmApprove
	case "q", "stop":
		return ArmStop
	default:
		return ArmSkip
	}
}
