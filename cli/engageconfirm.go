package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"blkchain/cli/internal/secgate"
)

// engageconfirm.go is the gate confirmation overlay for a REPL engagement: the
// human-in-the-loop prompt the secgate.Gate puts to the operator before a command
// runs. It mirrors clarify.go's channel bridge. The orchestrator goroutine calls
// widgetConfirmer (a secgate.EditConfirmer); it posts a confirmMsg to the event
// loop and blocks on a reply channel. The base Update opens a confirmPicker and,
// on resolve, answers the channel exactly once (including the displaced case).
//
// The gate's EditConfirmer contract is ONE-SHOT: ConfirmOrEdit returns (allow,
// edited). On an operator edit the gate re-validates the substitute through the
// full deny pipeline with the original Phase/Surface/Armed inherited, and a failed
// re-check comes back to the engagement as a terminal deny (the gate does not
// re-invoke the confirmer). So the overlay does not loop on a re-check denial.

// confirmResult is the operator's answer. allow runs the command; edited (when
// non-nil) substitutes a re-typed command the gate re-validates; stop both denies
// and cancels the running engagement turn (esc).
type confirmResult struct {
	allow  bool
	edited *secgate.Command
	stop   bool
}

// confirmMsg asks the base Update to open a confirm overlay for cmd and answer on
// reply. Posted by widgetConfirmer from the orchestrator goroutine.
type confirmMsg struct {
	cmd   secgate.Command
	reply chan confirmResult
}

// confirmResolvedMsg is emitted by the picker on a key resolve. The base Update
// sends res on reply, closes the overlay, and (on stop) cancels the turn.
type confirmResolvedMsg struct {
	res   confirmResult
	reply chan confirmResult
}

// progSender is the subset of *tea.Program the confirmer needs: posting a message
// into the event loop from a goroutine. *tea.Program satisfies it.
type progSender interface{ Send(tea.Msg) }

// widgetConfirmer is the TUI secgate.EditConfirmer: it bridges the gate's blocking
// confirm call to the confirm overlay over the event loop. A nil prog fails closed.
type widgetConfirmer struct{ prog progSender }

// widgetConfirmer must satisfy EditConfirmer so the gate's type-switch takes the
// edit path, not the plain bool Confirmer fallback.
var _ secgate.EditConfirmer = widgetConfirmer{}

// Confirm answers allow/deny only (the plain secgate.Confirmer contract).
func (w widgetConfirmer) Confirm(ctx context.Context, c secgate.Command) bool {
	allow, _ := w.ConfirmOrEdit(ctx, c)
	return allow
}

// ConfirmOrEdit posts a confirm overlay and blocks for the operator's answer. A
// canceled context or a nil program fails closed (deny, no edit).
func (w widgetConfirmer) ConfirmOrEdit(ctx context.Context, c secgate.Command) (bool, *secgate.Command) {
	if w.prog == nil {
		return false, nil
	}
	reply := make(chan confirmResult, 1)
	w.prog.Send(confirmMsg{cmd: c, reply: reply})
	select {
	case r := <-reply:
		return r.allow, r.edited
	case <-ctx.Done():
		return false, nil
	}
}

// commandLine renders a Command as a single editable argv line (binary then its
// literal args, space-joined). It is the prefill for the edit field and the body
// of the prompt.
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

// confirmPicker is the y/e/n/esc confirm overlay. editing opens a prefilled edit
// field for an operator substitute.
type confirmPicker struct {
	cmd     secgate.Command
	reply   chan confirmResult
	input   textinput.Model
	editing bool
}

func newConfirmPicker(cmd secgate.Command, width int, reply chan confirmResult) confirmPicker {
	ti := textinput.New()
	ti.Prompt = Glyph(GlyphPrompt) + " "
	ti.CharLimit = 4000
	ti.SetValue(commandLine(cmd))
	ti.CursorEnd()
	return confirmPicker{cmd: cmd, reply: reply, input: ti}
}

// --- side-effect-free seams ---

func (p confirmPicker) allow() confirmResult { return confirmResult{allow: true} }
func (p confirmPicker) deny() confirmResult  { return confirmResult{} }
func (p confirmPicker) stop() confirmResult  { return confirmResult{stop: true} }

// editResult parses the edit field into an allowed substitute. ok is false for a
// blank line, so the caller keeps the field open.
func (p confirmPicker) editResult() (confirmResult, bool) {
	c, ok := parseEditedCommand(p.input.Value())
	if !ok {
		return confirmResult{}, false
	}
	return confirmResult{allow: true, edited: &c}, true
}

// --- overlayModel ---

func (p confirmPicker) resolve(res confirmResult) tea.Cmd {
	reply := p.reply
	return func() tea.Msg { return confirmResolvedMsg{res: res, reply: reply} }
}

func (p confirmPicker) Update(msg tea.Msg) (overlayModel, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	if p.editing {
		switch km.String() {
		case "esc":
			p.editing = false
			p.input.Blur()
			return p, nil
		case "enter":
			if res, ok := p.editResult(); ok {
				return p, p.resolve(res)
			}
			return p, nil // a blank edit stays in the field
		}
		var cmd tea.Cmd
		p.input, cmd = p.input.Update(msg)
		return p, cmd
	}
	switch km.String() {
	case "y", "Y":
		return p, p.resolve(p.allow())
	case "n", "N":
		return p, p.resolve(p.deny())
	case "esc":
		return p, p.resolve(p.stop())
	case "e", "E":
		p.editing = true
		return p, p.input.Focus()
	}
	return p, nil
}

func (p confirmPicker) View(width, height int) string {
	argv := sanitizeTerminal(commandLine(p.cmd))
	ctxLine := confirmContextLine(p.cmd)
	poc := p.cmd.PoCIsInterpreter && !p.editing
	title := "confirm command"
	wantRows := 2
	if poc {
		// An interpreter PoC shows its plan + read-only script body; give it room
		// (overlayBox still fits it to the terminal height).
		title = "confirm interpreter PoC"
		wantRows = 24
	}
	body := func(w, rows int) string {
		if p.editing {
			p.input.Width = max(w-3, 1)
			head := Meta.Render("edit the command, then enter to re-check and run:")
			return head + "\n" + p.input.View()
		}
		lines := []string{Key.Render(ellipsize(argv, w))}
		if ctxLine != "" && rows > len(lines) {
			lines = append(lines, Meta.Render(ellipsize(ctxLine, w)))
		}
		if poc {
			lines = append(lines, pocPlanLines(p.cmd, w, rows-len(lines))...)
		}
		return strings.Join(lines, "\n")
	}
	return overlayBox(overlaySpec{title: title, wantW: 72, wantRows: wantRows, body: body}, width, height)
}

// pocPlanLines renders the interpreter-PoC plan beneath the command line: the
// sha256 and the read-only script body, within rows available lines. The body is
// already capped executor-side; it is capped again to the overlay height here and
// sanitized per line (it is model-generated script text, so a raw terminal escape
// must never reach the screen). A truncated body notes the remaining line count.
func pocPlanLines(c secgate.Command, width, rows int) []string {
	if rows < 1 {
		return nil
	}
	out := []string{Meta.Render(ellipsize("sha256 "+c.PoCHash, width))}
	if rows <= len(out) {
		return out
	}
	out = append(out, Meta.Render("script (read-only):"))
	avail := rows - len(out)
	if avail < 1 {
		return out
	}
	bodyLines := strings.Split(strings.TrimRight(c.PoCBody, "\n"), "\n")
	shown, truncated := bodyLines, 0
	if len(bodyLines) > avail {
		keep := max(avail-1, 1) // reserve a row for the "+N more" note
		shown, truncated = bodyLines[:keep], len(bodyLines)-keep
	}
	for _, ln := range shown {
		out = append(out, Body.Render(ellipsize(sanitizeTerminal(ln), width)))
	}
	if truncated > 0 {
		out = append(out, Meta.Render(fmt.Sprintf("+%d more lines (full script in the audit log)", truncated)))
	}
	return out
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
