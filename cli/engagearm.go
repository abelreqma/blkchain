package main

import (
	"context"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	eng "blkchain/cli/internal/engagement"
)

// engagearm.go is the operator arm gate for a REPL engagement: the mandatory
// human-in-the-loop prompt the exploit executor raises (ArmRequester.RequestArm)
// before an unarmed exploit/post-ex task runs, in Safe AND Auto. It mirrors the
// confirm overlay's channel bridge (engageconfirm.go). The model never arms; only
// the operator's ArmApprove causes armTask, so model-cannot-arm holds.
//
// Wiring: runTUI calls SetReplArmRequester(widgetArmRequester{prog}) once, so
// runReplEngage reads it onto deps.ArmReq. A nil requester (or a nil prog) fails
// safe: the exploit task's commands are gate-denied and nothing runs.

// armMsg asks the base Update to open the arm overlay for task and answer on
// reply. Posted by widgetArmRequester from the orchestrator goroutine.
type armMsg struct {
	task  eng.Task
	reply chan ArmDecision
}

// armResolvedMsg is emitted by the arm overlay on a key resolve. The base Update
// sends res on reply, closes the overlay, and (on ArmStop) cancels the turn.
type armResolvedMsg struct {
	res   ArmDecision
	reply chan ArmDecision
}

// widgetArmRequester is the TUI ArmRequester: it bridges the at-exploit arm gate
// to the arm overlay over the event loop. A nil prog, or a canceled context, fails
// safe (ArmSkip): arming never happens by default.
type widgetArmRequester struct{ prog progSender }

// widgetArmRequester must satisfy ArmRequester so SetReplArmRequester accepts it
// and the exploit executor drives the overlay.
var _ ArmRequester = widgetArmRequester{}

// RequestArm posts the arm overlay and blocks for the operator's decision. A
// canceled context or a nil program fails safe to ArmSkip (do not arm, do not run).
func (w widgetArmRequester) RequestArm(ctx context.Context, task eng.Task) ArmDecision {
	if w.prog == nil {
		return ArmSkip
	}
	reply := make(chan ArmDecision, 1)
	w.prog.Send(armMsg{task: task, reply: reply})
	select {
	case d := <-reply:
		return d
	case <-ctx.Done():
		return ArmSkip
	}
}

// armPicker is the y/n/esc arm-confirm overlay for one unarmed exploit/post-ex
// task. It carries no mode: the ribbon already shows safe/auto, and the prompt
// fires the same way in both.
type armPicker struct {
	task  eng.Task
	reply chan ArmDecision
}

func newArmPicker(task eng.Task, reply chan ArmDecision) armPicker {
	return armPicker{task: task, reply: reply}
}

func (p armPicker) resolve(d ArmDecision) tea.Cmd {
	reply := p.reply
	return func() tea.Msg { return armResolvedMsg{res: d, reply: reply} }
}

func (p armPicker) Update(msg tea.Msg) (overlayModel, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	switch km.String() {
	case "y", "Y":
		return p, p.resolve(ArmApprove)
	case "n", "N":
		return p, p.resolve(ArmSkip)
	case "esc":
		return p, p.resolve(ArmStop)
	}
	return p, nil
}

func (p armPicker) View(width, height int) string {
	label := vizSanitizeLabel(p.task.Kind + ": " + p.task.Objective)
	body := func(w, rows int) string {
		lines := []string{
			Caut.Render(Glyph(GlyphWarn)) + " " + Key.Render("arm to proceed?"),
			Body.Render(ellipsize(label, w)),
		}
		if rows > 2 {
			lines = append(lines, Meta.Render(ellipsize("the engagement reached armed exploitation; arming is operator-only", w)))
		}
		return strings.Join(lines, "\n")
	}
	return overlayBox(overlaySpec{title: "arm exploit task", wantW: 72, wantRows: 3, body: body}, width, height)
}
