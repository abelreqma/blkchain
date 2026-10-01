package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"blkchain/cli/internal/secgate"
)

func testConfirmCommand() secgate.Command {
	return secgate.Command{Binary: "nmap", Args: []string{"-sV", "10.0.0.5"}, Phase: secgate.PhaseExploit, Surface: secgate.SurfaceNetwork, Armed: true}
}

// The pure seams compute results without touching the reply channel, and the
// edit parser splits a line shell-free into a bare binary and literal args.
func TestConfirmPickerSeams(t *testing.T) {
	reply := make(chan confirmResult, 1)
	p := newConfirmPicker(testConfirmCommand(), 80, reply)

	if got := p.allow(); !got.allow || got.stop || got.edited != nil {
		t.Errorf("allow() = %+v; want allow only", got)
	}
	if got := p.deny(); got.allow || got.stop {
		t.Errorf("deny() = %+v; want a plain deny", got)
	}
	if got := p.stop(); got.allow || !got.stop {
		t.Errorf("stop() = %+v; want deny+stop", got)
	}

	cmd, ok := parseEditedCommand("nmap -sV 10.0.0.5")
	if !ok || cmd.Binary != "nmap" || len(cmd.Args) != 2 || cmd.Args[0] != "-sV" || cmd.Args[1] != "10.0.0.5" {
		t.Errorf("parseEditedCommand = %+v ok=%v; want {nmap [-sV 10.0.0.5]}", cmd, ok)
	}
	// An edited command carries no tier context: the gate inherits the original's.
	if cmd.Phase != "" || cmd.Surface != "" || cmd.Armed {
		t.Errorf("parseEditedCommand must not set Phase/Surface/Armed, got %+v", cmd)
	}
	if _, ok := parseEditedCommand("   "); ok {
		t.Errorf("an empty edit must not parse")
	}
	if len(reply) != 0 {
		t.Errorf("the seams must not send on the reply channel")
	}
}

// y/n/esc resolve allow / deny / deny+stop; the picker never writes the reply
// channel itself (the base Update does).
func TestConfirmPickerKeysResolve(t *testing.T) {
	reply := make(chan confirmResult, 1)
	var ov overlayModel = newConfirmPicker(testConfirmCommand(), 80, reply)

	_, cmd := ov.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if msg, ok := cmd().(confirmResolvedMsg); !ok || !msg.res.allow || msg.reply != reply {
		t.Fatalf("y should resolve allow, got %#v", cmd())
	}
	_, cmd = ov.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if msg, ok := cmd().(confirmResolvedMsg); !ok || msg.res.allow || msg.res.stop {
		t.Fatalf("n should resolve a plain deny, got %#v", cmd())
	}
	_, cmd = ov.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if msg, ok := cmd().(confirmResolvedMsg); !ok || msg.res.allow || !msg.res.stop {
		t.Fatalf("esc should resolve deny+stop, got %#v", cmd())
	}
	if len(reply) != 0 {
		t.Fatalf("the picker must not send on the reply channel itself")
	}
}

// e opens a prefilled edit field; enter submits the re-typed command as an edit.
func TestConfirmPickerEditSubmit(t *testing.T) {
	reply := make(chan confirmResult, 1)
	var ov overlayModel = newConfirmPicker(testConfirmCommand(), 80, reply)

	ov, _ = ov.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	cp := ov.(confirmPicker)
	if !cp.editing {
		t.Fatalf("e should open the edit field")
	}
	if cp.input.Value() != "nmap -sV 10.0.0.5" {
		t.Fatalf("edit field should prefill the argv, got %q", cp.input.Value())
	}
	// Replace the whole line.
	cp.input.SetValue("nmap -p 22 10.0.0.5")
	ov = cp
	_, cmd := ov.Update(tea.KeyMsg{Type: tea.KeyEnter})
	msg, ok := cmd().(confirmResolvedMsg)
	if !ok || !msg.res.allow || msg.res.edited == nil {
		t.Fatalf("enter should resolve an allowed edit, got %#v", cmd())
	}
	if e := msg.res.edited; e.Binary != "nmap" || len(e.Args) != 3 || e.Args[1] != "22" {
		t.Fatalf("edited command = %+v; want nmap -p 22 10.0.0.5", e)
	}
}

// esc in the edit field returns to the y/e/n prompt without resolving; an empty
// edit stays in the field.
func TestConfirmPickerEditEscAndEmpty(t *testing.T) {
	var ov overlayModel = newConfirmPicker(testConfirmCommand(), 80, make(chan confirmResult, 1))
	ov, _ = ov.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	ov, cmd := ov.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd != nil {
		t.Fatalf("esc in the edit field should not resolve")
	}
	if ov.(confirmPicker).editing {
		t.Fatalf("esc should leave the edit field")
	}

	ov, _ = ov.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	cp := ov.(confirmPicker)
	cp.input.SetValue("   ")
	ov = cp
	_, cmd = ov.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatalf("an empty edit must not resolve")
	}
	if !ov.(confirmPicker).editing {
		t.Fatalf("an empty edit should stay in the field")
	}
}

func TestConfirmMsgOpensOverlayAndReplies(t *testing.T) {
	m := newTestModel(t)
	reply := make(chan confirmResult, 1)
	nm, _ := m.Update(confirmMsg{cmd: testConfirmCommand(), reply: reply})
	m = nm.(model)
	if _, ok := m.overlay.(confirmPicker); !ok {
		t.Fatalf("confirmMsg should open the confirm picker, got %T", m.overlay)
	}
	if len(m.footerKeys().short) == 0 {
		t.Fatalf("the confirm overlay needs footer hints")
	}
	nm, cmd := m.Update(confirmResolvedMsg{res: confirmResult{allow: true}, reply: reply})
	m = nm.(model)
	if m.overlay != nil {
		t.Fatalf("resolving should clear the overlay")
	}
	drainCmd(cmd)
	select {
	case got := <-reply:
		if !got.allow {
			t.Fatalf("reply = %+v; want allow", got)
		}
	default:
		t.Fatalf("resolving should send the result on the reply channel")
	}
}

func TestConfirmDisplacedReplyIsDenied(t *testing.T) {
	m := newTestModel(t)
	replyA := make(chan confirmResult, 1)
	replyB := make(chan confirmResult, 1)
	nm, _ := m.Update(confirmMsg{cmd: testConfirmCommand(), reply: replyA})
	m = nm.(model)
	nm, cmd := m.Update(confirmMsg{cmd: testConfirmCommand(), reply: replyB})
	m = nm.(model)
	if cmd == nil {
		t.Fatalf("displacing a confirm overlay should return a deny command")
	}
	cmd()
	select {
	case got := <-replyA:
		if got.allow {
			t.Fatalf("displaced reply = %+v; want a deny", got)
		}
	default:
		t.Fatalf("the displaced confirm was not answered")
	}
	if p, ok := m.overlay.(confirmPicker); !ok || p.reply != replyB {
		t.Fatalf("overlay should be the new confirm picker, got %T", m.overlay)
	}
	if len(replyB) != 0 {
		t.Fatalf("the new request must not be answered")
	}
}

// esc (stop) both denies the command and cancels the running engagement turn.
func TestConfirmStopCancelsTurn(t *testing.T) {
	m := newTestModel(t)
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	reply := make(chan confirmResult, 1)
	nm, cmd := m.Update(confirmResolvedMsg{res: confirmResult{stop: true}, reply: reply})
	m = nm.(model)
	drainCmd(cmd)
	select {
	case <-ctx.Done():
	default:
		t.Fatalf("a stop should cancel the engagement turn")
	}
	select {
	case got := <-reply:
		if got.allow {
			t.Fatalf("stop reply = %+v; want a deny", got)
		}
	default:
		t.Fatalf("stop should still answer the reply channel")
	}
}

// fakeProg captures the messages a goroutine confirmer sends to the event loop.
type fakeProg struct{ got chan tea.Msg }

func (f *fakeProg) Send(m tea.Msg) { f.got <- m }

func TestWidgetConfirmerBridgesProg(t *testing.T) {
	fp := &fakeProg{got: make(chan tea.Msg, 1)}
	wc := widgetConfirmer{prog: fp}

	type out struct {
		allow  bool
		edited *secgate.Command
	}
	done := make(chan out, 1)
	go func() {
		allow, edited := wc.ConfirmOrEdit(context.Background(), testConfirmCommand())
		done <- out{allow, edited}
	}()
	msg := (<-fp.got).(confirmMsg)
	msg.reply <- confirmResult{allow: true, edited: &secgate.Command{Binary: "ls"}}
	got := <-done
	if !got.allow || got.edited == nil || got.edited.Binary != "ls" {
		t.Fatalf("confirmer should return the injected reply, got %+v", got)
	}

	// A canceled context fails closed (deny, no edit).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	go func() {
		allow, edited := wc.ConfirmOrEdit(ctx, testConfirmCommand())
		done <- out{allow, edited}
	}()
	<-fp.got // drain the sent confirmMsg
	got = <-done
	if got.allow || got.edited != nil {
		t.Fatalf("a canceled context should deny, got %+v", got)
	}

	// A nil program fails closed without blocking.
	if allow, edited := (widgetConfirmer{}).ConfirmOrEdit(context.Background(), testConfirmCommand()); allow || edited != nil {
		t.Fatalf("a nil prog should deny")
	}
}

// drainCmd executes a (possibly batched) command's side effects, draining nested
// batch messages, for tests that assert on the reply channel.
func drainCmd(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	msg := cmd()
	if b, ok := msg.(tea.BatchMsg); ok {
		for _, c := range b {
			drainCmd(c)
		}
	}
}

// The confirm overlay shows the command, its tier context, and (when editing) a
// prefilled field and hint. The footer carries y/e/n/esc.
func TestConfirmPickerView(t *testing.T) {
	noColor(t)
	p := newConfirmPicker(testConfirmCommand(), 80, make(chan confirmResult, 1))
	out := p.View(80, 24)
	for _, want := range []string{"confirm command", "nmap -sV 10.0.0.5", "phase exploit", "surface network", "armed"} {
		if !strings.Contains(out, want) {
			t.Fatalf("confirm view is missing %q:\n%s", want, out)
		}
	}
	p.editing = true
	out = p.View(80, 24)
	for _, want := range []string{"nmap -sV 10.0.0.5", "re-check and run"} {
		if !strings.Contains(out, want) {
			t.Fatalf("editing view is missing %q:\n%s", want, out)
		}
	}
}

// When the command is an interpreter PoC, the confirm overlay shows the plan
// (title, sha256, and the read-only script body) in addition to the y/e/n/esc
// controls.
func TestConfirmPickerPoCView(t *testing.T) {
	noColor(t)
	cmd := secgate.Command{
		Binary: "python3", Args: []string{"/s/poc.py", "--target", "10.0.0.5"},
		Phase: secgate.PhaseExploit, Surface: secgate.SurfaceWeb, Armed: true,
		PoCIsInterpreter: true,
		PoCHash:          "9f3ac4b2e1d8a77e21",
		PoCBody:          "import sys\nprint('hello')\n",
	}
	out := newConfirmPicker(cmd, 80, make(chan confirmResult, 1)).View(80, 40)
	for _, want := range []string{"interpreter PoC", "sha256", "9f3ac4b2e1d8a77e21", "script", "import sys", "print('hello')"} {
		if !strings.Contains(out, want) {
			t.Fatalf("PoC view missing %q:\n%s", want, out)
		}
	}
}

// A long PoC body is capped to the overlay height with a remaining-lines note.
func TestConfirmPickerPoCBodyTruncates(t *testing.T) {
	noColor(t)
	var b strings.Builder
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&b, "line%d\n", i)
	}
	cmd := secgate.Command{Binary: "python3", Args: []string{"/s/poc.py"}, PoCIsInterpreter: true, PoCHash: "h", PoCBody: b.String()}
	out := newConfirmPicker(cmd, 80, make(chan confirmResult, 1)).View(80, 20)
	if !strings.Contains(out, "more lines") {
		t.Fatalf("a body taller than the overlay should note the remaining lines:\n%s", out)
	}
}

// A non-PoC command renders the plain confirm overlay (no PoC plan).
func TestConfirmPickerNonPoCViewPlain(t *testing.T) {
	noColor(t)
	out := newConfirmPicker(testConfirmCommand(), 80, make(chan confirmResult, 1)).View(80, 24)
	if strings.Contains(out, "sha256") || strings.Contains(out, "interpreter PoC") {
		t.Fatalf("a non-PoC command must not show the PoC plan:\n%s", out)
	}
	if !strings.Contains(out, "confirm command") {
		t.Fatalf("a non-PoC command keeps the plain title:\n%s", out)
	}
}

// The PoC body is sanitized before display (it is model-generated script text), so
// a raw terminal escape never reaches the screen.
func TestConfirmPickerPoCBodySanitized(t *testing.T) {
	noColor(t)
	cmd := secgate.Command{Binary: "python3", Args: []string{"/s/poc.py"}, PoCIsInterpreter: true, PoCHash: "h", PoCBody: "safe\x1b[31mred\x1b[0m\n"}
	out := newConfirmPicker(cmd, 80, make(chan confirmResult, 1)).View(80, 40)
	if strings.Contains(out, "\x1b[31m") {
		t.Fatalf("the PoC body must be sanitized of raw escapes:\n%q", out)
	}
}
