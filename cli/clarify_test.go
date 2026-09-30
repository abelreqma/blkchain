package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func testClarification() Clarification {
	return Clarification{Question: "pick next", Detail: "two leads", Options: []ClarifyOption{
		{Label: "SQLi", Note: "login form", Value: "sqli"}, {Label: "IDOR", Value: "idor"},
	}, AllowCustom: true}
}

func TestClarifyPickerSelectAndReply(t *testing.T) {
	reply := make(chan ClarifyResult, 1)
	c := testClarification()
	p := newClarifyPicker(c, 80, reply)
	p = p.moveDown()
	res := p.choose()
	if res.Value != "idor" || res.Canceled {
		t.Fatalf("choose returned %+v; want idor, not canceled", res)
	}
	if !p.onCustomRow(len(c.Options)) {
		t.Fatalf("index %d should be the custom row", len(c.Options))
	}
	if got := p.cancel(); !got.Canceled {
		t.Fatalf("cancel should set Canceled")
	}
	if len(reply) != 0 {
		t.Fatalf("the seams must not send on the reply channel")
	}
}

func TestClarifyPickerCustomRow(t *testing.T) {
	reply := make(chan ClarifyResult, 1)
	p := newClarifyPicker(testClarification(), 80, reply)
	if p.customChosen() {
		t.Fatalf("first row is not the custom row")
	}
	p = p.moveDown().moveDown()
	if !p.customChosen() {
		t.Fatalf("third row should be the custom row")
	}
	res := p.choose()
	if res.Value != "" || res.Canceled {
		t.Fatalf("choose on the custom row = %+v; want empty, not canceled", res)
	}
	p = p.moveDown() // stays on the last row
	if !p.customChosen() {
		t.Fatalf("moveDown past the end must stay on the custom row")
	}
	p = p.moveUp().moveUp()
	if p.customChosen() || p.choose().Value != "sqli" {
		t.Fatalf("moveUp twice should return to the first option")
	}
	if len(reply) != 0 {
		t.Fatalf("the seams must not send on the reply channel")
	}
}

func TestClarifyPickerNoCustomRow(t *testing.T) {
	c := testClarification()
	c.AllowCustom = false
	p := newClarifyPicker(c, 80, make(chan ClarifyResult, 1))
	if p.onCustomRow(len(c.Options)) {
		t.Fatalf("no custom row when AllowCustom is false")
	}
	p = p.moveDown().moveDown()
	if p.choose().Value != "idor" {
		t.Fatalf("selection should stop at the last option")
	}
}

func TestClarifyPickerKeysResolve(t *testing.T) {
	reply := make(chan ClarifyResult, 1)
	var ov overlayModel = newClarifyPicker(testClarification(), 80, reply)
	ov, _ = ov.Update(tea.KeyMsg{Type: tea.KeyDown})
	_, cmd := ov.Update(tea.KeyMsg{Type: tea.KeyEnter})
	msg, ok := cmd().(clarifyResolvedMsg)
	if !ok || msg.res.Value != "idor" || msg.reply != reply {
		t.Fatalf("enter should resolve idor on the reply channel, got %#v", msg)
	}
	_, cmd = ov.Update(tea.KeyMsg{Type: tea.KeyEsc})
	msg, ok = cmd().(clarifyResolvedMsg)
	if !ok || !msg.res.Canceled {
		t.Fatalf("esc should resolve canceled, got %#v", msg)
	}
	if len(reply) != 0 {
		t.Fatalf("the picker must not send on the reply channel itself")
	}
}

func TestClarifyPickerCustomInput(t *testing.T) {
	reply := make(chan ClarifyResult, 1)
	var ov overlayModel = newClarifyPicker(testClarification(), 80, reply)
	ov, _ = ov.Update(tea.KeyMsg{Type: tea.KeyDown})
	ov, _ = ov.Update(tea.KeyMsg{Type: tea.KeyDown})
	ov, _ = ov.Update(tea.KeyMsg{Type: tea.KeyEnter}) // opens the input (its cmd is a cursor blink)
	if !ov.(clarifyPicker).typing {
		t.Fatalf("enter on the custom row opens the input, not a result")
	}
	for _, r := range "try xss" {
		ov, _ = ov.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	_, cmd := ov.Update(tea.KeyMsg{Type: tea.KeyEnter})
	msg, ok := cmd().(clarifyResolvedMsg)
	if !ok || msg.res.Custom != "try xss" || msg.res.Canceled {
		t.Fatalf("custom submit = %#v; want Custom \"try xss\"", msg)
	}
}

func TestClarifyPickerCustomEscReturnsToList(t *testing.T) {
	var ov overlayModel = newClarifyPicker(testClarification(), 80, make(chan ClarifyResult, 1))
	ov, _ = ov.Update(tea.KeyMsg{Type: tea.KeyDown})
	ov, _ = ov.Update(tea.KeyMsg{Type: tea.KeyDown})
	ov, _ = ov.Update(tea.KeyMsg{Type: tea.KeyEnter})
	ov, cmd := ov.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd != nil {
		t.Fatalf("esc in the custom input goes back to the list, not cancel")
	}
	if !ov.(clarifyPicker).customChosen() || ov.(clarifyPicker).typing {
		t.Fatalf("expected the list with the custom row still selected")
	}
}

func TestClarifyPickerView(t *testing.T) {
	p := newClarifyPicker(testClarification(), 80, make(chan ClarifyResult, 1))
	out := p.View(80, 24)
	for _, want := range []string{"pick next", "two leads", "SQLi", "login form", "IDOR", "custom instruction"} {
		if !strings.Contains(out, want) {
			t.Fatalf("view is missing %q:\n%s", want, out)
		}
	}
}

func TestClarifyMsgOpensOverlayAndReplies(t *testing.T) {
	m := newTestModel(t)
	reply := make(chan ClarifyResult, 1)
	nm, _ := m.Update(clarifyMsg{c: testClarification(), reply: reply})
	m = nm.(model)
	if _, ok := m.overlay.(clarifyPicker); !ok {
		t.Fatalf("clarifyMsg should open the clarify picker, got %T", m.overlay)
	}
	if got := m.footerKeys().short; len(got) == 0 {
		t.Fatalf("clarify overlay needs footer hints")
	}
	nm, cmd := m.Update(clarifyResolvedMsg{res: ClarifyResult{Value: "sqli"}, reply: reply})
	m = nm.(model)
	if m.overlay != nil {
		t.Fatalf("resolving should clear the overlay")
	}
	if cmd == nil {
		t.Fatalf("resolving should return a command that sends the reply")
	}
	if b, ok := cmd().(tea.BatchMsg); ok {
		for _, c := range b {
			if c != nil {
				c()
			}
		}
	}
	select {
	case got := <-reply:
		if got.Value != "sqli" {
			t.Fatalf("reply = %+v", got)
		}
	default:
		t.Fatalf("resolving should send the result on the reply channel")
	}
}

func TestClarifyDisplacedReplyIsCanceled(t *testing.T) {
	m := newTestModel(t)
	replyA := make(chan ClarifyResult, 1)
	replyB := make(chan ClarifyResult, 1)
	nm, _ := m.Update(clarifyMsg{c: testClarification(), reply: replyA})
	m = nm.(model)
	nm, cmd := m.Update(clarifyMsg{c: testClarification(), reply: replyB})
	m = nm.(model)
	if cmd == nil {
		t.Fatalf("displacing a clarify overlay should return a cancel command")
	}
	cmd()
	select {
	case got := <-replyA:
		if !got.Canceled {
			t.Fatalf("displaced reply = %+v; want Canceled", got)
		}
	default:
		t.Fatalf("displaced clarify reply was not answered")
	}
	p, ok := m.overlay.(clarifyPicker)
	if !ok || p.reply != replyB {
		t.Fatalf("overlay should be the new clarify picker, got %T", m.overlay)
	}
	if len(replyB) != 0 {
		t.Fatalf("the new request must not be answered")
	}
}

func footerText(m model) string {
	var parts []string
	for _, b := range m.footerKeys().short {
		parts = append(parts, b.Help().Key+"="+b.Help().Desc)
	}
	return strings.Join(parts, ",")
}

func TestClarifyFooterKeys(t *testing.T) {
	m := newTestModel(t)
	nm, _ := m.Update(clarifyMsg{c: testClarification(), reply: make(chan ClarifyResult, 1)})
	m = nm.(model)
	if got, want := footerText(m), "up/down=move,enter=choose,esc=cancel"; got != want {
		t.Fatalf("list footer = %q; want %q", got, want)
	}
	p := m.overlay.(clarifyPicker)
	p.typing = true
	m.overlay = p
	if got, want := footerText(m), "enter=submit,esc=back"; got != want {
		t.Fatalf("typing footer = %q; want %q", got, want)
	}
}
