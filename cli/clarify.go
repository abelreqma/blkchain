package main

import (
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// clarify.go holds the clarify overlay: an up/down selectable prompt the harness
// uses to ask the operator a question. It follows the other overlay pickers
// (overlay.go). The pure seams (moveUp, moveDown, choose, cancel, onCustomRow,
// customChosen) have no side effects; the reply channel is only written by the
// base Update in tui.go when a clarifyResolvedMsg arrives.

// Clarification is one question put to the operator.
type Clarification struct {
	Question    string
	Detail      string
	Options     []ClarifyOption
	AllowCustom bool // adds a trailing "type a custom instruction" row
}

// ClarifyOption is one selectable answer. Value is what the harness receives.
type ClarifyOption struct {
	Label string
	Note  string
	Value string
}

// ClarifyResult is the operator's answer: an option Value, a typed Custom
// instruction, or Canceled.
type ClarifyResult struct {
	Value    string
	Custom   string
	Canceled bool
}

// clarifyMsg asks the base Update to open a clarify overlay and answer on reply.
type clarifyMsg struct {
	c     Clarification
	reply chan ClarifyResult
}

// clarifyResolvedMsg is emitted by the picker on enter or esc. The base Update
// sends res on reply and closes the overlay.
type clarifyResolvedMsg struct {
	res   ClarifyResult
	reply chan ClarifyResult
}

const clarifyCustomLabel = "type a custom instruction"

// clarifyItem is one list row. custom marks the trailing custom-instruction row.
type clarifyItem struct {
	label, note string
	labelW      int // widest label, so notes line up in one column
	custom      bool
}

func (c clarifyItem) FilterValue() string { return c.label }

func clarifyRow(selected bool, item list.Item) string {
	it := item.(clarifyItem)
	label := sanitizeTerminal(it.label)
	pad := strings.Repeat(" ", max(it.labelW-lipgloss.Width(label), 0))
	note := ""
	if n := strings.TrimSpace(sanitizeTerminal(it.note)); n != "" {
		note = "  " + Meta.Render(n)
	}
	switch {
	case selected:
		return Prompt.Render(Glyph(GlyphPrompt)) + " " + Key.Render(label) + pad + note
	case it.custom:
		return "  " + Meta.Render(label) + pad + note
	}
	return "  " + Body.Render(label) + pad + note
}

type clarifyPicker struct {
	c      Clarification
	list   list.Model
	reply  chan ClarifyResult
	input  textinput.Model
	typing bool // the custom instruction input is open
}

// newClarifyPicker builds the picker: one row per option, plus a trailing custom
// row when AllowCustom.
func newClarifyPicker(c Clarification, width int, reply chan ClarifyResult) clarifyPicker {
	labelW := 0
	for _, o := range c.Options {
		labelW = max(labelW, lipgloss.Width(sanitizeTerminal(o.Label)))
	}
	if c.AllowCustom {
		labelW = max(labelW, len(clarifyCustomLabel))
	}
	items := make([]list.Item, 0, len(c.Options)+1)
	for _, o := range c.Options {
		items = append(items, clarifyItem{label: o.Label, note: o.Note, labelW: labelW})
	}
	if c.AllowCustom {
		items = append(items, clarifyItem{label: clarifyCustomLabel, labelW: labelW, custom: true})
	}
	w := clamp(width-6, 30, 72)
	ti := textinput.New()
	ti.Prompt = Glyph(GlyphPrompt) + " "
	ti.CharLimit = 2000
	return clarifyPicker{
		c:     c,
		list:  newCompactList(items, w, clamp(len(items), 1, 9), clarifyRow),
		reply: reply,
		input: ti,
	}
}

// --- side-effect-free seams ---

func (p clarifyPicker) moveDown() clarifyPicker {
	p.list.CursorDown()
	return p
}

func (p clarifyPicker) moveUp() clarifyPicker {
	p.list.CursorUp()
	return p
}

// onCustomRow reports whether index i is the trailing custom-instruction row.
func (p clarifyPicker) onCustomRow(i int) bool {
	return p.c.AllowCustom && i == len(p.c.Options)
}

// customChosen reports whether the selected row is the custom-instruction row.
func (p clarifyPicker) customChosen() bool { return p.onCustomRow(p.list.Index()) }

// choose returns the selected option's result. On the custom row it returns the
// zero result; callers detect that case with customChosen and open the input.
func (p clarifyPicker) choose() ClarifyResult {
	i := p.list.Index()
	if p.onCustomRow(i) || i < 0 || i >= len(p.c.Options) {
		return ClarifyResult{}
	}
	return ClarifyResult{Value: p.c.Options[i].Value}
}

func (p clarifyPicker) cancel() ClarifyResult { return ClarifyResult{Canceled: true} }

// --- overlayModel ---

func (p clarifyPicker) resolve(res ClarifyResult) tea.Cmd {
	reply := p.reply
	return func() tea.Msg { return clarifyResolvedMsg{res: res, reply: reply} }
}

func (p clarifyPicker) Update(msg tea.Msg) (overlayModel, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	if p.typing {
		switch km.String() {
		case "esc":
			p.typing = false
			p.input.Blur()
			return p, nil
		case "enter":
			text := strings.TrimSpace(p.input.Value())
			if text == "" {
				return p, nil
			}
			return p, p.resolve(ClarifyResult{Custom: text})
		}
		var cmd tea.Cmd
		p.input, cmd = p.input.Update(msg)
		return p, cmd
	}
	switch km.String() {
	case "esc":
		return p, p.resolve(p.cancel())
	case "enter":
		if p.customChosen() {
			p.typing = true
			return p, p.input.Focus()
		}
		if len(p.c.Options) == 0 {
			return p, nil
		}
		return p, p.resolve(p.choose())
	case "up", "k":
		return p.moveUp(), nil
	case "down", "j":
		return p.moveDown(), nil
	}
	return p, nil
}

func (p clarifyPicker) View(width, height int) string {
	detail := strings.TrimSpace(oneLine(sanitizeTerminal(p.c.Detail)))
	body := func(w, rows int) string {
		var head []string
		if detail != "" && rows > 2 {
			rows--
			head = append(head, Meta.Render(ellipsize(detail, w)))
		}
		if p.typing {
			p.input.Width = max(w-3, 1)
			head = append(head, p.input.View())
			return strings.Join(head, "\n")
		}
		p.list.SetSize(w, rows)
		head = append(head, p.list.View())
		return strings.Join(head, "\n")
	}
	wantRows := clamp(len(p.list.Items()), 1, 9)
	if detail != "" {
		wantRows++
	}
	return overlayBox(overlaySpec{
		title: sanitizeTerminal(oneLine(p.c.Question)),
		wantW: 72, wantRows: wantRows, body: body,
	}, width, height)
}
