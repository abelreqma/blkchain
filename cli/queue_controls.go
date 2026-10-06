package main

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"strconv"
	"strings"
)

const maxQueueItems = 16
const maxQueueBytes = 256 << 10

func isQueuedTurn(q string) bool {
	verb, arg := parseInput(q)
	if verb == "web" {
		c, err := parseWebCommand(strings.Fields(arg))
		return err == nil && c.action == "search"
	}
	if verb == "rag" {
		toggle, _, question := ragArg(arg)
		return !toggle && question != ""
	}
	return isTurnVerb(verb)
}

func (m *model) enqueueQuestion(q string) error {
	bytes := len(q)
	for _, old := range m.queue {
		bytes += len(old)
	}
	if len(m.queue) >= maxQueueItems || bytes > maxQueueBytes {
		return fmt.Errorf("queue limit reached; edit or remove a queued question")
	}
	m.queue = append(m.queue, q)
	return nil
}

func (m model) queueText() string {
	state := "ready"
	if m.queuePaused {
		state = "paused"
	}
	lines := []string{fmt.Sprintf("QUEUE  %d questions, %s", len(m.queue), state)}
	for i, q := range m.queue {
		lines = append(lines, fmt.Sprintf("%d  %s", i+1, ellipsize(oneLine(sanitizeTerminal(q)), max(m.renderWidth()-4, 1))))
	}
	return strings.Join(lines, "\n")
}

func (m *model) queueAction(arg string) (string, error) {
	f := strings.Fields(arg)
	if len(f) == 0 || (len(f) == 1 && f[0] == "list") {
		return m.queueText(), nil
	}
	if len(f) == 1 {
		switch f[0] {
		case "pause":
			m.queuePaused = true
			return "queue paused; the active turn continues", nil
		case "resume":
			m.queuePaused = false
			return "queue resumed", nil
		case "clear":
			m.queue = nil
			return "cleared queued questions", nil
		}
	}
	if len(f) != 2 || (f[0] != "edit" && f[0] != "remove") {
		return "", fmt.Errorf("queue: use list, edit N, remove N, pause, resume, or clear")
	}
	n, err := strconv.Atoi(f[1])
	if err != nil || n < 1 || n > len(m.queue) {
		return "", fmt.Errorf("queue: no question %s", f[1])
	}
	note := "removed queued question"
	if f[0] == "edit" {
		if m.ta.Value() != "" {
			return "", fmt.Errorf("save or clear the current draft before editing a queued question")
		}
		m.setDraft(m.queue[n-1])
		m.queuePaused = true
		note = "queued question ready for editing"
	}
	m.queue = append(m.queue[:n-1:n-1], m.queue[n:]...)
	return note, nil
}

type queueChangedMsg struct{ action string }

func (m *model) pauseQueueAfterMessage(msg tea.Msg) {
	failed := false
	switch v := msg.(type) {
	case errMsg, canceledMsg:
		failed = true
	case streamDoneMsg:
		failed = v.err != nil
	case webDoneMsg:
		failed = v.Err != nil
	case engageDoneMsg:
		failed = v.err != nil || v.paused
	}
	if failed {
		m.queuePaused = true
	}
}

type queuePicker struct {
	items    []string
	selected int
}

func (p queuePicker) Update(msg tea.Msg) (overlayModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	action := ""
	switch k.String() {
	case "esc":
		return p, closeOverlayCmd
	case "up":
		p.selected = max(p.selected-1, 0)
	case "down":
		p.selected = min(p.selected+1, max(len(p.items)-1, 0))
	case "r":
		action = "resume"
	case "enter", "d":
		if len(p.items) == 0 {
			return p, nil
		}
		verb := "edit"
		if k.String() == "d" {
			verb = "remove"
		}
		action = fmt.Sprintf("%s %d", verb, p.selected+1)
	}
	if action != "" {
		return p, func() tea.Msg { return queueChangedMsg{action} }
	}
	return p, nil
}
func (p queuePicker) View(width, height int) string {
	body := func(w, rows int) string {
		if len(p.items) == 0 {
			return Meta.Render("no queued questions")
		}
		start := max(p.selected-rows+1, 0)
		var lines []string
		for i := start; i < min(start+rows, len(p.items)); i++ {
			marker := "  "
			if i == p.selected {
				marker = Glyph(GlyphPrompt) + " "
			}
			label := fmt.Sprintf("%d %s", i+1, oneLine(sanitizeTerminal(p.items[i])))
			lines = append(lines, marker+ellipsize(label, max(w-2, 1)))
		}
		return strings.Join(lines, "\n")
	}
	return overlayBox(overlaySpec{title: "QUEUE (paused)", wantW: 72, wantRows: clamp(len(p.items), 1, 9), body: body}, width, height)
}
