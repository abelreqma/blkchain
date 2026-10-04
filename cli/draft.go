package main

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/rivo/uniseg"
)

const maxDraftLines = 10000

type draftPasteMsg struct {
	text      string
	err       error
	truncated bool
}

var readDraftClipboard = clipboard.ReadAll

func pasteDraftCmd() tea.Msg {
	text, err := readDraftClipboard()
	text, cut := boundedDraftText(text, inputCharLimit)
	return draftPasteMsg{text: text, err: err, truncated: cut}
}

func boundedDraftText(text string, budget int) (string, bool) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(sanitizeTerminal(text), "\t", "    ")
	cut := false
	lines := 1
	for i, r := range text {
		if r == '\n' {
			lines++
			if lines > maxDraftLines {
				text, cut = text[:i], true
				break
			}
		}
	}
	if len(text) > budget {
		g := uniseg.NewGraphemes(text)
		end := 0
		for g.Next() {
			_, next := g.Positions()
			if next > budget {
				break
			}
			end = next
		}
		return text[:end], true
	}
	return text, cut
}

func (m *model) setDraft(text string) {
	text, m.draftTruncated = boundedDraftText(text, inputCharLimit)
	m.ta.SetValue(text)
	m.draftVertical = false
	m.resizeDraft()
}

func (m *model) resizeDraft() {
	rows := m.draftRows()
	m.draftLayout = draftLayout{value: m.ta.Value(), width: m.ta.Width(), rows: rows}
	m.ta.SetHeight(clamp(len(rows), 1, 6))
	line, col := m.draftPosition()
	m.draftTop = draftViewportTop(rows, line, col, m.draftTop, m.ta.Height())
}

func (m model) updateDraft(msg tea.Msg) (tea.Model, tea.Cmd) {
	before := m.ta.Value()
	if km, ok := msg.(tea.KeyMsg); ok {
		if key.Matches(km, m.ta.KeyMap.LinePrevious) || key.Matches(km, m.ta.KeyMap.LineNext) {
			delta := 1
			if key.Matches(km, m.ta.KeyMap.LinePrevious) {
				delta = -1
			}
			m.moveDraftVertical(delta)
			return m, m.ta.Cursor.BlinkCmd()
		}
		m.draftVertical = false
		if key.Matches(km, m.ta.KeyMap.Paste) {
			return m, pasteDraftCmd
		}
		if m.editGrapheme(km) {
			m.resizeDraft()
			return m.refreshPalette(), m.ta.Cursor.BlinkCmd()
		}
		if len(km.Runes) > 0 && !km.Alt {
			text, cut := m.boundDraftInsert(string(km.Runes))
			km.Runes = []rune(text)
			m.draftTruncated = m.draftTruncated || cut
			msg = km
		}
		if key.Matches(km, m.keys.Newline) && (len(before) >= inputCharLimit || m.ta.LineCount() >= maxDraftLines) {
			m.draftTruncated = true
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.ta, cmd = m.ta.Update(msg)
	m.snapDraftCursor()
	if text := m.ta.Value(); text != before {
		limited, cut := boundedDraftText(text, inputCharLimit)
		if cut {
			m.ta.SetValue(limited)
		}
		m.draftTruncated = cut || (m.draftTruncated && len(text) >= len(before))
		m.resizeDraft()
		m = m.refreshPalette()
	}
	return m, cmd
}

func (m model) pasteDraft(msg draftPasteMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		return m, tea.Println(styleErr(fmt.Errorf("paste: clipboard unavailable")))
	}
	text, cut := m.boundDraftInsert(msg.text)
	m.draftVertical = false
	m.ta.InsertString(text)
	m.draftTruncated = msg.truncated || cut
	m.resizeDraft()
	return m.refreshPalette(), m.ta.Cursor.BlinkCmd()
}

// editGrapheme keeps character editing on visible character boundaries.
func (m *model) editGrapheme(km tea.KeyMsg) bool {
	k := km.String()
	switch k {
	case "left", "ctrl+b", "right", "ctrl+f", "backspace", "ctrl+h", "delete", "ctrl+t":
	default:
		return false
	}
	lines := strings.Split(m.ta.Value(), "\n")
	row := m.ta.Line()
	line := lines[row]
	li := m.ta.LineInfo()
	col := li.StartColumn + li.ColumnOffset
	byteCol := len(string([]rune(line)[:min(col, utf8.RuneCountInString(line))]))
	prev, next := 0, len(line)
	g := uniseg.NewGraphemes(line)
	for g.Next() {
		start, end := g.Positions()
		if end <= byteCol {
			prev = start
		}
		if end > byteCol {
			next = end
			break
		}
	}
	to := byteCol
	switch k {
	case "left", "ctrl+b":
		if byteCol == 0 {
			return false
		}
		to = prev
	case "right", "ctrl+f":
		if byteCol == len(line) {
			return false
		}
		to = next
	case "backspace", "ctrl+h":
		if byteCol == 0 {
			return false
		}
		lines[row] = line[:prev] + line[byteCol:]
		to = prev
	case "delete":
		if byteCol == len(line) {
			return false
		}
		lines[row] = line[:byteCol] + line[next:]
	case "ctrl+t":
		if byteCol == 0 {
			return true
		}
		if byteCol == len(line) {
			byteCol = prev
			g := uniseg.NewGraphemes(line[:byteCol])
			for g.Next() {
				prev, _ = g.Positions()
			}
			if byteCol == 0 {
				return true
			}
		}
		lines[row] = line[:prev] + line[byteCol:next] + line[prev:byteCol] + line[next:]
		to = next
	}
	if lines[row] != line {
		m.ta.SetValue(strings.Join(lines, "\n"))
		for m.ta.Line() > row {
			m.ta.CursorUp()
		}
		m.draftTruncated = false
	}
	m.ta.SetCursor(utf8.RuneCountInString(lines[row][:to]))
	m.ta, _ = m.ta.Update(nil)
	return true
}

func (m model) boundDraftInsert(text string) (string, bool) {
	text, cut := boundedDraftText(text, max(inputCharLimit-len(m.ta.Value()), 0))
	remaining := maxDraftLines - m.ta.LineCount()
	for i, r := range text {
		if r == '\n' {
			if remaining == 0 {
				return text[:i], true
			}
			remaining--
		}
	}
	return text, cut
}

func (m *model) snapDraftCursor() {
	line, col := m.draftPosition()
	text := strings.Split(m.ta.Value(), "\n")[line]
	pos := 0
	g := uniseg.NewGraphemes(text)
	for g.Next() {
		next := pos + utf8.RuneCountInString(g.Str())
		if col > pos && col < next {
			m.ta.SetCursor(next)
			return
		}
		pos = next
	}
}
