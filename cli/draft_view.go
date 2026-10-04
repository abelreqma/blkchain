package main

import (
	"strings"
	"unicode/utf8"

	"github.com/rivo/uniseg"
)

type draftLayout struct {
	value string
	width int
	rows  []draftRow
}

func (m model) draftRows() []draftRow {
	value, width := m.ta.Value(), m.ta.Width()
	if m.draftLayout.value == value && m.draftLayout.width == width && m.draftLayout.rows != nil {
		return m.draftLayout.rows
	}
	return wrapDraft(value, width)
}

type draftRow struct {
	line, start int
	text        string
}

func wrapDraft(value string, width int) []draftRow {
	width = max(width, 1)
	var rows []draftRow
	for line, text := range strings.Split(value, "\n") {
		start, runeStart, runeEnd, columns := 0, 0, 0, 0
		lastBreak, runeBreak := 0, 0
		g := uniseg.NewGraphemes(text)
		for g.Next() {
			from, to := g.Positions()
			w := g.Width()
			if columns+w > width && from > start {
				at, runeAt := from, runeEnd
				if lastBreak > start {
					at, runeAt = lastBreak, runeBreak
				}
				rows = append(rows, draftRow{line: line, start: runeStart, text: text[start:at]})
				start, runeStart, columns = at, runeAt, uniseg.StringWidth(text[at:from])
				lastBreak = 0
			}
			runeEnd += utf8.RuneCountInString(text[from:to])
			columns += w
			if g.LineBreak() >= uniseg.LineCanBreak {
				lastBreak, runeBreak = to, runeEnd
			}
		}
		rows = append(rows, draftRow{line: line, start: runeStart, text: text[start:]})
		if columns >= width {
			rows = append(rows, draftRow{line: line, start: runeEnd})
		}
	}
	return rows
}

func (m model) draftPosition() (int, int) {
	li := m.ta.LineInfo()
	return m.ta.Line(), li.StartColumn + li.ColumnOffset
}

func draftCursorRow(rows []draftRow, line, col int) int {
	for i, row := range rows {
		if row.line == line && (i+1 == len(rows) || rows[i+1].line != line || col < rows[i+1].start) {
			return i
		}
	}
	return len(rows) - 1
}

func (m *model) setDraftCursor(line, col int) {
	for m.ta.Line() > line {
		m.ta.CursorUp()
	}
	for m.ta.Line() < line {
		m.ta.CursorDown()
	}
	m.ta.SetCursor(col)
}

func (m *model) moveDraftVertical(delta int) {
	rows := m.draftRows()
	line, col := m.draftPosition()
	current := draftCursorRow(rows, line, col)
	row := rows[current]
	prefix := []rune(row.text)[:min(max(col-row.start, 0), utf8.RuneCountInString(row.text))]
	goal := m.draftGoal
	if !m.draftVertical {
		goal = uniseg.StringWidth(string(prefix))
	}
	m.draftGoal, m.draftVertical = goal, true
	target := rows[clamp(current+delta, 0, len(rows)-1)]
	g := uniseg.NewGraphemes(target.text)
	columns, to := 0, target.start
	for g.Next() {
		if columns+g.Width() > goal {
			break
		}
		columns += g.Width()
		to += utf8.RuneCountInString(g.Str())
	}
	m.setDraftCursor(target.line, to)
	m.draftTop = draftViewportTop(rows, target.line, to, m.draftTop, m.ta.Height())
}

func (m model) draftView() string {
	if m.ta.Value() == "" {
		return m.ta.View()
	}
	rows := m.draftRows()
	line, col := m.draftPosition()
	cursorRow := draftCursorRow(rows, line, col)
	top := draftViewportTop(rows, line, col, m.draftTop, m.ta.Height())
	var out strings.Builder
	for i := top; i < min(top+m.ta.Height(), len(rows)); i++ {
		if i > top {
			out.WriteByte('\n')
		}
		out.WriteString(m.ta.FocusedStyle.Prompt.Render(m.ta.Prompt))
		row := rows[i]
		if i != cursorRow {
			out.WriteString(m.ta.FocusedStyle.Text.Render(row.text))
			continue
		}
		at := len(string([]rune(row.text)[:min(max(col-row.start, 0), utf8.RuneCountInString(row.text))]))
		before, after, char := row.text[:at], row.text[at:], " "
		g := uniseg.NewGraphemes(after)
		if g.Next() {
			char = g.Str()
			after = after[len(char):]
		}
		m.ta.Cursor.SetChar(char)
		out.WriteString(m.ta.FocusedStyle.Text.Render(before))
		out.WriteString(m.ta.Cursor.View())
		out.WriteString(m.ta.FocusedStyle.Text.Render(after))
	}
	return out.String()
}

func draftViewportTop(rows []draftRow, line, col, top, height int) int {
	cursorRow := draftCursorRow(rows, line, col)
	top = clamp(top, 0, max(len(rows)-height, 0))
	if cursorRow < top {
		return cursorRow
	}
	if cursorRow >= top+height {
		return cursorRow - height + 1
	}
	return top
}
