package main

import (
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// reverseSearch is the transient Ctrl-R state. cycle is how many matches to skip
// (older) from the newest match; match/count are the current result.
type reverseSearch struct {
	open  bool
	query string
	match string
	count int
	cycle int
}

// reverseSearchMatch returns the (cycle)-th match for query in history, newest
// first, plus the number of matches. An empty query matches nothing. cycle wraps
// around the match count.
func reverseSearchMatch(history []string, query string, cycle int) (string, int) {
	if strings.TrimSpace(query) == "" {
		return "", 0
	}
	q := strings.ToLower(query)
	var matches []string
	for i := len(history) - 1; i >= 0; i-- {
		if strings.Contains(strings.ToLower(history[i]), q) {
			matches = append(matches, history[i])
		}
	}
	if len(matches) == 0 {
		return "", 0
	}
	idx := cycle % len(matches)
	if idx < 0 {
		idx = 0
	}
	return matches[idx], len(matches)
}

// openReverseSearch starts a Ctrl-R session over the current history.
func (m model) openReverseSearch() (tea.Model, tea.Cmd) {
	m.pal.open = false
	m.rsearch = reverseSearch{open: true}
	return m, nil
}

// updateReverseMatch recomputes the current match from the query and cycle.
func (m model) updateReverseMatch() model {
	m.rsearch.match, m.rsearch.count = reverseSearchMatch(m.history, m.rsearch.query, m.rsearch.cycle)
	return m
}

// reverseSearchKey drives the Ctrl-R prompt: typing filters, Ctrl-R cycles, Enter
// accepts the match into the input, Esc/Ctrl-C cancels.
func (m model) reverseSearchKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "ctrl+c":
		m.rsearch = reverseSearch{}
		return m, nil
	case "enter":
		match := m.rsearch.match
		m.rsearch = reverseSearch{}
		if match != "" {
			m.setDraft(match)
			m.ta.CursorEnd()
			m = m.refreshPalette()
		}
		return m, textarea.Blink
	case "ctrl+r":
		m.rsearch.cycle++
		return m.updateReverseMatch(), nil
	case "backspace":
		if m.rsearch.query != "" {
			r := []rune(m.rsearch.query)
			m.rsearch.query = string(r[:len(r)-1])
		}
		m.rsearch.cycle = 0
		return m.updateReverseMatch(), nil
	default:
		if len(msg.Runes) > 0 {
			m.rsearch.query += string(msg.Runes)
			m.rsearch.cycle = 0
			m = m.updateReverseMatch()
		}
		return m, nil
	}
}

// reverseSearchView renders the reverse-search prompt in place of the input,
// fitted to the terminal width. The label shrinks, then goes, before the query
// is cut; the match tail gets the ASCII ellipsis, and its "(ctrl+r for next)"
// hint is the first thing dropped. The query and the match come from typing
// and history, so both are sanitized and reduced to one line.
func (m model) reverseSearchView() string {
	w, _ := m.termSize()
	q := oneLine(sanitizeTerminal(m.rsearch.query))
	tail, tailStyle, hint := oneLine(sanitizeTerminal(m.rsearch.match)), Body, ""
	switch {
	case m.rsearch.match != "":
		if m.rsearch.count > 1 {
			hint = "  (ctrl+r for next)"
		}
	case strings.TrimSpace(m.rsearch.query) == "":
		tail, tailStyle = "type to search history", Meta
	default:
		tail, tailStyle = "no match", Meta
	}

	// Pick the longest label that still leaves room for a useful stretch of the
	// tail. The line is " " + label + " `" + query + "':" + " " + tail.
	label, room := "", 0
	for _, l := range []string{"(reverse-i-search)", "(i-search)", ""} {
		label = l
		head := 1 + 3 + lipgloss.Width(q)
		if l != "" {
			head += lipgloss.Width(l) + 1
		}
		if room = w - head - 1; room >= min(lipgloss.Width(tail), 4) {
			break
		}
	}
	if room < 0 { // even the bare query is too wide
		q = ellipsize(q, max(w-4, 0))
		room = 0
	}

	line := " "
	if label != "" {
		line += Meta.Render(label) + " "
	}
	line += Prompt.Render("`") + Body.Render(q) + Prompt.Render("':")
	switch tw := lipgloss.Width(tail); {
	case tail == "":
	case room >= tw+lipgloss.Width(hint):
		line += " " + tailStyle.Render(tail) + Meta.Render(hint)
	case room >= 1:
		line += " " + tailStyle.Render(ellipsize(tail, room))
	}
	return lipgloss.NewStyle().MaxWidth(w).Render(line)
}
