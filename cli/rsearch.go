package main

import (
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
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
	case "ctrl+d":
		return m, tea.Quit
	case "enter":
		match := m.rsearch.match
		m.rsearch = reverseSearch{}
		if match != "" {
			m.ta.SetValue(match)
			m.ta.SetHeight(clamp(m.ta.LineCount(), 1, 6))
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

// reverseSearchView renders the reverse-search prompt in place of the input.
func (m model) reverseSearchView() string {
	label := Meta.Render("(reverse-i-search)")
	q := Body.Render(m.rsearch.query)
	var tail string
	switch {
	case m.rsearch.match != "":
		tail = Body.Render(m.rsearch.match)
		if m.rsearch.count > 1 {
			tail += "  " + Meta.Render("(ctrl+r for next)")
		}
	case strings.TrimSpace(m.rsearch.query) == "":
		tail = Meta.Render("type to search history")
	default:
		tail = Meta.Render("no match")
	}
	return " " + label + " " + Prompt.Render("`") + q + Prompt.Render("':") + " " + tail
}
