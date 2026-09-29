package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/lipgloss"
)

func TestMatchCommand(t *testing.T) {
	cases := []struct {
		name, query string
		wantOK      bool
		wantRank    int
	}{
		{"model", "", true, 0},     // empty query matches everything
		{"model", "mo", true, 3},   // prefix
		{"model", "del", true, 2},  // substring
		{"model", "mdl", true, 1},  // subsequence
		{"model", "xyz", false, 0}, // no match
		{"model", "MO", true, 3},   // case-insensitive prefix
	}
	for _, tc := range cases {
		pos, ok, rank := matchCommand(tc.name, tc.query)
		if ok != tc.wantOK || rank != tc.wantRank {
			t.Errorf("matchCommand(%q,%q) = (ok=%v rank=%d), want (ok=%v rank=%d)",
				tc.name, tc.query, ok, rank, tc.wantOK, tc.wantRank)
		}
		if ok && tc.query != "" && len(pos) != len(tc.query) {
			t.Errorf("matchCommand(%q,%q) pos len = %d, want %d", tc.name, tc.query, len(pos), len(tc.query))
		}
	}
}

func TestFilterCommandsPrefixFirst(t *testing.T) {
	cmds := []command{
		{name: "attach", desc: "a"},
		{name: "ask", desc: "b"},
		{name: "clear", desc: "c"}, // contains 'a' (substring), not prefix
		{name: "model", desc: "d"}, // no 'a'
	}
	got := filterCommands(cmds, "a")
	if len(got) != 3 {
		t.Fatalf("filterCommands('a') returned %d, want 3: %+v", len(got), got)
	}
	// Prefix matches (attach, ask) rank above the substring match (clear).
	if got[len(got)-1].name != "clear" {
		t.Errorf("substring match should sort last, got order %v", names(got))
	}
	if got[0].name != "attach" && got[0].name != "ask" {
		t.Errorf("prefix match should sort first, got %q", got[0].name)
	}
}

func TestFilterCommandsExactMatchWins(t *testing.T) {
	got := filterCommands(slashCommands(), "open")
	if len(got) == 0 || got[0].name != "open" {
		t.Fatalf("filterCommands('open') first = %v, want open", names(got))
	}
}

func names(items []paletteItem) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.name
	}
	return out
}

func TestRefreshPaletteActivation(t *testing.T) {
	m := model{ta: textarea.New()}

	m.ta.SetValue("/mo")
	m = m.refreshPalette()
	if !m.pal.open {
		t.Fatal("palette should open for a slash command in progress")
	}
	found := false
	for _, it := range m.pal.items {
		if it.name == "model" || it.name == "mode" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected model/mode in palette items, got %v", names(m.pal.items))
	}

	// A space (args mode) closes it.
	m.ta.SetValue("/mode ")
	m = m.refreshPalette()
	if m.pal.open {
		t.Error("palette should close once the command has a trailing space (args mode)")
	}

	// A non-slash draft closes it.
	m.ta.SetValue("how does this work")
	m = m.refreshPalette()
	if m.pal.open {
		t.Error("palette should not open for a plain question")
	}
}

func TestCompleteSelected(t *testing.T) {
	m := model{ta: textarea.New()}
	m.ta.SetValue("/mod")
	m = m.refreshPalette()
	// Force selection onto "model" if present.
	for i, it := range m.pal.items {
		if it.name == "model" {
			m.pal.selected = i
		}
	}
	m = m.completeSelected()
	if got := m.ta.Value(); got != "/model " {
		t.Errorf("completeSelected wrote %q, want %q", got, "/model ")
	}
	if m.pal.open {
		t.Error("palette should close after completing (trailing space = args mode)")
	}
}

func TestIsExactCommand(t *testing.T) {
	if !isExactCommand("help") {
		t.Error("help should be an exact command")
	}
	if isExactCommand("nope") {
		t.Error("nope should not be an exact command")
	}
}

func paletteFixture(w, h, selected int) model {
	m := model{ta: textarea.New(), width: w, height: h}
	m.pal.open = true
	m.pal.items = filterCommands(slashCommands(), "")
	m.pal.selected = selected
	return m
}

func TestPaletteFitsEveryTerminal(t *testing.T) {
	for _, w := range []int{40, 60, 80, 120} {
		for _, h := range []int{10, 24, 50} {
			for _, sel := range []int{0, 12, 24} {
				m := paletteFixture(w, h, sel)
				// The layout hands the palette at most h-4 rows of the terminal.
				view := m.paletteView(w, h-4)
				label := fmt.Sprintf("palette %dx%d sel %d", w, h, sel)
				lines := strings.Split(view, "\n")
				want := lipgloss.Width(lines[0])
				for i, ln := range lines {
					if got := lipgloss.Width(ln); got != want {
						t.Errorf("%s: line %d is %d columns, top border is %d: %q", label, i, got, want, ln)
					}
					r := []rune(sanitizeTerminal(ln))
					if i > 0 && i < len(lines)-1 && r[0] != r[len(r)-1] {
						t.Errorf("%s: line %d right border was cut: %q", label, i, ln)
					}
				}
				if want > w-2 {
					t.Errorf("%s: box is %d columns, limit is %d", label, want, w-2)
				}
				if len(lines) > h-4 {
					t.Errorf("%s: box is %d rows, limit is %d", label, len(lines), h-4)
				}
				// The selected command name and args are always fully visible.
				it := m.pal.items[sel]
				name := "/" + it.name
				if it.args != "" {
					name += " " + it.args
				}
				if !strings.Contains(view, name) {
					t.Errorf("%s: selected row %q clipped:\n%s", label, name, view)
				}
			}
		}
	}
}

func TestPaletteRowTruncatesDescriptionWithAsciiEllipsis(t *testing.T) {
	it := paletteItem{name: "search", args: "<q>", desc: "find ranked source chunks and then some more words to overflow"}
	row := paletteRow(it, false, 0, 40)
	if lipgloss.Width(row) > 40 {
		t.Errorf("row is %d columns, want <= 40: %q", lipgloss.Width(row), row)
	}
	if !strings.Contains(row, "/search <q>") {
		t.Errorf("command name column must stay whole: %q", row)
	}
	if !strings.HasSuffix(strings.TrimRight(row, " "), "...") {
		t.Errorf("truncated description should end in an ASCII ellipsis: %q", row)
	}
	if strings.ContainsRune(row, '…') {
		t.Errorf("row uses a unicode ellipsis: %q", row)
	}
	// A description that fits is left alone.
	fit := paletteRow(paletteItem{name: "help", desc: "this help"}, false, 0, 40)
	if strings.Contains(fit, "...") || !strings.Contains(fit, "this help") {
		t.Errorf("short description was altered: %q", fit)
	}
	// With no room for a description, the name column still survives.
	tight := paletteRow(it, false, 16, 14)
	if !strings.Contains(tight, "/search <q>") {
		t.Errorf("name clipped at tight width: %q", tight)
	}
}

func TestPaletteNarrowTerminalsDoNotPanic(t *testing.T) {
	for _, w := range []int{-1, 0, 1, 2, 5, 10, 20} {
		for _, h := range []int{-1, 0, 1, 4, 10} {
			_ = paletteFixture(w, h, 3).paletteView(w, h)
		}
	}
}

func TestHealthCommandDescriptionNamesEveryService(t *testing.T) {
	for _, c := range slashCommands() {
		if c.name != "health" {
			continue
		}
		for _, svc := range []string{"qdrant", "embed_server", "llm"} {
			if !strings.Contains(strings.ToLower(c.desc), svc) {
				t.Errorf("/health description %q does not name %s", c.desc, svc)
			}
		}
		return
	}
	t.Fatal("no /health command")
}

// The palette is clamped to the rows it is given: never taller, empty when it
// cannot show one command row, and the selected row stays visible.
func TestPaletteClampsToGivenRows(t *testing.T) {
	for _, sel := range []int{0, 12, 24} {
		m := paletteFixture(80, 24, sel)
		for maxH := 0; maxH <= 14; maxH++ {
			view := m.paletteView(80, maxH)
			if maxH < 3 {
				if view != "" {
					t.Errorf("maxHeight %d: want no palette, got %q", maxH, view)
				}
				continue
			}
			if n := len(strings.Split(view, "\n")); n > maxH {
				t.Errorf("maxHeight %d sel %d: palette is %d rows", maxH, sel, n)
			}
			if !strings.Contains(view, "/"+m.pal.items[sel].name) {
				t.Errorf("maxHeight %d sel %d: selected row scrolled out of view:\n%s", maxH, sel, view)
			}
		}
	}
}

// Every description starts in one column, whatever the width of its command
// name, and the name column is never cut.
func TestPaletteAlignsDescriptionsInOneColumn(t *testing.T) {
	noColor(t)
	m := paletteFixture(100, 30, 0)
	view := m.paletteView(100, 30)
	want := -1
	rows := 0
	for _, ln := range strings.Split(view, "\n") {
		for _, it := range m.pal.items {
			// The start of the description is enough to find it; a long one is cut.
			start := it.desc[:min(len(it.desc), 20)]
			if it.desc == "" || !strings.Contains(ln, start) {
				continue
			}
			col := lipgloss.Width(ln[:strings.Index(ln, start)])
			if want < 0 {
				want = col
			}
			if col != want {
				t.Errorf("/%s description starts at column %d, want %d: %q", it.name, col, want, ln)
			}
			rows++
		}
	}
	if rows < maxPaletteRows {
		t.Fatalf("checked %d rows, want %d:\n%s", rows, maxPaletteRows, view)
	}
}

func TestPaletteNameColumnStaysWholeWhenDescriptionsCut(t *testing.T) {
	noColor(t)
	m := paletteFixture(40, 30, 0)
	view := m.paletteView(40, 30)
	for _, it := range m.pal.items[:maxPaletteRows] {
		name := "/" + it.name
		if it.args != "" {
			name += " " + it.args
		}
		if !strings.Contains(view, name) {
			t.Errorf("name %q cut at 40 columns:\n%s", name, view)
		}
	}
	if !strings.Contains(view, "...") || strings.ContainsRune(view, '\u2026') {
		t.Errorf("cut descriptions must end in an ASCII ellipsis:\n%s", view)
	}
}

func TestPaletteOverflowRowSaysHowToNarrow(t *testing.T) {
	noColor(t)
	m := paletteFixture(80, 30, 0)
	want := fmt.Sprintf("+%d more, keep typing to filter", len(m.pal.items)-maxPaletteRows)
	if view := m.paletteView(80, 30); !strings.Contains(view, want) {
		t.Errorf("overflow row lacks %q:\n%s", want, view)
	}
	// On a box too narrow for the hint, the count survives.
	narrow := paletteFixture(28, 30, 0)
	if view := narrow.paletteView(28, 30); !strings.Contains(view, "more") || !strings.Contains(view, "+") {
		t.Errorf("narrow overflow row lost its count:\n%s", view)
	}
}

func TestSlashHelpGroupsFollowVocabulary(t *testing.T) {
	var titles []string
	for _, g := range commandGroups() {
		titles = append(titles, g.title)
	}
	want := []string{"Ask and search", "Modes", "Session", "Services", "Agent (Hermes)", "Setup"}
	if strings.Join(titles, "|") != strings.Join(want, "|") {
		t.Errorf("groups = %v, want %v", titles, want)
	}
	// /agent and /rag stay in the palette but are folded into /mode in help.
	for _, g := range commandGroups() {
		for _, c := range g.cmds {
			if c.name == "agent" || c.name == "rag" {
				t.Errorf("/%s must not be a separate help row", c.name)
			}
		}
	}
	if !isExactCommand("agent") || !isExactCommand("rag") {
		t.Error("/agent and /rag must still be commands")
	}
}
