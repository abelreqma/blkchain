package main

import (
	"testing"

	"github.com/charmbracelet/bubbles/textarea"
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
