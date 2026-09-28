package main

import (
	"strings"
	"testing"
)

func TestParseInput(t *testing.T) {
	cases := []struct {
		in       string
		wantVerb string
		wantArg  string
	}{
		{"", "", ""},
		{"   ", "", ""},
		{"how does consensus work", "ask", "how does consensus work"},
		{"/ask what is ssrf", "ask", "what is ssrf"},
		{"/search vector tuning", "search", "vector tuning"},
		{"s vector tuning", "search", "vector tuning"},
		{"search vector tuning", "search", "vector tuning"},
		{"/open 2", "open", "2"},
		{"/open docs/a.md", "open", "docs/a.md"},
		{"/hermes summarize notes", "hermes", "summarize notes"},
		{"/health", "health", ""},
		{"/copy", "copy", ""},
		{"/quit", "quit", ""},
		{"/HELP", "help", ""},                             // verb is lowercased
		{"is search broken?", "ask", "is search broken?"}, // bare non-shorthand stays an ask
	}
	for _, tc := range cases {
		gotVerb, gotArg := parseInput(tc.in)
		if gotVerb != tc.wantVerb || gotArg != tc.wantArg {
			t.Errorf("parseInput(%q) = (%q, %q), want (%q, %q)",
				tc.in, gotVerb, gotArg, tc.wantVerb, tc.wantArg)
		}
	}
}

func TestClipboardCandidatesByGOOS(t *testing.T) {
	darwin := clipboardCandidates("darwin")
	if len(darwin) != 1 || darwin[0][0] != "pbcopy" {
		t.Errorf("clipboardCandidates(darwin) = %v, want [[pbcopy]]", darwin)
	}

	linux := clipboardCandidates("linux")
	if len(linux) != 2 || linux[0][0] != "wl-copy" || linux[1][0] != "xclip" {
		t.Errorf("clipboardCandidates(linux) = %v, want wl-copy then xclip", linux)
	}
	// xclip must target the clipboard selection, not the primary one.
	if strings.Join(linux[1], " ") != "xclip -selection clipboard" {
		t.Errorf("xclip argv = %v, want [xclip -selection clipboard]", linux[1])
	}
}

func TestClampBounds(t *testing.T) {
	cases := []struct{ v, lo, hi, want int }{
		{0, 1, 6, 1},
		{3, 1, 6, 3},
		{9, 1, 6, 6},
		{1, 1, 6, 1},
	}
	for _, tc := range cases {
		if got := clamp(tc.v, tc.lo, tc.hi); got != tc.want {
			t.Errorf("clamp(%d, %d, %d) = %d, want %d", tc.v, tc.lo, tc.hi, got, tc.want)
		}
	}
}
