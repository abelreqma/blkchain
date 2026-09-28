package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestScoreStyleBanding(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0.95, "success"},
		{0.85, "success"}, // boundary: >= 0.85 is success
		{0.849, "warn"},
		{0.65, "warn"}, // boundary: >= 0.65 is warn
		{0.649, "muted"},
		{0.0, "muted"},
	}
	for _, c := range cases {
		got := scoreStyle(c.score).GetForeground()
		var want interface{}
		switch c.want {
		case "success":
			want = Success
		case "warn":
			want = Warn
		case "muted":
			want = Muted
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("scoreStyle(%v) foreground = %v, want %v (%s)", c.score, got, want, c.want)
		}
	}
}

func TestGlyphFor(t *testing.T) {
	cases := []struct {
		name      GlyphName
		unicode   bool
		wantGlyph string
	}{
		{GlyphOK, true, "✓"},
		{GlyphOK, false, "[ok]"},
		{GlyphErr, true, "✗"},
		{GlyphErr, false, "[x]"},
		{GlyphWarn, true, "▲"},
		{GlyphWarn, false, "[!]"},
		{GlyphPrompt, true, "❯"},
		{GlyphPrompt, false, ">"},
		{GlyphBullet, true, "·"},
		{GlyphBullet, false, "-"},
		{GlyphArrow, true, "→"},
		{GlyphArrow, false, "->"},
	}
	for _, c := range cases {
		if got := glyphFor(c.name, c.unicode); got != c.wantGlyph {
			t.Errorf("glyphFor(%v, %v) = %q, want %q", c.name, c.unicode, got, c.wantGlyph)
		}
	}
}

func TestSpinnerFramesFor(t *testing.T) {
	if got := spinnerFramesFor(true); len(got) != 10 {
		t.Errorf("unicode spinner frames = %d, want 10", len(got))
	}
	if got := spinnerFramesFor(false); !reflect.DeepEqual(got, []string{"|", "/", "-", "\\"}) {
		t.Errorf("ascii spinner frames = %v", got)
	}
}

func TestDetectCapabilities(t *testing.T) {
	cases := []struct {
		name                                      string
		isTTY                                     bool
		term, noColor, cliColorForce, lcAll, lang string
		wantColor, wantUnicode                    bool
	}{
		{"plain tty utf8", true, "xterm-256color", "", "", "en_US.UTF-8", "", true, true},
		{"no_color disables", true, "xterm-256color", "1", "", "en_US.UTF-8", "", false, true},
		{"no_color overridden by force", true, "xterm-256color", "1", "1", "en_US.UTF-8", "", true, true},
		{"dumb disables color and unicode", true, "dumb", "", "", "en_US.UTF-8", "", false, false},
		{"non-tty disables color and unicode", false, "xterm-256color", "", "", "en_US.UTF-8", "", false, false},
		{"non-utf8 locale disables unicode only", true, "xterm-256color", "", "", "C", "", true, false},
		{"lang fallback utf8", true, "xterm", "", "", "", "en_US.utf8", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := detectCapabilities(c.isTTY, c.term, c.noColor, c.cliColorForce, c.lcAll, c.lang)
			if got.color != c.wantColor {
				t.Errorf("color = %v, want %v", got.color, c.wantColor)
			}
			if got.unicode != c.wantUnicode {
				t.Errorf("unicode = %v, want %v", got.unicode, c.wantUnicode)
			}
		})
	}
}

func TestWrapWidth(t *testing.T) {
	cases := []struct {
		termWidth, max, want int
	}{
		{80, 90, 78},  // termWidth-2 smaller than max
		{100, 90, 90}, // capped at max
		{0, 90, 1},    // never below 1
		{10, 0, 8},    // max<=0 means no cap
	}
	for _, c := range cases {
		if got := wrapWidth(c.termWidth, c.max); got != c.want {
			t.Errorf("wrapWidth(%d, %d) = %d, want %d", c.termWidth, c.max, got, c.want)
		}
	}
}

func TestWrap(t *testing.T) {
	// go test's stdout is not a TTY, so terminalWidth() falls back to 80.
	s := wrap(strings.Repeat("word ", 40), 20)
	for _, line := range strings.Split(s, "\n") {
		if len(line) > 20 {
			t.Errorf("wrap line exceeds max width 20: %q (%d chars)", line, len(line))
		}
	}
}

func TestLoadAppendHistory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	if got := loadHistory(); got != nil {
		t.Fatalf("loadHistory on missing file = %v, want nil", got)
	}

	if err := appendHistory("ask what is ssrf"); err != nil {
		t.Fatal(err)
	}
	if err := appendHistory("search vector index"); err != nil {
		t.Fatal(err)
	}
	// empty and duplicate-of-last should be skipped
	if err := appendHistory(""); err != nil {
		t.Fatal(err)
	}
	if err := appendHistory("   "); err != nil {
		t.Fatal(err)
	}
	if err := appendHistory("search vector index"); err != nil {
		t.Fatal(err)
	}

	got := loadHistory()
	want := []string{"ask what is ssrf", "search vector index"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loadHistory = %v, want %v", got, want)
	}

	p := filepath.Join(dir, "blkchain", "history")
	if fi, err := os.Stat(p); err != nil {
		t.Fatalf("history file not created: %v", err)
	} else if fi.Mode().Perm() != 0o644 {
		t.Fatalf("history file mode = %v, want 0644", fi.Mode().Perm())
	}
}

func TestLoadHistoryCapsAt500(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	for i := 0; i < 510; i++ {
		if err := appendHistory(fmt.Sprintf("line %d", i)); err != nil {
			t.Fatal(err)
		}
	}
	got := loadHistory()
	if len(got) != historyMaxLines {
		t.Fatalf("loadHistory len = %d, want %d", len(got), historyMaxLines)
	}
}
