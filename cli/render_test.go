package main

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"blkchain/cli/internal/retrieval"
)

func TestGlowRenderNonEmpty(t *testing.T) {
	out := glowRender("# Heading\n\nSome **bold** prose.", 80)
	if strings.TrimSpace(out) == "" {
		t.Fatal("glowRender returned empty output for non-empty markdown")
	}
	if !strings.Contains(out, "Heading") {
		t.Errorf("glowRender output missing heading text, got:\n%s", out)
	}
	if !strings.Contains(out, "bold") {
		t.Errorf("glowRender output missing body text, got:\n%s", out)
	}
}

func TestGlowRenderNoANSIWhenColorDisabled(t *testing.T) {
	old := useColor
	useColor = false
	defer func() { useColor = old }()

	out := glowRender("# Heading\n\nSome **bold** prose with `code`.", 80)
	if strings.TrimSpace(out) == "" {
		t.Fatal("glowRender returned empty output")
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("glowRender emitted an ANSI escape with color disabled:\n%q", out)
	}
}

func TestHeaderLine(t *testing.T) {
	got := headerLine("left", "right", 80)
	if !strings.HasPrefix(got, "left") || !strings.HasSuffix(got, "right") {
		t.Fatalf("headerLine(%q, %q) = %q, want left...right", "left", "right", got)
	}
}

// headerLine must use the width it is given, not the OS terminal width, so it
// is right inside the TUI after a resize and when output is piped.
func TestHeaderLineUsesGivenWidth(t *testing.T) {
	for _, w := range []int{20, 40, 60, 80, 120} {
		got := headerLine("left", "right", w)
		want := wrapWidth(w, 78)
		if lipgloss.Width(got) != want {
			t.Errorf("headerLine width %d: got %d columns, want %d", w, lipgloss.Width(got), want)
		}
	}
}

func TestHeaderLineNeverOverflows(t *testing.T) {
	long := strings.Repeat("x", 500)
	for _, w := range []int{1, 2, 5, 10, 40, 60, 80, 120} {
		limit := wrapWidth(w, 78)
		for _, c := range [][2]string{{long, "0.9000"}, {"left", long}, {long, long}, {"", ""}} {
			got := headerLine(c[0], c[1], w)
			if lipgloss.Width(got) > limit {
				t.Errorf("headerLine width %d: %d columns exceeds %d", w, lipgloss.Width(got), limit)
			}
		}
	}
}

func TestEllipsize(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 10, "this is..."},
		{"abcdef", 3, "..."},
		{"abcdef", 2, ".."},
		{"abcdef", 0, ""},
		{"abcdef", -4, ""},
	}
	for _, c := range cases {
		if got := ellipsize(c.in, c.n); got != c.want {
			t.Errorf("ellipsize(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

func TestWrapIndentHardBreaksLongToken(t *testing.T) {
	token := strings.Repeat("A", 500)
	for _, w := range []int{1, 5, 34, 74} {
		out := wrapIndent("see "+token+" end", 6, w+6)
		joined := ""
		for _, ln := range strings.Split(out, "\n") {
			if lipgloss.Width(ln) > w+6 {
				t.Errorf("width %d: line %q is %d columns", w, ln, lipgloss.Width(ln))
			}
			if !strings.HasPrefix(ln, "      ") {
				t.Errorf("width %d: line %q lost its indent", w, ln)
			}
			joined += strings.TrimSpace(ln)
		}
		if !strings.Contains(joined, token) {
			t.Errorf("width %d: wrapping lost token characters", w)
		}
	}
}

func resultsFixture(text string) []retrieval.Result {
	return []retrieval.Result{{
		ID:    "p1",
		Score: 0.9123,
		Payload: retrieval.Payload{
			Source:  "source-" + strings.Repeat("s", 120),
			Section: "section " + strings.Repeat("x", 120),
			Path:    "corpus/" + strings.Repeat("p", 300) + ".md",
			Type:    "markdown",
			Text:    text,
		},
	}}
}

func TestFormatResultsCollapsesWhitespace(t *testing.T) {
	text := "first line\nsecond\tline\r\n\n\n    third   line\n"
	out := formatResults("q", resultsFixture(text), 0, 120)
	if !strings.Contains(out, "first line second line third line") {
		t.Errorf("preview whitespace not collapsed to single spaces:\n%q", out)
	}
	// Only the fixed layout lines may exist: banner, blank, row, path, preview, blank.
	for _, ln := range strings.Split(out, "\n") {
		if ln != "" && !strings.HasPrefix(ln, " ") {
			t.Errorf("line %q lost its indent", ln)
		}
	}
}

func TestFormatResultsNeverOverflows(t *testing.T) {
	token := strings.Repeat("Z", 200)
	texts := []string{
		"plain preview text " + strings.Repeat("word ", 100),
		"payload " + token + " tail",
		strings.Repeat("Q", 500),
	}
	for _, w := range []int{40, 60, 80, 120} {
		for _, text := range texts {
			out := formatResults("query "+strings.Repeat("q", 300), resultsFixture(text), 5*time.Millisecond, w)
			for _, ln := range strings.Split(out, "\n") {
				if lipgloss.Width(ln) > w {
					t.Errorf("width %d: line is %d columns: %q", w, lipgloss.Width(ln), ln)
				}
			}
		}
	}
}

func TestFormatResultsKeepsWholeShortToken(t *testing.T) {
	token := strings.Repeat("Z", 200)
	out := formatResults("q", resultsFixture("payload "+token+" tail"), 0, 40)
	var b strings.Builder
	for _, ln := range strings.Split(out, "\n") {
		b.WriteString(strings.TrimSpace(ln))
	}
	if !strings.Contains(b.String(), token) {
		t.Errorf("hard-broken token lost characters:\n%s", out)
	}
}

// The width guards must hold with real ANSI styling too, where the raw string
// is longer than the visible width.
func TestFormatResultsNeverOverflowsWithColor(t *testing.T) {
	old := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(old)
	for _, w := range []int{40, 60, 80, 120} {
		out := formatResults("query "+strings.Repeat("q", 300), resultsFixture(strings.Repeat("Q", 500)), 5*time.Millisecond, w)
		for _, ln := range strings.Split(out, "\n") {
			if lipgloss.Width(ln) > w {
				t.Errorf("width %d: line is %d columns: %q", w, lipgloss.Width(ln), ln)
			}
		}
		if got := headerLine(strings.Repeat("L", 500), Meta.Render("0.9000"), w); lipgloss.Width(got) > wrapWidth(w, 78) {
			t.Errorf("width %d: styled headerLine is %d columns", w, lipgloss.Width(got))
		}
	}
}

func TestFormatResultsTinyWidthDoesNotPanic(t *testing.T) {
	for _, w := range []int{-5, 0, 1, 2, 3, 8, 15} {
		_ = formatResults("q", resultsFixture("some text"), time.Second, w)
	}
}
