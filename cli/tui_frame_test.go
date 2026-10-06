package main

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"blkchain/cli/internal/ragconfig"
)

// frameModel is a TUI session at 80x24 with isolated user dirs, dead services,
// and no OMLX_MODEL, so the status line shows the configured default model.
func frameModel(tb testing.TB) model {
	tb.Helper()
	tb.Setenv("XDG_CONFIG_HOME", tb.TempDir())
	tb.Setenv("XDG_DATA_HOME", tb.TempDir())
	tb.Setenv("HOME", tb.TempDir())
	tb.Setenv("OMLX_MODEL", "")
	tb.Setenv("BLK_REDUCE_MOTION", "")
	m := initialModel()
	m.mode = "rag"
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	return nm.(model)
}

// streamInto feeds text to m as chunkMsgs of n bytes, the way a stream arrives.
func streamInto(m model, text string, n int) model {
	for len(text) > 0 {
		k := min(n, len(text))
		nm, _ := m.Update(chunkMsg(text[:k]))
		m = nm.(model)
		text = text[k:]
	}
	return m
}

// The config is read once, when the session starts. Frames, turns, and the
// answer loop never read rag.json again.
func TestTUIReadsConfigOnceAtStart(t *testing.T) {
	useDeadServices(t)
	prev := loadConfig
	calls := 0
	loadConfig = func() ragconfig.Config {
		calls++
		cfg := prev()
		cfg.DefaultModel = "seam-model"
		return cfg
	}
	t.Cleanup(func() { loadConfig = prev })

	m := frameModel(t)
	if calls != 1 {
		t.Fatalf("starting the session read the config %d times, want 1", calls)
	}
	if !strings.Contains(m.View(), "seam-model") {
		t.Errorf("the status line does not show the configured model:\n%s", m.View())
	}
	for range 5 {
		_ = m.View()
	}
	nm, cmd := m.dispatchInput("/search ssrf")
	if cmd == nil {
		t.Fatal("no command for a search turn")
	}
	_ = nm.(model).View()
	nm.(model).cancel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = m.streamCmd(ctx, "q", "", time.Now(), false)()
	if calls != 1 {
		t.Errorf("frames, a dispatched turn, and the answer loop read the config %d more times, want 0", calls-1)
	}

	// The plain REPL has no session, so it reads the config through the seam.
	calls = 0
	if got := ragModelLabel(); got != "seam-model" || calls != 1 {
		t.Errorf("ragModelLabel() = %q after %d loadConfig calls, want seam-model after 1", got, calls)
	}
}

// liveReference is the live region's text as it was built before the cache:
// the whole buffer sanitized, trailing newlines trimmed, and wrapped at once.
func liveReference(live string, width int) []string {
	wrapped := lipgloss.NewStyle().Width(width).Render(strings.TrimRight(sanitizeTerminal(live), "\n"))
	lines := strings.Split(wrapped, "\n")
	for i := range lines {
		lines[i] = " " + Meta.Render(Glyph(GlyphBar)) + " " + Body.Render(strings.TrimRight(lines[i], " "))
	}
	return lines
}

// The live region shows the same text whether it is built at once or chunk by
// chunk, including an escape sequence split across chunks, and after a resize.
func TestLiveRegionIncrementalMatchesWhole(t *testing.T) {
	useDeadServices(t)
	stream := longStream(40) + "tail with \x1b]0;evil-title\x07 hidden osc and " + strings.Repeat("W", 150) + " end"
	for _, n := range []int{1, 7, 64} {
		m := frameModel(t)
		m.working = true
		m = streamInto(m, stream, n)
		whole := m
		whole.liveCache = nil
		for _, rows := range []int{0, 1, 8} {
			got, want := m.liveRegion(rows), whole.liveRegion(rows)
			if got != want {
				t.Fatalf("chunks of %d, %d rows: incremental\n%s\nwant\n%s", n, rows, got, want)
			}
		}
		if lr := m.liveRegion(0); strings.Contains(lr, "evil-title") || strings.ContainsRune(lr, 0x1b) {
			t.Fatalf("chunks of %d: the split escape sequence reached the live region:\n%q", n, lr)
		}
		if lr := m.liveRegion(0); !strings.Contains(lr, "line 39 of the streamed answer") || !strings.Contains(lr, "hidden osc and") {
			t.Fatalf("chunks of %d: streamed text is missing:\n%s", n, lr)
		}
		if got, want := m.liveRegion(0), strings.Join(liveReference(m.live, 77), "\n"); got != want {
			t.Fatalf("chunks of %d: live region differs from wrapping the whole buffer:\n%s\nwant\n%s", n, got, want)
		}

		nm, _ := m.Update(tea.WindowSizeMsg{Width: 50, Height: 24})
		m = nm.(model)
		whole = m
		whole.liveCache = nil
		if got, want := m.liveRegion(0), whole.liveRegion(0); got != want {
			t.Fatalf("chunks of %d after a resize: incremental\n%s\nwant\n%s", n, got, want)
		}
	}
}

// Blank lines inside the stream stay, trailing ones wait for more text, and
// tabs and long runs wrap as the whole buffer would.
func TestLiveRegionMatchesWholeBufferShapes(t *testing.T) {
	useDeadServices(t)
	for _, stream := range []string{
		"a\n\n\nb\n\n",
		"a\n  \n",
		"\tindented\twith tabs\n" + strings.Repeat("Z", 300) + "\nlast",
		"\x1b[31mred\x1b[0m and \x9b2J c1\n\u009d0;t\x07after",
	} {
		m := frameModel(t)
		m.working = true
		m = streamInto(m, stream, 3)
		if got, want := m.liveRegion(0), strings.Join(liveReference(m.live, 77), "\n"); got != want {
			t.Errorf("%q: live region\n%q\nwant\n%q", stream, got, want)
		}
	}
}

// A new turn starts the live region over.
func TestLiveRegionResetsForANewBuffer(t *testing.T) {
	useDeadServices(t)
	m := frameModel(t)
	m.working = true
	m = streamInto(m, longStream(30), 16)
	_ = m.liveRegion(0)
	m.live = "fresh answer"
	if got := m.liveRegion(0); strings.Contains(got, "line 29") || !strings.Contains(got, "fresh answer") {
		t.Errorf("live region after a new buffer:\n%s", got)
	}
}

// BenchmarkViewIdle is an idle frame: the status line, the input, and the
// footer, with the default model shown.
func BenchmarkViewIdle(b *testing.B) {
	useDeadServices(b)
	m := frameModel(b)
	b.ReportAllocs()
	for b.Loop() {
		_ = m.View()
	}
}

// BenchmarkViewLive5000 is a frame while a 5000-line answer streams in: one
// token arrives per frame, and every twelfth ends its line.
func BenchmarkViewLive5000(b *testing.B) {
	useDeadServices(b)
	m := frameModel(b)
	m.working = true
	m = streamInto(m, longStream(5000), 4096)
	_ = m.View()
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		tok := chunkMsg("tok ")
		if i++; i%12 == 0 {
			tok = "tok\n"
		}
		nm, _ := m.Update(tok)
		m = nm.(model)
		_ = m.View()
	}
}
