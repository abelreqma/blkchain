package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func manySessions(n int) []sessionMeta {
	metas := make([]sessionMeta, n)
	for i := range metas {
		metas[i] = sessionMeta{ID: fmt.Sprintf("id%02d", i), Title: fmt.Sprintf("row-%02d", i), MsgCount: i}
	}
	// One row with a 500 character unbroken title.
	metas[1].Title = "row-01-" + strings.Repeat("T", 500)
	return metas
}

func manyModels(n int) []string {
	models := make([]string, n)
	for i := range models {
		models[i] = fmt.Sprintf("model-%02d", i)
	}
	models[1] = "model-01-" + strings.Repeat("M", 500)
	return models
}

// checkBox asserts the box invariants: every line has the same width, every
// line ends in the same border rune it starts with (the right border is
// intact), no wider than the terminal minus 2, no taller than the terminal
// minus 4.
func checkBox(t *testing.T, label, view string, w, h int) {
	t.Helper()
	lines := strings.Split(view, "\n")
	want := lipgloss.Width(lines[0])
	for i, ln := range lines {
		if got := lipgloss.Width(ln); got != want {
			t.Errorf("%s: line %d is %d columns, top border is %d: %q", label, i, got, want, ln)
		}
		r := []rune(sanitizeTerminal(ln)) // drop ANSI so the border runes are visible
		if r[0] == ' ' || r[len(r)-1] == ' ' {
			t.Errorf("%s: line %d has a missing border: %q", label, i, ln)
		}
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
}

func visibleRows(view, prefix string) int {
	n := 0
	for _, ln := range strings.Split(view, "\n") {
		if strings.Contains(ln, prefix) {
			n++
		}
	}
	return n
}

func TestResumePickerFitsEveryTerminal(t *testing.T) {
	for _, w := range layoutWidths {
		for _, h := range layoutHeights {
			p := newHistoryPicker(manySessions(20), "id15", w)
			view := p.View(w, h)
			label := fmt.Sprintf("resume %dx%d", w, h)
			checkBox(t, label, view, w, h)
			if rows := visibleRows(view, "row-"); rows < 3 {
				t.Errorf("%s: only %d list rows visible, want >= 3", label, rows)
			}
			if !strings.Contains(view, "row-15") {
				t.Errorf("%s: selected row scrolled out of view", label)
			}
		}
	}
}

// With real ANSI styling on, cutting a long row must keep the styled text
// intact and the box the same width on every line.
func TestPickersFitWithColorEnabled(t *testing.T) {
	old := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(old)
	for _, w := range layoutWidths {
		for _, h := range layoutHeights {
			checkBox(t, fmt.Sprintf("color resume %dx%d", w, h), newHistoryPicker(manySessions(20), "id01", w).View(w, h), w, h)
			checkBox(t, fmt.Sprintf("color model %dx%d", w, h), newModelPicker(manyModels(20), "model-01", "low", w).View(w, h), w, h)
		}
	}
}

func TestResumePickerFewSessionsShrinks(t *testing.T) {
	p := newHistoryPicker(manySessions(2), "", 80)
	view := p.View(80, 50)
	checkBox(t, "resume small", view, 80, 50)
	if got := len(strings.Split(view, "\n")); got > 12 {
		t.Errorf("two sessions should not fill a tall overlay, got %d rows", got)
	}
	empty := newHistoryPicker(nil, "", 80)
	checkBox(t, "resume empty", empty.View(80, 24), 80, 24)
}

func TestResumePickerResizeRecomputes(t *testing.T) {
	p := newHistoryPicker(manySessions(20), "id15", 120)
	big := p.View(120, 50)
	small := p.View(40, 10)
	if lipgloss.Width(strings.Split(small, "\n")[0]) >= lipgloss.Width(strings.Split(big, "\n")[0]) {
		t.Errorf("box did not narrow with the terminal")
	}
	if len(strings.Split(small, "\n")) >= len(strings.Split(big, "\n")) {
		t.Errorf("box did not shorten with the terminal")
	}
	// Growing back restores the size: the picker keeps no stale geometry.
	if again := p.View(120, 50); again != big {
		t.Errorf("view after resize round trip differs from the original")
	}
}

func TestModelPickerFitsEveryTerminal(t *testing.T) {
	for _, w := range layoutWidths {
		for _, h := range layoutHeights {
			p := newModelPicker(manyModels(20), "model-15", "high", w)
			view := p.View(w, h)
			label := fmt.Sprintf("model %dx%d", w, h)
			checkBox(t, label, view, w, h)
			if rows := visibleRows(view, "model-"); rows < 3 {
				t.Errorf("%s: only %d model rows visible, want >= 3", label, rows)
			}
			if !strings.Contains(view, "model-15") {
				t.Errorf("%s: selected model scrolled out of view", label)
			}
			if !strings.Contains(view, "high") || !strings.Contains(view, "REASONING") {
				t.Errorf("%s: reasoning column clipped:\n%s", label, view)
			}
		}
	}
}

func TestOverlayNarrowTerminalsDoNotPanic(t *testing.T) {
	for _, w := range []int{1, 2, 3, 5, 8, 12, 20, 30} {
		for _, h := range []int{1, 3, 6, 10} {
			_ = newHistoryPicker(manySessions(5), "id01", w).View(w, h)
			_ = newModelPicker(manyModels(5), "", "", w).View(w, h)
		}
	}
}

func TestOverlayBoxGeometryClamps(t *testing.T) {
	spec := overlaySpec{
		title: "TITLE", wantW: 500, wantRows: 50,
		body: func(w, rows int) string {
			if w < 1 || rows < 1 {
				t.Errorf("body called with non-positive size %dx%d", w, rows)
			}
			return strings.Repeat(strings.Repeat("b", w)+"\n", rows-1) + strings.Repeat("b", w)
		},
	}
	for _, w := range []int{8, 40, 200} {
		for _, h := range []int{10, 24, 60} {
			checkBox(t, fmt.Sprintf("spec %dx%d", w, h), overlayBox(spec, w, h), w, h)
		}
	}
}

// On terminals too short for the comfortable minimum, the title goes and the
// list shrinks to a single row that still holds the selection. Whatever the
// size, the body is never asked for a non-positive size and never overruns it.
func TestOverlayBoxShrinksOnShortTerminals(t *testing.T) {
	var asked [][2]int
	spec := overlaySpec{
		title: "TITLE", wantW: 72, wantRows: 9, minRows: 4,
		body: func(w, rows int) string {
			asked = append(asked, [2]int{w, rows})
			if w < 1 || rows < 1 {
				t.Errorf("body called with non-positive size %dx%d", w, rows)
			}
			return strings.Repeat("b\n", rows-1) + "b"
		},
	}
	for h := 1; h <= 24; h++ {
		for w := 1; w <= 80; w++ {
			view := overlayBox(spec, w, h)
			if got := len(strings.Split(view, "\n")); got > max(h-4, 3) {
				t.Errorf("%dx%d: box is %d rows, limit is %d", w, h, got, max(h-4, 3))
			}
		}
	}
	if len(asked) == 0 {
		t.Fatal("body never called")
	}

	for h := 6; h <= 9; h++ {
		p := newHistoryPicker(manySessions(20), "id15", 40)
		view := p.View(40, h)
		if strings.Contains(view, "HISTORY") || !strings.Contains(view, "row-15") {
			t.Errorf("height %d: want no title and the selected row visible:\n%s", h, view)
		}
		if n := len(strings.Split(p.View(40, h), "\n")); n+2 > h {
			t.Errorf("height %d: box of %d rows plus status and footer does not fit", h, n)
		}
		for name, ov := range map[string]overlayModel{
			"model": newModelPicker(manyModels(20), "model-15", "high", 40),
			"file":  newFilePicker(t.TempDir(), 40),
		} {
			if n := len(strings.Split(ov.View(40, h), "\n")); n+2 > h {
				t.Errorf("%s height %d: box of %d rows plus status and footer does not fit", name, h, n)
			}
		}
	}
}

// The state-aware footer under the view is the only key hint line, so no overlay
// draws its own inside the box.
func TestOverlaysDrawNoInBoxKeyFooter(t *testing.T) {
	views := map[string]string{
		"resume": newHistoryPicker(manySessions(3), "", 100).View(100, 30),
		"model":  newModelPicker(manyModels(3), "model-00", "low", 100).View(100, 30),
		"file":   newFilePicker(t.TempDir(), 100).View(100, 30),
	}
	for name, v := range views {
		for _, hint := range []string{"esc", "enter", "type to filter", "backspace", "d then y", "any key", "to confirm"} {
			if strings.Contains(v, hint) {
				t.Errorf("%s overlay draws a key hint %q inside the box:\n%s", name, hint, v)
			}
		}
	}
	confirming := newHistoryPicker(manySessions(3), "", 100)
	confirming.confirm = true
	if v := confirming.View(100, 30); strings.Contains(v, "confirm") {
		t.Errorf("resume delete prompt must live in the footer, not the box:\n%s", v)
	}
}

func TestFilePickerHeaderSanitizesDirectory(t *testing.T) {
	p := newFilePicker(t.TempDir(), 80)
	p.dir = "/tmp/a\x1b]0;x\x07b"
	for _, w := range []int{40, 80} {
		view := p.View(w, 30)
		if strings.ContainsAny(view, "\x1b\x07") {
			t.Errorf("width %d: control bytes reached the terminal: %q", w, view)
		}
		if !strings.Contains(sanitizeTerminal(view), "/tmp/a") {
			t.Errorf("width %d: directory header is missing:\n%s", w, view)
		}
	}
}

func TestFilePickerEmptyDirectoryKeepsHeader(t *testing.T) {
	p := newFilePicker(t.TempDir(), 80)
	p.dir = "/some/empty/dir"
	p.all = nil
	view := p.View(80, 30)
	if !strings.Contains(view, "/some/empty/dir") || !strings.Contains(view, "empty directory") {
		t.Errorf("an empty directory must still name itself:\n%s", view)
	}
}
