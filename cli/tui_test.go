package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/secgate"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

// --- keyboard and interaction regression tests ---

// newKeyModel builds a fully initialized model (real key map, help, spinner,
// textarea) with history and sessions redirected to a temp dir.
func newKeyModel(t *testing.T) model {
	t.Helper()
	isolateUserDirs(t)
	t.Setenv("BLK_REDUCE_MOTION", "")
	return initialModel()
}

// isolateUserDirs points every per-user location (config, data, home) at fresh
// temp dirs, so history and session files never touch the real ones.
func isolateUserDirs(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
}

// press sends one key and runs the returned command, if any, returning its message.
func press(t *testing.T, m model, k tea.KeyMsg) (model, tea.Msg) {
	t.Helper()
	nm, cmd := m.Update(k)
	var msg tea.Msg
	if cmd != nil {
		msg = cmd()
	}
	return nm.(model), msg
}

func isQuit(msg tea.Msg) bool {
	_, ok := msg.(tea.QuitMsg)
	return ok
}

var (
	keyCtrlC = tea.KeyMsg{Type: tea.KeyCtrlC}
	keyCtrlD = tea.KeyMsg{Type: tea.KeyCtrlD}
	keyEsc   = tea.KeyMsg{Type: tea.KeyEsc}
)

func TestCharLimitAndTruncationNotice(t *testing.T) {
	m := newKeyModel(t)
	if m.ta.CharLimit != 65536 {
		t.Fatalf("CharLimit = %d, want 65536", m.ta.CharLimit)
	}
	if got := m.limitNotice(); got != "" {
		t.Errorf("empty draft should show no notice, got %q", got)
	}
	m.ta.SetValue(strings.Repeat("a", 65536+500))
	if m.ta.Length() != 65536 {
		t.Fatalf("draft length = %d, want it capped at 65536", m.ta.Length())
	}
	if notice := m.limitNotice(); !strings.Contains(notice, "truncated at 64 KiB") {
		t.Errorf("notice at the limit = %q, want it to mention truncation at 64 KiB", notice)
	}
	if !strings.Contains(m.View(), "truncated at 64 KiB") {
		t.Error("View should show the truncation notice while the draft is at the limit")
	}
}

func TestCtrlDConfirmsWhenWorkingOrDraft(t *testing.T) {
	// Idle, empty draft: quits at once.
	m := newKeyModel(t)
	if _, msg := press(t, m, keyCtrlD); !isQuit(msg) {
		t.Errorf("idle empty ctrl+d should quit, got %v", msg)
	}

	// Non-empty draft: hint first, quit on the second press.
	m = newKeyModel(t)
	m.ta.SetValue("half a question")
	m, msg := press(t, m, keyCtrlD)
	if isQuit(msg) || !strings.Contains(fmt.Sprint(msg), "press ctrl+d again to quit") {
		t.Fatalf("first ctrl+d with a draft should print the hint, got %v", msg)
	}
	if _, msg = press(t, m, keyCtrlD); !isQuit(msg) {
		t.Errorf("second ctrl+d with a draft should quit, got %v", msg)
	}

	// Mid-stream: same two-step.
	m = newKeyModel(t)
	m.working = true
	m, msg = press(t, m, keyCtrlD)
	if isQuit(msg) || !strings.Contains(fmt.Sprint(msg), "press ctrl+d again to quit") {
		t.Fatalf("first ctrl+d mid-stream should print the hint, got %v", msg)
	}
	if _, msg = press(t, m, keyCtrlD); !isQuit(msg) {
		t.Errorf("second ctrl+d mid-stream should quit, got %v", msg)
	}

	// Any other key disarms the confirmation.
	m = newKeyModel(t)
	m.working = true
	m, _ = press(t, m, keyCtrlD)
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	if _, msg = press(t, m, keyCtrlD); isQuit(msg) {
		t.Error("ctrl+d after another key should re-arm, not quit")
	}
}

func TestCancelCommitsPartialAnswer(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  tea.Msg
	}{
		{"canceledMsg", canceledMsg{}},
		{"streamDone rag", streamDoneMsg{err: context.Canceled}},
		{"streamDone agent", streamDoneMsg{err: context.Canceled, agent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newKeyModel(t)
			m.working = true
			m.live = "partial answer text\n"
			nm, cmd := m.Update(tc.msg)
			m = nm.(model)
			if m.live != "" || m.working {
				t.Errorf("live/working not reset: live=%q working=%v", m.live, m.working)
			}
			out := fmt.Sprint(cmd())
			if !strings.Contains(out, "partial") || !strings.Contains(out, "canceled") {
				t.Errorf("cancel output should hold the partial text and a canceled tag, got %q", out)
			}
		})
	}
}

func TestCancelPartialIsSanitized(t *testing.T) {
	m := newKeyModel(t)
	m.working = true
	m.live = "before \x1b]0;evil-title\x07after"
	_, cmd := m.Update(canceledMsg{})
	out := fmt.Sprint(cmd())
	if strings.Contains(out, "\x1b]") || strings.Contains(out, "evil-title") {
		t.Errorf("partial text must be sanitized before it reaches the terminal, got %q", out)
	}
}

func TestCancelWithoutPartialPrintsOnlyTag(t *testing.T) {
	m := newKeyModel(t)
	m.working = true
	_, cmd := m.Update(canceledMsg{})
	out := fmt.Sprint(cmd())
	if !strings.Contains(out, "canceled") || strings.Count(out, "\n") != 0 {
		t.Errorf("empty partial should print a single canceled line, got %q", out)
	}
}

func TestCtrlCClosesEveryOverlay(t *testing.T) {
	overlays := map[string]overlayModel{
		"resume": newHistoryPicker(nil, "", 80),
		"model":  newModelPicker([]string{"a", "b"}, "a", "medium", 80),
		"file":   newFilePicker(t.TempDir(), 80),
	}
	for name, ov := range overlays {
		t.Run(name, func(t *testing.T) {
			m := newKeyModel(t)
			m.overlay = ov
			m, msg := press(t, m, keyCtrlC)
			if _, ok := msg.(overlayCloseMsg); !ok {
				t.Fatalf("ctrl+c in the %s overlay should close it, got %v", name, msg)
			}
			nm, _ := m.Update(msg)
			if nm.(model).overlay != nil {
				t.Error("overlay still open after close message")
			}
		})
	}
}

func TestCtrlCClosesPaletteWithoutClearingDraft(t *testing.T) {
	m := newKeyModel(t)
	m.ta.SetValue("/")
	m = m.refreshPalette()
	if !m.pal.open {
		t.Fatal("palette should be open for a bare slash")
	}
	m, msg := press(t, m, keyCtrlC)
	if isQuit(msg) {
		t.Fatal("ctrl+c in the palette must not quit")
	}
	if m.pal.open {
		t.Error("ctrl+c should close the palette")
	}
	if m.ta.Value() != "/" {
		t.Errorf("draft = %q, want it left untouched", m.ta.Value())
	}
}

func helpText(bs []key.Binding) string {
	var parts []string
	for _, b := range bs {
		parts = append(parts, b.Help().Key+" "+b.Help().Desc)
	}
	return strings.Join(parts, " | ")
}

func TestFooterFollowsState(t *testing.T) {
	m := newKeyModel(t)
	idle := helpText(m.footerKeys().short)
	if strings.Contains(idle, "cancel") || !strings.Contains(idle, "enter") {
		t.Errorf("idle footer = %q, want the normal hints without cancel", idle)
	}

	m.working = true
	working := helpText(m.footerKeys().short)
	if !strings.Contains(working, "ctrl+c cancel") {
		t.Errorf("working footer = %q, want ctrl+c cancel", working)
	}

	overlays := map[string]overlayModel{
		"resume": newHistoryPicker(nil, "", 80),
		"model":  newModelPicker([]string{"a"}, "a", "medium", 80),
		"file":   newFilePicker(t.TempDir(), 80),
	}
	for name, ov := range overlays {
		m2 := newKeyModel(t)
		m2.overlay = ov
		got := helpText(m2.footerKeys().short)
		if !strings.Contains(got, "esc") || strings.Contains(got, "newline") {
			t.Errorf("%s overlay footer = %q, want overlay keys with esc and no input hints", name, got)
		}
	}

	m3 := newKeyModel(t)
	m3.ta.SetValue("/")
	m3 = m3.refreshPalette()
	if got := helpText(m3.footerKeys().short); !strings.Contains(got, "esc") || strings.Contains(got, "newline") {
		t.Errorf("palette footer = %q, want palette keys with esc", got)
	}

	m4 := newKeyModel(t)
	m4.rsearch.open = true
	if got := helpText(m4.footerKeys().short); !strings.Contains(got, "esc") {
		t.Errorf("reverse search footer = %q, want esc", got)
	}
}

func TestViewUnderOverlayOmitsInputHints(t *testing.T) {
	m := newKeyModel(t)
	m.overlay = newHistoryPicker(nil, "", 80)
	if strings.Contains(m.View(), "newline") {
		t.Error("View under an overlay should not show the input footer hints")
	}
}

func TestEscCancelsActiveTurn(t *testing.T) {
	m := newKeyModel(t)
	m.working = true
	called := false
	m.cancel = func() { called = true }
	m, _ = press(t, m, keyEsc)
	if !called {
		t.Error("esc should cancel the active turn")
	}
	if !m.lastCtrlC.IsZero() {
		t.Error("esc must not arm the ctrl+c double-press quit")
	}

	// Idle esc does nothing.
	m = newKeyModel(t)
	if _, msg := press(t, m, keyEsc); isQuit(msg) {
		t.Error("idle esc must not quit")
	}

	// With the palette open, esc closes the palette and leaves the turn running.
	m = newKeyModel(t)
	m.working = true
	called = false
	m.cancel = func() { called = true }
	m.ta.SetValue("/")
	m = m.refreshPalette()
	m, _ = press(t, m, keyEsc)
	if called || m.pal.open {
		t.Errorf("esc with palette open: canceled=%v palOpen=%v, want palette closed and turn running", called, m.pal.open)
	}
}

func TestCtrlCEmptyDraftHintThenQuit(t *testing.T) {
	m := newKeyModel(t)
	m, msg := press(t, m, keyCtrlC)
	if isQuit(msg) {
		t.Fatal("first ctrl+c on an empty idle draft must not quit")
	}
	if !strings.Contains(fmt.Sprint(msg), "ctrl+c again to quit") {
		t.Errorf("first ctrl+c should print the hint, got %v", msg)
	}
	if _, msg = press(t, m, keyCtrlC); !isQuit(msg) {
		t.Errorf("second ctrl+c should quit, got %v", msg)
	}
}

func TestCtrlCClearsDraftThenQuits(t *testing.T) {
	m := newKeyModel(t)
	m.ta.SetValue("draft")
	m, msg := press(t, m, keyCtrlC)
	if isQuit(msg) || m.ta.Value() != "" {
		t.Fatalf("first ctrl+c should clear the draft without quitting: value=%q msg=%v", m.ta.Value(), msg)
	}
	if _, msg = press(t, m, keyCtrlC); !isQuit(msg) {
		t.Errorf("second ctrl+c within the window should quit, got %v", msg)
	}
}

func TestFullHelpListsAllKeys(t *testing.T) {
	m := newKeyModel(t)
	var all []key.Binding
	for _, col := range m.keys.FullHelp() {
		all = append(all, col...)
	}
	text := helpText(all)
	for _, want := range []string{"ctrl+u", "@", "esc", "ctrl+c", "ctrl+p"} {
		if !strings.Contains(text, want) {
			t.Errorf("full help missing %q: %s", want, text)
		}
	}
	// The two bindings that shadow textarea keys say when they do: ctrl+p only
	// while idle, ctrl+u only while prompts are queued.
	for _, b := range all {
		switch b.Help().Key {
		case "ctrl+p":
			if d := b.Help().Desc; !strings.Contains(d, "idle") || !strings.Contains(d, "shadows line up") {
				t.Errorf("ctrl+p help = %q, want it to say it applies while idle and shadows line up", d)
			}
		case "ctrl+u":
			if d := b.Help().Desc; !strings.Contains(d, "queued") || !strings.Contains(d, "shadows delete to line start") {
				t.Errorf("ctrl+u help = %q, want it to say it applies while queued and shadows delete to line start", d)
			}
		}
	}
	if k := m.keys.PickModel.Keys(); len(k) != 1 || k[0] != "ctrl+p" {
		t.Errorf("ctrl+p must stay bound to the model picker, got %v", k)
	}
	if k := m.keys.ClearQueue.Keys(); len(k) != 1 || k[0] != "ctrl+u" {
		t.Errorf("ctrl+u must stay bound to clear queue, got %v", k)
	}
}

func TestReduceMotionEnv(t *testing.T) {
	cases := map[string]bool{"": false, "0": false, "false": false, "FALSE": false, "1": true, "true": true, "yes": true}
	for v, want := range cases {
		t.Setenv("BLK_REDUCE_MOTION", v)
		if got := reduceMotion(); got != want {
			t.Errorf("BLK_REDUCE_MOTION=%q: reduceMotion() = %v, want %v", v, got, want)
		}
	}
}

func TestReduceMotionSetFromEnv(t *testing.T) {
	isolateUserDirs(t)
	t.Setenv("BLK_REDUCE_MOTION", "1")
	if !initialModel().reduceMotion {
		t.Error("initialModel should read BLK_REDUCE_MOTION")
	}
}

func TestReduceMotionStaticWorkingLine(t *testing.T) {
	m := newKeyModel(t)
	m.reduceMotion = true
	m.working = true
	m.workingVerb = "thinking..."
	m.turnStart = time.Now().Add(-3 * time.Second)
	line := m.spinnerLine()
	if !strings.Contains(line, "thinking...") || !strings.Contains(line, "3s") {
		t.Errorf("static working line = %q, want the verb and elapsed seconds", line)
	}
	// The animated line is the same text with the spinner frame instead of a bullet.
	m.reduceMotion = false
	if animated := m.spinnerLine(); animated == line {
		t.Errorf("reduce-motion line should differ from the animated one: %q", line)
	}
}

// The working line drops the live readout first, then the elapsed time, then
// cuts the verb, so it never exceeds the width.
func TestSpinnerLineFitsEveryWidth(t *testing.T) {
	for _, reduced := range []bool{false, true} {
		var prevTok, prevEl bool
		for w := 120; w >= 10; w-- {
			m := layoutModel(t, w, 24)
			m.reduceMotion = reduced
			m.working = true
			m.workingVerb = "answering..."
			m.turnStart = time.Now().Add(-95 * time.Second)
			m.firstTokAt = time.Now().Add(-90 * time.Second)
			m.liveTokens = 1234
			line := m.spinnerLine()
			if got := lipgloss.Width(line); got > w {
				t.Errorf("reduced=%v width %d: line is %d columns: %q", reduced, w, got, line)
			}
			tok, el := strings.Contains(line, "tok/s"), strings.Contains(line, "(")
			if tok && !el || (el && !strings.Contains(line, "answering...")) {
				t.Errorf("reduced=%v width %d: wrong drop order: %q", reduced, w, line)
			}
			if (tok && !prevTok && w != 120) || (el && !prevEl && w != 120) {
				t.Errorf("reduced=%v width %d: a part came back at a narrower width: %q", reduced, w, line)
			}
			prevTok, prevEl = tok, el
			if w == 120 && (!tok || !el) {
				t.Errorf("reduced=%v: a roomy line should carry the readout and the elapsed time: %q", reduced, line)
			}
		}
	}
}

func TestSpinnerLineCutsVerbLast(t *testing.T) {
	m := layoutModel(t, 12, 24)
	m.working = true
	m.workingVerb = "retrieving..."
	m.turnStart = time.Now().Add(-95 * time.Second)
	line := m.spinnerLine()
	if lipgloss.Width(line) > 12 || !strings.Contains(line, "retr") || !strings.HasSuffix(strings.TrimRight(line, " "), "...") {
		t.Errorf("narrow line = %q, want a verb cut with an ASCII ellipsis within 12 columns", line)
	}
	if strings.Contains(line, "(") {
		t.Errorf("elapsed time should be gone before the verb is cut: %q", line)
	}
}

func TestReduceMotionTicksOncePerSecond(t *testing.T) {
	m := newKeyModel(t)
	m.reduceMotion = true
	m.working = true
	m.tickGen = 2

	if _, cmd := m.Update(secondTickMsg{gen: 2}); cmd == nil {
		t.Error("a current-generation tick while working should schedule the next one")
	}
	if _, cmd := m.Update(secondTickMsg{gen: 1}); cmd != nil {
		t.Error("a stale-generation tick should be dropped")
	}
	m.working = false
	if _, cmd := m.Update(secondTickMsg{gen: 2}); cmd != nil {
		t.Error("ticks should stop once the turn ends")
	}
}

func noColor(t *testing.T) {
	t.Helper()
	old := useColor
	useColor = false
	t.Cleanup(func() { useColor = old })
}

// printed runs a tea.Println command and returns the text it prints.
func printed(t *testing.T, cmd tea.Cmd) string {
	t.Helper()
	if cmd == nil {
		t.Fatal("nil command")
	}
	return fmt.Sprint(cmd())
}

func TestStageMsgSetsWorkingVerb(t *testing.T) {
	m := model{working: true, ta: textarea.New()}
	nm, _ := m.Update(stageMsg("grading"))
	if v := nm.(model).workingVerb; !strings.HasPrefix(v, "grading") {
		t.Errorf("workingVerb = %q, want it to start with the stage", v)
	}
	idle := model{ta: textarea.New()}
	nm, _ = idle.Update(stageMsg("grading"))
	if v := nm.(model).workingVerb; v != "" {
		t.Errorf("a stray stage after the turn ended must be ignored, got %q", v)
	}
}

func TestFormatNoResultsIsWarningNotSuccess(t *testing.T) {
	noColor(t)
	out := formatNoResults()
	for _, want := range []string{Glyph(GlyphWarn), "rephrase", "blk status", "blk add"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{Glyph(GlyphOK), "Answered in", "SOURCES"} {
		if strings.Contains(out, bad) {
			t.Errorf("no-results looks like a success (%q):\n%s", bad, out)
		}
	}
}

func TestNoResultsMsgEndsTurnAsWarning(t *testing.T) {
	noColor(t)
	m := model{working: true, live: "stale", workingVerb: "answering", ta: textarea.New(),
		openTargets: []openTarget{{Path: "old.md"}}, lastAnswer: "prev"}
	nm, cmd := m.Update(noResultsMsg{})
	got := nm.(model)
	if got.working || got.live != "" || got.workingVerb != "" || len(got.openTargets) != 0 {
		t.Errorf("turn state not reset: %+v", got)
	}
	if got.lastAnswer != "prev" {
		t.Errorf("lastAnswer clobbered: %q", got.lastAnswer)
	}
	out := printed(t, cmd)
	if !strings.Contains(out, "blk status") || strings.Contains(out, "Answered in") {
		t.Errorf("output = %q", out)
	}
}

func TestFormatAnswerTagsWebCitations(t *testing.T) {
	noColor(t)
	resp := &answerResponse{
		Answer: "x [1] [2]",
		Citations: []citation{
			{Source: "wstg", Path: "docs/a.md", Section: "Intro"},
			{Source: "web", Path: "https://example.com/post", Section: "A post"},
		},
		UsedWeb: true,
	}
	out := formatAnswer(resp, time.Second, 80, false)
	if n := strings.Count(out, "[web, untrusted]"); n != 1 {
		t.Fatalf("want one tag, got %d:\n%s", n, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "docs/a.md") && strings.Contains(line, "[web, untrusted]") {
			t.Errorf("local citation tagged as web: %q", line)
		}
		if strings.Contains(line, "example.com/post") && !strings.Contains(line, "[web, untrusted]") {
			t.Errorf("web citation not tagged: %q", line)
		}
	}
}

func TestOpenWebTargetPrintsURLAndDoesNotOpen(t *testing.T) {
	noColor(t)
	m := model{openTargets: []openTarget{{Path: "docs/a.md"}, {Path: "https://example.com/p?q=1\x1b]0;x\x07", Section: "Heading"}}}
	for _, arg := range []string{"2", "https://example.com/p?q=1"} {
		out := printed(t, m.openCmd(arg))
		if !strings.Contains(out, "web results are not opened automatically") || !strings.Contains(out, "https://example.com/p?q=1") {
			t.Errorf("/open %s: %q", arg, out)
		}
		if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) || strings.Count(out, "\n") > 1 {
			t.Errorf("/open %s: output not sanitized or not one line: %q", arg, out)
		}
	}
}

func TestOpenTargetsCarrySections(t *testing.T) {
	cits := []citation{{Path: "a.md", Section: "A > B"}, {Path: "https://x.test/p"}}
	got := citationTargets(cits)
	if len(got) != 2 || got[0] != (openTarget{Path: "a.md", Section: "A > B"}) || got[1].Section != "" {
		t.Errorf("citationTargets = %+v", got)
	}
	var r retrieval.Result
	r.Payload.Path, r.Payload.Section = "b.md", "page 3"
	rt := resultTargets([]retrieval.Result{r})
	if len(rt) != 1 || rt[0] != (openTarget{Path: "b.md", Section: "page 3"}) {
		t.Errorf("resultTargets = %+v", rt)
	}
}

func TestOpenNumberJumpsToCitedSection(t *testing.T) {
	dir := t.TempDir()
	doc := filepath.Join(dir, "doc.md")
	if err := os.WriteFile(doc, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeLess(t)
	got := captureViewer(t)
	m := model{openTargets: []openTarget{{Path: doc, Section: "SSRF > Blind SSRF"}, {Path: doc}}}

	path, section, done := m.openAction("1")
	if done != nil {
		t.Fatal("unexpected notice for a local target")
	}
	if err := openFile(path, section, false); err != nil {
		t.Fatal(err)
	}
	if want := []string{"+/Blind SSRF", "--", doc}; strings.Join(*got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("/open 1 argv = %q, want %q", *got, want)
	}

	// No section on the target, and a literal path: open at the top.
	for _, arg := range []string{"2", doc} {
		path, section, done = m.openAction(arg)
		if done != nil || section != "" {
			t.Fatalf("/open %s: section %q notice %v", arg, section, done != nil)
		}
		*got = nil
		if err := openFile(path, section, false); err != nil {
			t.Fatal(err)
		}
		if len(*got) != 1 || (*got)[0] != doc {
			t.Errorf("/open %s argv = %q", arg, *got)
		}
	}
}

func TestStatusLineNamesWhichServiceIsDown(t *testing.T) {
	noColor(t)
	base := model{mode: "rag", width: 200, servicesChecked: true}
	cases := []struct {
		h    serviceHealth
		want string
	}{
		{serviceHealth{Qdrant: true, EmbedServer: true, LLM: true}, "services ok"},
		{serviceHealth{Qdrant: true, EmbedServer: true}, "llm down"},
		{serviceHealth{EmbedServer: true, LLM: true}, "qdrant down"},
		{serviceHealth{Qdrant: true}, "embed_server, llm down"},
	}
	for _, c := range cases {
		h := c.h
		m := base
		m.health = &h
		m.servicesOK = h.ok()
		line := m.statusLine()
		if !strings.Contains(line, c.want) {
			t.Errorf("%+v: %q lacks %q", c.h, line, c.want)
		}
		if c.want != "services ok" && strings.Contains(line, "services ok") {
			t.Errorf("%+v: dot must not be ok: %q", c.h, line)
		}
	}
	// Unknown cause (for example a search error) keeps the generic label.
	if line := (model{mode: "rag", width: 200, servicesChecked: true}).statusLine(); !strings.Contains(line, "services down") {
		t.Errorf("fallback label lost: %q", line)
	}
}

func TestLLMDownErrorMarksLLMDownInStatus(t *testing.T) {
	noColor(t)
	okHealth := func() *serviceHealth {
		return &serviceHealth{Qdrant: true, EmbedServer: true, LLM: true}
	}
	newM := func(h *serviceHealth) model {
		m := layoutModel(t, 200, 30)
		m.working = true
		m.health, m.servicesOK, m.servicesChecked = h, true, true
		return m
	}
	const base = "http://127.0.0.1:8000/v1"

	// A refused connection means the LLM is down: the dot and label follow at once.
	m := newM(okHealth())
	nm, _ := m.Update(errMsg{mapLLMError(syscall.ECONNREFUSED, base)})
	got := nm.(model)
	if got.servicesOK || got.health == nil || got.health.LLM || !got.health.Qdrant || !got.health.EmbedServer {
		t.Errorf("after refused: ok=%v health=%+v", got.servicesOK, got.health)
	}
	if line := got.statusLine(); !strings.Contains(line, "llm down") || strings.Contains(line, "services ok") {
		t.Errorf("status = %q, want it to name llm as down", line)
	}
	// The probe result the model held is not mutated in place.
	if m.health.LLM != true {
		t.Error("the previous health snapshot was mutated")
	}

	// With no probe result yet, retrieval must have worked to reach the LLM.
	nm, _ = newM(nil).Update(errMsg{mapLLMError(syscall.ECONNREFUSED, base)})
	if line := nm.(model).statusLine(); !strings.Contains(line, "llm down") {
		t.Errorf("status without a prior probe = %q, want llm down", line)
	}

	// A timeout is a slow model, not a dead one: the dot stays as it was.
	nm, _ = newM(okHealth()).Update(errMsg{mapLLMError(context.DeadlineExceeded, base)})
	if got := nm.(model); !got.servicesOK || !got.health.LLM {
		t.Errorf("a timeout must not mark the LLM down: ok=%v health=%+v", got.servicesOK, got.health)
	}
}

func TestSearchSuccessDoesNotClearKnownLLMDown(t *testing.T) {
	noColor(t)
	m := layoutModel(t, 200, 30)
	m.working = true
	m.health = &serviceHealth{Qdrant: false, EmbedServer: false, LLM: false}
	m.servicesChecked = true
	nm, _ := m.Update(searchMsg{query: "q"})
	got := nm.(model)
	if got.servicesOK || got.health.LLM || !got.health.Qdrant || !got.health.EmbedServer {
		t.Errorf("search must only update qdrant and embed_server: ok=%v health=%+v", got.servicesOK, got.health)
	}
	if line := got.statusLine(); !strings.Contains(line, "llm down") {
		t.Errorf("status = %q, want llm down", line)
	}

	// With the LLM up, a successful search restores the ok dot.
	m.health = &serviceHealth{LLM: true}
	m.working = true
	nm, _ = m.Update(searchMsg{query: "q"})
	if got := nm.(model); !got.servicesOK || !got.health.ok() {
		t.Errorf("search with a healthy LLM: ok=%v health=%+v", got.servicesOK, got.health)
	}

	// With nothing known about the LLM, search still reports ok as before.
	m = layoutModel(t, 200, 30)
	m.working = true
	nm, _ = m.Update(searchMsg{query: "q"})
	if got := nm.(model); !got.servicesOK || !got.servicesChecked {
		t.Errorf("search without a probe: ok=%v checked=%v", got.servicesOK, got.servicesChecked)
	}
}

func TestHealthMsgStoresPerServiceState(t *testing.T) {
	m := model{ta: textarea.New()}
	h := &serviceHealth{Qdrant: true, EmbedServer: true}
	nm, _ := m.Update(healthMsg{h: h})
	got := nm.(model)
	if got.servicesOK || !got.servicesChecked || got.health != h {
		t.Errorf("state = ok:%v checked:%v health:%v", got.servicesOK, got.servicesChecked, got.health)
	}
	nm, _ = got.Update(healthMsg{h: &serviceHealth{Qdrant: true, EmbedServer: true, LLM: true}})
	if !nm.(model).servicesOK {
		t.Error("all three up must set the dot ok")
	}
}

// A probe that started before a turn found the LLM refusing connections must not
// bring the LLM back up when its result arrives late.
func TestStaleHealthProbeDoesNotClearLLMDown(t *testing.T) {
	noColor(t)
	const base = "http://127.0.0.1:8000/v1"
	up := func() *serviceHealth {
		return &serviceHealth{Qdrant: true, EmbedServer: true, LLM: true}
	}
	newM := func() model {
		m := layoutModel(t, 200, 30)
		m.working = true
		m.health, m.servicesOK, m.servicesChecked = up(), true, true
		return m
	}
	probeStart := time.Now().Add(-time.Minute)

	// The turn fails first, then the older probe reports the LLM up.
	nm, _ := newM().Update(errMsg{mapLLMError(syscall.ECONNREFUSED, base)})
	m := nm.(model)
	nm, _ = m.Update(healthMsg{h: up(), started: probeStart})
	got := nm.(model)
	if got.servicesOK || got.health == nil || got.health.LLM || got.health.ok() {
		t.Errorf("stale probe overwrote the LLM-down state: ok=%v health=%+v", got.servicesOK, got.health)
	}
	if line := got.statusLine(); !strings.Contains(line, "llm down") {
		t.Errorf("status = %q, want llm down", line)
	}
	if !got.health.Qdrant || !got.health.EmbedServer {
		t.Errorf("the rest of the stale probe result is still valid: %+v", got.health)
	}

	// The probe result lands first, then the failure: the LLM ends up down.
	m = newM()
	nm, _ = m.Update(healthMsg{h: up(), started: probeStart})
	nm, _ = nm.(model).Update(errMsg{mapLLMError(syscall.ECONNREFUSED, base)})
	if got := nm.(model); got.servicesOK || got.health.LLM {
		t.Errorf("failure after the probe must mark the LLM down: ok=%v health=%+v", got.servicesOK, got.health)
	}

	// A probe that started after the mark is current, so it may bring the LLM back.
	down := nm.(model)
	nm, _ = down.Update(healthMsg{h: up(), started: down.llmDownAt.Add(time.Second)})
	if got := nm.(model); !got.servicesOK || !got.health.LLM {
		t.Errorf("a fresh probe should restore the LLM: ok=%v health=%+v", got.servicesOK, got.health)
	}

	// A stale probe that reports the LLM down is taken as is.
	nm, _ = down.Update(healthMsg{h: &serviceHealth{Qdrant: true}, started: probeStart})
	if got := nm.(model); got.servicesOK || got.health.LLM || got.health.EmbedServer {
		t.Errorf("a stale down result should still be stored: ok=%v health=%+v", got.servicesOK, got.health)
	}
}

func TestHealthCmdStampsProbeStart(t *testing.T) {
	useDeadServices(t)
	t.Setenv("QDRANT_GRPC_URL", "127.0.0.1:1")
	before := time.Now()
	msg, ok := newKeyModel(t).healthCmd()().(healthMsg)
	if !ok || msg.started.Before(before) || msg.started.After(time.Now()) {
		t.Errorf("healthCmd() = %#v, want started between %v and now", msg, before)
	}
}

// healthCmd is a tea.Cmd, so the probe never runs on the UI goroutine.
func TestHealthCmdProbesLLM(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	useDeadServices(t)
	t.Setenv("OMLX_BASE_URL", up.URL)
	t.Setenv("QDRANT_GRPC_URL", "127.0.0.1:1")
	msg, ok := newKeyModel(t).healthCmd()().(healthMsg)
	if !ok || msg.h == nil {
		t.Fatalf("healthCmd() = %#v", msg)
	}
	if !msg.h.LLM || msg.h.Qdrant {
		t.Errorf("health = %+v", msg.h)
	}
}

// layoutModel builds a hermetic model sized like a terminal of w x h, going
// through Update so the resize path is exercised too.
func layoutModel(t *testing.T, w, h int) model {
	t.Helper()
	ta := textarea.New()
	ta.SetHeight(1)
	ta.Focus()
	m := model{ta: ta, sp: spinner.New(), help: help.New(), keys: defaultKeys(), mode: "rag", reasoning: "medium", ragModel: "m"}
	nm, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	return nm.(model)
}

var (
	layoutWidths  = []int{40, 60, 80, 120}
	layoutHeights = []int{10, 24, 50}
)

func TestWindowSizeStoresWidthAndHeight(t *testing.T) {
	m := layoutModel(t, 100, 30)
	if m.width != 100 || m.height != 30 {
		t.Fatalf("size after WindowSizeMsg = %dx%d, want 100x30", m.width, m.height)
	}
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 50, Height: 12})
	m = nm.(model)
	if m.width != 50 || m.height != 12 {
		t.Fatalf("size after second WindowSizeMsg = %dx%d, want 50x12", m.width, m.height)
	}
}

func longStream(lines int) string {
	var b strings.Builder
	for i := 0; i < lines; i++ {
		fmt.Fprintf(&b, "line %d of the streamed answer with some words\n", i)
	}
	return b.String()
}

func TestLiveRegionCapShowsTailAndIndicator(t *testing.T) {
	m := layoutModel(t, 80, 24)
	m.working = true
	m.live = longStream(5000)
	lr := m.liveRegion(8)
	lines := strings.Split(lr, "\n")
	if len(lines) != 8 {
		t.Fatalf("live region has %d rows, want the cap of 8:\n%s", len(lines), lr)
	}
	if !strings.Contains(lines[0], "earlier lines hidden") {
		t.Errorf("top row should be the hidden-lines indicator, got %q", lines[0])
	}
	if !strings.Contains(lines[len(lines)-1], "line 4999 ") {
		t.Errorf("last row should be the newest line, got %q", lines[len(lines)-1])
	}
	// 5000 source lines; 7 shown, so 4993 hidden.
	if !strings.Contains(lines[0], "4993") {
		t.Errorf("indicator should count hidden lines (4993), got %q", lines[0])
	}
}

func TestLiveRegionUnderCapHasNoIndicator(t *testing.T) {
	m := layoutModel(t, 80, 24)
	m.live = "one\ntwo\nthree"
	lr := m.liveRegion(10)
	if strings.Contains(lr, "hidden") {
		t.Errorf("no indicator expected when content fits:\n%s", lr)
	}
	if got := len(strings.Split(lr, "\n")); got != 3 {
		t.Errorf("got %d rows, want 3", got)
	}
	// A cap of 0 means unbounded.
	m.live = longStream(50)
	if got := len(strings.Split(m.liveRegion(0), "\n")); got != 50 {
		t.Errorf("liveRegion(0) has %d rows, want all 50", got)
	}
}

func TestLiveRegionHardBreaksLongToken(t *testing.T) {
	token := strings.Repeat("A", 500)
	for _, w := range []int{40, 60, 80, 120} {
		m := layoutModel(t, w, 50)
		m.live = "url " + token + " end"
		lr := m.liveRegion(40)
		var joined strings.Builder
		for _, ln := range strings.Split(lr, "\n") {
			if lipgloss.Width(ln) > w {
				t.Errorf("width %d: live row is %d columns: %q", w, lipgloss.Width(ln), ln)
			}
			joined.WriteString(strings.Trim(ln, " "+Glyph(GlyphBar)))
		}
		if !strings.Contains(joined.String(), token) {
			t.Errorf("width %d: token characters were lost", w)
		}
	}
}

func TestViewBoundedByTerminal(t *testing.T) {
	buffers := map[string]string{
		"5000 lines":   longStream(5000),
		"500 char run": strings.Repeat("A", 500),
		"mixed":        longStream(300) + strings.Repeat("B", 500) + "\n" + longStream(300),
	}
	for name, buf := range buffers {
		for _, w := range layoutWidths {
			for _, h := range layoutHeights {
				m := layoutModel(t, w, h)
				m.working = true
				m.live = buf
				lines := strings.Split(m.View(), "\n")
				if len(lines) > h {
					t.Errorf("%s %dx%d: view has %d rows, terminal has %d", name, w, h, len(lines), h)
				}
				for i, ln := range lines {
					if lipgloss.Width(ln) > w {
						t.Errorf("%s %dx%d: row %d is %d columns: %q", name, w, h, i, lipgloss.Width(ln), ln)
					}
				}
				if !strings.Contains(lines[0], "rag") {
					t.Errorf("%s %dx%d: status line is not the first row: %q", name, w, h, lines[0])
				}
				if name == "5000 lines" && !strings.Contains(m.View(), "line 4999 ") {
					t.Errorf("%s %dx%d: newest streamed line is not visible", name, w, h)
				}
			}
		}
	}
}

// TestViewNeverExceedsShortTerminals is the layout budget check: at every size,
// in every state, the view has at most as many rows as the terminal and no row
// wider than it. The palette and a multi-line draft take their rows first; the
// live region gets what is left, or is omitted.
func TestViewNeverExceedsShortTerminals(t *testing.T) {
	sixRows := "one\ntwo\nthree\nfour\nfive\nsix"
	states := map[string]func(m model) model{
		"idle": func(m model) model { return m },
		"key panel": func(m model) model {
			m.keyPanel = true
			return m
		},
		"working": func(m model) model {
			m.working, m.live = true, longStream(200)
			return m
		},
		"working with palette": func(m model) model {
			m.working, m.live = true, longStream(200)
			m.ta.SetValue("/")
			m.pal.open, m.pal.items = true, filterCommands(slashCommands(), "")
			return m
		},
		"working with 6 row draft": func(m model) model {
			m.working, m.live = true, longStream(200)
			m.ta.SetValue(sixRows)
			m.ta.SetHeight(6)
			return m
		},
		"working with palette and 6 row draft": func(m model) model {
			m.working, m.live = true, longStream(200)
			m.ta.SetValue(sixRows)
			m.ta.SetHeight(6)
			m.pal.open, m.pal.items = true, filterCommands(slashCommands(), "")
			return m
		},
		"idle with 6 row draft": func(m model) model {
			m.ta.SetValue(sixRows)
			m.ta.SetHeight(6)
			return m
		},
		"resume overlay": func(m model) model {
			m.overlay = newHistoryPicker(manySessions(20), "id01", m.width)
			return m
		},
		"model overlay": func(m model) model {
			m.overlay = newModelPicker(manyModels(20), "model-01", "low", m.width)
			return m
		},
		"file overlay": func(m model) model {
			m.overlay = newFilePicker(t.TempDir(), m.width)
			return m
		},
		"reverse search": func(m model) model {
			m.rsearch = reverseSearch{open: true, query: "ssrf", match: strings.Repeat("payload ", 30), count: 3}
			return m
		},
		"services down with a queue": func(m model) model {
			m.working, m.live = true, longStream(50)
			m.health, m.servicesChecked = &serviceHealth{}, true
			m.queue, m.sessTitle = []string{"a", "b"}, "a long session title"
			return m
		},
	}
	for name, setup := range states {
		for _, w := range []int{20, 40, 80} {
			for h := 6; h <= 24; h++ {
				m := setup(layoutModel(t, w, h))
				lines := strings.Split(m.View(), "\n")
				if len(lines) > h {
					t.Errorf("%s %dx%d: view has %d rows, terminal has %d:\n%s", name, w, h, len(lines), h, strings.Join(lines, "\n"))
				}
				for i, ln := range lines {
					if lipgloss.Width(ln) > w {
						t.Errorf("%s %dx%d: row %d is %d columns: %q", name, w, h, i, lipgloss.Width(ln), ln)
					}
				}
				if !strings.Contains(lines[0], "rag") {
					t.Errorf("%s %dx%d: status line is not the first row: %q", name, w, h, lines[0])
				}
				if h := m.ta.Height(); name == "working with 6 row draft" && h != 6 {
					t.Errorf("%s %dx%d: View changed the draft height to %d", name, w, len(lines), h)
				}
			}
		}
	}
}

// On a short terminal the draft is cut to the rows the budget allows, and the
// row holding the cursor must stay in it, wherever the cursor sits.
func TestViewKeepsCursorRowVisibleOnShortTerminal(t *testing.T) {
	sixRows := "first-line\nsecond\nthird\nfourth\nfifth\nlast-line"
	for _, working := range []bool{false, true} {
		for h := 6; h <= 9; h++ {
			m := layoutModel(t, 40, h)
			m.working = working
			m.ta.SetValue(sixRows)
			m.ta.SetHeight(6)
			if view := m.View(); !strings.Contains(view, "last-line") {
				t.Errorf("working=%v height %d: cursor on the last line, but it is not shown:\n%s", working, h, view)
			}
			// Move the cursor to the first line: now that row must show instead.
			for i := 0; i < 5; i++ {
				m.ta.CursorUp()
			}
			if view := m.View(); !strings.Contains(view, "first-line") {
				t.Errorf("working=%v height %d: cursor on the first line, but it is not shown:\n%s", working, h, view)
			}
			if got := m.ta.Height(); got != 6 {
				t.Errorf("working=%v height %d: View changed the draft height to %d", working, h, got)
			}
		}
	}
}

// The specific case from the review: the cursor on the last line of a 6 line
// draft at 8 rows, mid-turn (the spinner takes a row).
func TestViewCursorOnLastDraftLineAtEightRows(t *testing.T) {
	m := layoutModel(t, 40, 8)
	m.working = true
	m.ta.SetValue("l1\nl2\nl3\nl4\nl5\nl6-cursor")
	m.ta.SetHeight(6)
	if n := len(strings.Split(m.View(), "\n")); n > 8 {
		t.Fatalf("view is %d rows in an 8 row terminal", n)
	}
	if view := m.View(); !strings.Contains(view, "l6-cursor") {
		t.Errorf("the cursor line is not visible:\n%s", view)
	}
}

func TestViewTinyTerminalsDoNotPanic(t *testing.T) {
	states := map[string]func(m model) model{
		"draft": func(m model) model {
			m.working, m.live = true, longStream(20)
			m.ta.SetValue("a\nb\nc\nd\ne\nf")
			m.ta.SetHeight(6)
			return m
		},
		"reverse search": func(m model) model {
			m.rsearch = reverseSearch{open: true, query: "q", match: "matched text", count: 2}
			return m
		},
		"file overlay": func(m model) model {
			m.overlay = newFilePicker(t.TempDir(), m.width)
			return m
		},
	}
	for _, setup := range states {
		for w := 1; w <= 30; w++ {
			for h := 1; h <= 5; h++ {
				_ = setup(layoutModel(t, w, h)).View()
			}
		}
	}
}

// With the palette open during a turn, the palette keeps its share of a roomy
// terminal and the live region still shows.
func TestViewSharesRowsBetweenPaletteAndLiveRegion(t *testing.T) {
	m := layoutModel(t, 80, 40)
	m.working, m.live = true, longStream(200)
	m.ta.SetValue("/")
	m.pal.open, m.pal.items = true, filterCommands(slashCommands(), "")
	view := m.View()
	if !strings.Contains(view, "/ask") || !strings.Contains(view, "line 199") {
		t.Errorf("roomy terminal should show both the palette and the live tail:\n%s", view)
	}
}

// The live region shows fewer rows than its old floor of 3 when that is all
// that is left, and none at all when nothing is left.
func TestLiveRegionShrinksBelowThreeRows(t *testing.T) {
	m := layoutModel(t, 80, 24)
	m.live = longStream(50)
	for rows, want := range map[int]int{1: 1, 2: 2, 3: 3} {
		if got := len(strings.Split(m.liveRegion(rows), "\n")); got != want {
			t.Errorf("liveRegion(%d) has %d rows, want %d", rows, got, want)
		}
	}
	if got := m.liveRegion(1); !strings.Contains(got, "line 49") {
		t.Errorf("a one row live region should show the newest line, got %q", got)
	}
}

func TestViewLiveRegionFollowsResize(t *testing.T) {
	m := layoutModel(t, 80, 50)
	m.working = true
	m.live = longStream(5000)
	tall := len(strings.Split(m.View(), "\n"))
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	short := len(strings.Split(nm.(model).View(), "\n"))
	if short >= tall || short > 12 {
		t.Errorf("view rows after shrink = %d (was %d), want <= 12", short, tall)
	}
}

func TestViewNarrowTerminalsDoNotPanic(t *testing.T) {
	for _, w := range []int{1, 2, 3, 4, 5, 8, 10, 15, 20, 30} {
		for _, h := range []int{1, 2, 4, 6, 10} {
			m := layoutModel(t, w, h)
			m.working = true
			m.live = strings.Repeat("X", 200) + "\n" + longStream(20)
			_ = m.View()
			m.working = false
			m.pal.open = true
			m.pal.items = filterCommands(slashCommands(), "")
			_ = m.View()
			m.overlay = newHistoryPicker([]sessionMeta{{ID: "a", Title: "t", MsgCount: 1}}, "a", w)
			_ = m.View()
			m.overlay = newModelPicker([]string{"a", "b"}, "a", "medium", w)
			_ = m.View()
		}
	}
}

func TestLiveRegionNarrowWidthsStayInBounds(t *testing.T) {
	for _, w := range []int{4, 5, 8, 10, 20, 30} {
		m := layoutModel(t, w, 24)
		m.live = strings.Repeat("X", 200)
		for _, ln := range strings.Split(m.liveRegion(10), "\n") {
			if lipgloss.Width(ln) > w {
				t.Errorf("width %d: live row is %d columns: %q", w, lipgloss.Width(ln), ln)
			}
		}
	}
}

// Each overlay's key hints come from the one state-aware footer, and it lists
// every key that overlay handles, including the close keys.
func TestOverlayFooterListsEveryKey(t *testing.T) {
	confirm := newHistoryPicker(manySessions(2), "", 100)
	confirm.confirm = true
	cases := map[string]struct {
		overlay overlayModel
		want    []string
	}{
		"resume":         {newHistoryPicker(manySessions(2), "", 100), []string{"1-9", "up/down", "enter", "d then y", "esc/ctrl+c close"}},
		"resume confirm": {confirm, []string{"y confirm delete", "ctrl+d quit", "any other key cancel"}},
		"model":          {newModelPicker(manyModels(2), "model-00", "low", 100), []string{"up/down", "tab/left/right", "enter", "esc/ctrl+c close"}},
		"file":           {newFilePicker(t.TempDir(), 100), []string{"type", "up/down", "enter", "backspace", "esc/ctrl+c close"}},
	}
	for name, c := range cases {
		m := layoutModel(t, 140, 30)
		m.overlay = c.overlay
		got := m.footer()
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s footer %q is missing %q", name, got, w)
			}
		}
		if n := len(strings.Split(m.View(), "\n")); n > 30 {
			t.Errorf("%s: view is %d rows in a 30 row terminal", name, n)
		}
	}
}

// Every key the delete-confirm footer lists does what it says, driven through
// the full Update path: ctrl+d is handled before the overlay and quits, y
// deletes, and every other key (ctrl+c and esc included) only cancels the delete.
func TestResumeConfirmFooterKeysDoWhatTheyList(t *testing.T) {
	confirming := func() model {
		isolateUserDirs(t) // fresh session store for every case
		for _, title := range []string{"first session", "second session"} {
			s, err := newSession()
			if err != nil {
				t.Fatal(err)
			}
			if err := s.appendTurn(turnRecord{Role: roleUser, Content: title}); err != nil {
				t.Fatal(err)
			}
		}
		metas, err := listSessions()
		if err != nil || len(metas) != 2 {
			t.Fatalf("sessions = %v, %v; want 2", metas, err)
		}
		p := newHistoryPicker(metas, "", 100)
		p.confirm = true
		m := layoutModel(t, 100, 30)
		m.overlay = p
		return m
	}
	count := func() int { metas, _ := listSessions(); return len(metas) }

	// The footer lists exactly these hints.
	hints := helpText(confirming().footerKeys().short)
	if want := "y confirm delete | ctrl+d quit | any other key cancel"; hints != want {
		t.Fatalf("confirm footer = %q, want %q", hints, want)
	}

	// y: deletes the selected session, leaves confirm mode, keeps the picker open.
	m, msg := press(t, confirming(), tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	if isQuit(msg) || m.overlay == nil || m.overlay.(historyPicker).confirm || count() != 1 {
		t.Errorf("y: quit=%v overlay=%v sessions=%d, want the picker open and one session deleted", isQuit(msg), m.overlay, count())
	}

	// ctrl+d: quits (an idle empty draft needs no second press) and deletes nothing.
	m, msg = press(t, confirming(), keyCtrlD)
	if !isQuit(msg) || count() != 2 {
		t.Errorf("ctrl+d: quit=%v sessions=%d, want quit and nothing deleted", isQuit(msg), count())
	}

	// Everything else cancels the delete only: no quit, no close, nothing deleted.
	others := map[string]tea.KeyMsg{
		"n":      {Type: tea.KeyRunes, Runes: []rune("n")},
		"x":      {Type: tea.KeyRunes, Runes: []rune("x")},
		"enter":  {Type: tea.KeyEnter},
		"esc":    keyEsc,
		"ctrl+c": keyCtrlC,
		"down":   {Type: tea.KeyDown},
	}
	for name, k := range others {
		m, msg = press(t, confirming(), k)
		if isQuit(msg) {
			t.Errorf("%s: must not quit", name)
		}
		if _, closed := msg.(overlayCloseMsg); closed {
			t.Errorf("%s: must cancel the delete, not close the picker", name)
		}
		if m.overlay == nil || m.overlay.(historyPicker).confirm {
			t.Errorf("%s: picker should stay open with the confirmation cleared", name)
		}
		if count() != 2 {
			t.Errorf("%s: deleted a session, want none", name)
		}
	}
}

// --- runtime config seam, timeout wording, clipboard sanitizing ---

func TestDeadlineExceededMapsToTimeoutWording(t *testing.T) {
	const want = "request timed out (raise BLKCHAIN_TIMEOUT_SECONDS)"
	if got := timeoutOrErr(context.DeadlineExceeded); got.Error() != want {
		t.Errorf("bare deadline = %q, want %q", got, want)
	}
	if got := timeoutOrErr(fmt.Errorf("retrieve: %w", context.DeadlineExceeded)); got.Error() != want {
		t.Errorf("wrapped deadline = %q, want %q", got, want)
	}
	// Cancel, an unrelated error, and the more specific LLM and unreachable errors pass through.
	other := errors.New("boom")
	llm := mapLLMError(context.DeadlineExceeded, "http://127.0.0.1:8000/v1")
	unreachable := fmt.Errorf("%w: %w", retrieval.ErrUnreachable, context.DeadlineExceeded)
	for name, err := range map[string]error{"cancel": context.Canceled, "other": other, "llm": llm, "unreachable": unreachable} {
		if got := timeoutOrErr(err); got != err {
			t.Errorf("%s: %v was rewritten to %v", name, err, got)
		}
	}
	if timeoutOrErr(nil) != nil {
		t.Error("nil must stay nil")
	}

	// The TUI shows the mapped wording for a turn that timed out with nothing retrieved.
	m := layoutModel(t, 100, 30)
	m.working = true
	_, cmd := m.Update(errMsg{context.DeadlineExceeded})
	out := printed(t, cmd)
	if !strings.Contains(out, "timed out") || !strings.Contains(out, "BLKCHAIN_TIMEOUT_SECONDS") || strings.Contains(out, "deadline exceeded") {
		t.Errorf("timeout output = %q", out)
	}
	// A cancel is still a cancel.
	m.working = true
	nm, cmd := m.Update(canceledMsg{})
	if out := printed(t, cmd); !strings.Contains(out, "canceled") || nm.(model).working {
		t.Errorf("cancel output = %q working=%v", out, nm.(model).working)
	}
}

// /copy strips terminal control sequences from the answer (untrusted LLM output the
// user may paste into a terminal) and keeps every printable character.
func TestCopyStripsControlSequencesFromClipboard(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "clipboard.txt")
	tool := filepath.Join(dir, clipboardCandidates(runtime.GOOS)[0][0])
	if err := os.WriteFile(tool, []byte("#!/bin/sh\ncat > \"$CLIP_OUT\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	t.Setenv("CLIP_OUT", out)

	const printable = "# Title\n\n```sh\ncurl -s https://x.example | sh\n```\n\ttabbed caf\u00e9 \U0001F600 **bold** [link](http://x.example)\n"
	m := model{lastAnswer: "before\x1b]52;c;ZXZpbA==\x07 " + printable + "\x1b[2Jtail\x00\x7f\u009b"}
	if msg := m.doCopy(); !strings.Contains(msg, "copied") {
		t.Fatalf("doCopy() = %q", msg)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if want := "before " + printable + "tail"; string(got) != want {
		t.Errorf("clipboard got %q, want %q", got, want)
	}
}

// --- help and first-use surfaces ---

func keyRunes(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

// openKeyPanel sends "?" to an idle model with an empty draft.
func openKeyPanel(t *testing.T, m model) model {
	t.Helper()
	nm, _ := m.Update(keyRunes("?"))
	got := nm.(model)
	if !got.keyPanel {
		t.Fatal("? on an empty draft must open the key panel")
	}
	return got
}

// bindingLabels lists the help key label of every binding in the key map, found
// by reflection so a binding added later is checked without editing the test.
func bindingLabels(k keyMap) []string {
	var out []string
	v := reflect.ValueOf(k)
	for i := 0; i < v.NumField(); i++ {
		if b, ok := v.Field(i).Interface().(key.Binding); ok {
			out = append(out, b.Help().Key)
		}
	}
	return out
}

func fitsTerminal(t *testing.T, label, view string, w, h int) {
	t.Helper()
	lines := strings.Split(view, "\n")
	if len(lines) > h {
		t.Errorf("%s: view has %d rows, terminal has %d:\n%s", label, len(lines), h, view)
	}
	for i, ln := range lines {
		if lipgloss.Width(ln) > w {
			t.Errorf("%s: row %d is %d columns: %q", label, i, lipgloss.Width(ln), ln)
		}
	}
}

func TestKeyPanelFitsAndListsEveryBinding(t *testing.T) {
	noColor(t)
	prev := useUnicode
	t.Cleanup(func() { useUnicode = prev })
	for _, unicode := range []bool{false, true} {
		useUnicode = unicode
		for _, w := range layoutWidths {
			for _, h := range layoutHeights {
				m := openKeyPanel(t, layoutModel(t, w, h))
				fitsTerminal(t, fmt.Sprintf("key panel %dx%d unicode=%v", w, h, unicode), m.View(), w, h)
			}
		}
		// The whole reference is on screen at 80x40.
		m := openKeyPanel(t, layoutModel(t, 80, 40))
		view := m.View()
		for _, k := range bindingLabels(m.keys) {
			if !strings.Contains(view, k) {
				t.Errorf("80x40 unicode=%v: binding %q missing:\n%s", unicode, k, view)
			}
		}
		if strings.Contains(view, "more,") {
			t.Errorf("80x40 unicode=%v: the panel should not be cut:\n%s", unicode, view)
		}
	}
}

func TestKeyPanelIsGroupedWithConditionalNotes(t *testing.T) {
	noColor(t)
	view := openKeyPanel(t, layoutModel(t, 80, 40)).View()
	for _, want := range []string{"MOVE AND EDIT", "ASK", "OVERLAYS", "SESSION"} {
		if !strings.Contains(view, want) {
			t.Errorf("panel lacks the %s group:\n%s", want, view)
		}
	}
	// The bindings that shadow a textarea key say when they apply. A single
	// column keeps each row's wrapped text in reading order.
	flat := strings.Join(strings.Fields(strings.Join(keyPanelLines(defaultKeys(), 60), " ")), " ")
	for _, want := range []string{"pick the model and reasoning level (only while idle;", "(only while some are queued;"} {
		if !strings.Contains(flat, want) {
			t.Errorf("panel lacks the note %q:\n%s", want, flat)
		}
	}
}

func TestKeyPanelUsesTwoColumnsWhenWide(t *testing.T) {
	noColor(t)
	rows := func(w int) int { return len(keyPanelLines(defaultKeys(), w)) }
	if narrow, wide := rows(60), rows(120); wide >= narrow {
		t.Errorf("120 columns give %d rows, 60 columns give %d: want fewer rows in two columns", wide, narrow)
	}
	for _, w := range []int{20, 40, 69} {
		for _, ln := range keyPanelLines(defaultKeys(), w) {
			if strings.Count(ln, "ctrl+") > 1 {
				t.Errorf("width %d should be one column: %q", w, ln)
			}
		}
	}
}

func TestKeyPanelClosesOnQuestionMarkEscOrAnyOtherKey(t *testing.T) {
	m := openKeyPanel(t, layoutModel(t, 80, 24))
	for name, k := range map[string]tea.KeyMsg{"?": keyRunes("?"), "esc": keyEsc} {
		nm, _ := m.Update(k)
		if nm.(model).keyPanel {
			t.Errorf("%s must close the panel", name)
		}
	}
	nm, _ := m.Update(keyRunes("w"))
	got := nm.(model)
	if got.keyPanel || got.ta.Value() != "w" {
		t.Errorf("a typed key closes the panel and is kept: open=%v draft=%q", got.keyPanel, got.ta.Value())
	}
	// "?" inside a question is still a plain character.
	typed := layoutModel(t, 80, 24)
	typed.ta.SetValue("what is ssrf")
	nm, _ = typed.Update(keyRunes("?"))
	if got := nm.(model); got.keyPanel || got.ta.Value() != "what is ssrf?" {
		t.Errorf("? in a draft: open=%v draft=%q", got.keyPanel, got.ta.Value())
	}
	// While a turn runs, "?" does not open it.
	busy := layoutModel(t, 80, 24)
	busy.working = true
	nm, _ = busy.Update(keyRunes("?"))
	if nm.(model).keyPanel {
		t.Error("the panel must not open while a turn runs")
	}
}

func TestKeyPanelScrollsToEveryBinding(t *testing.T) {
	noColor(t)
	m := openKeyPanel(t, layoutModel(t, 40, 10))
	if !strings.Contains(m.View(), "more") {
		t.Fatalf("a short terminal must say how many rows are hidden:\n%s", m.View())
	}
	seen := map[string]bool{}
	for i := 0; i < 40; i++ {
		view := m.View()
		fitsTerminal(t, "scrolled panel", view, 40, 10)
		for _, k := range bindingLabels(m.keys) {
			if strings.Contains(view, k) {
				seen[k] = true
			}
		}
		nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = nm.(model)
		if !m.keyPanel {
			t.Fatal("down must scroll the panel, not close it")
		}
	}
	for _, k := range bindingLabels(m.keys) {
		if !seen[k] {
			t.Errorf("binding %q is never reachable by scrolling", k)
		}
	}
	// Up scrolls back, and a scroll past the end does not strand the view.
	for i := 0; i < 60; i++ {
		nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
		m = nm.(model)
	}
	if !strings.Contains(m.View(), "MOVE AND EDIT") {
		t.Errorf("scrolling back up must return to the first group:\n%s", m.View())
	}
}

func TestKeyPanelFooterSaysHowToClose(t *testing.T) {
	m := openKeyPanel(t, layoutModel(t, 100, 24))
	if got := helpText(m.footerKeys().short); !strings.Contains(got, "esc") || !strings.Contains(got, "close") {
		t.Errorf("panel footer = %q, want a close hint", got)
	}
}

func TestWelcomeBannerFitsEveryWidth(t *testing.T) {
	// Unicode tiers render a full-width rounded box: exactly 3 lines, each exactly
	// `width` columns wide (corners flush, right edge straight).
	for _, tier := range []plTier{plUnicode, plNerd} {
		vizForceTier(t, tier)
		for w := 24; w <= 200; w++ {
			b := welcomeBanner(w)
			lines := strings.Split(b, "\n")
			if len(lines) != 3 {
				t.Fatalf("tier %v width %d: box is %d lines, want 3:\n%s", tier, w, len(lines), b)
			}
			for i, ln := range lines {
				if lipgloss.Width(ln) != w {
					t.Errorf("tier %v width %d: row %d is %d cols, want exactly %d: %q", tier, w, i, lipgloss.Width(ln), w, ln)
				}
			}
		}
		b := welcomeBanner(80)
		if !strings.Contains(b, "blk") || !strings.Contains(b, "Autonomous Offensive Security Framework") {
			t.Errorf("tier %v: box must name blk and the tagline:\n%s", tier, b)
		}
		for _, corner := range []string{"\u256D", "\u256E", "\u2570", "\u256F"} {
			if !strings.Contains(b, corner) {
				t.Errorf("tier %v: box lacks corner %q:\n%s", tier, corner, b)
			}
		}
	}
	// Nerd tier leads the title with the radar glyph; the unicode tier does not.
	vizForceTier(t, plNerd)
	if !strings.Contains(welcomeBanner(80), "\U000F2B10") {
		t.Error("nerd banner should carry the radar glyph U+F2B10")
	}
	vizForceTier(t, plUnicode)
	if b := welcomeBanner(80); strings.ContainsRune(b, 0xF2B10) {
		t.Errorf("unicode banner must not carry a Plane-15 glyph:\n%s", b)
	}
	// ASCII tier: no box, plain lines, still naming blk and the tagline.
	vizForceTier(t, plASCII)
	b := welcomeBanner(80)
	for _, corner := range []string{"\u256D", "\u2570"} {
		if strings.Contains(b, corner) {
			t.Errorf("ascii banner must not draw a box:\n%s", b)
		}
	}
	if !strings.Contains(b, "blk") || !strings.Contains(b, "Autonomous Offensive Security Framework") {
		t.Errorf("ascii banner must still name blk and the tagline:\n%s", b)
	}
}

func widestLine(s string) int {
	w := 0
	for _, ln := range strings.Split(s, "\n") {
		w = max(w, lipgloss.Width(ln))
	}
	return w
}

func TestHelpBlockLayout(t *testing.T) {
	noColor(t)
	out := helpBlock(100)
	lines := strings.Split(out, "\n")

	// The bare-question row is the first row of the first section.
	if !strings.Contains(lines[0], "ASK AND SEARCH") {
		t.Fatalf("first line = %q, want the first section title", lines[0])
	}
	if !strings.Contains(lines[1], "<question>") {
		t.Errorf("first row = %q, want the bare-question row", lines[1])
	}
	// /agent and /rag are folded into the /mode row.
	for _, ln := range lines {
		f := strings.Fields(ln)
		if len(f) > 0 && (f[0] == "/agent" || f[0] == "/rag") {
			t.Errorf("/agent and /rag must not be separate rows: %q", ln)
		}
		if len(f) > 0 && f[0] == "/mode" && !strings.Contains(ln, "/agent") {
			t.Errorf("the /mode row must name /agent and /rag: %q", ln)
		}
	}
	// One description column.
	col := strings.Index(lines[1], "type a question")
	if col < 0 {
		t.Fatalf("question row lacks its description: %q", lines[1])
	}
	rows := 0
	for _, ln := range lines {
		f := strings.Fields(ln)
		if len(f) == 0 || !(strings.HasPrefix(f[0], "/") || f[0] == "<question>" || f[0] == "s") || !strings.HasPrefix(ln, "   ") {
			continue
		}
		rows++
		if len(ln) <= col || ln[col] == ' ' || ln[col-1] != ' ' || ln[col-2] != ' ' {
			t.Errorf("description is not in column %d: %q", col, ln)
		}
	}
	if rows < 20 {
		t.Errorf("checked %d rows, want the whole command list", rows)
	}
	// Plain words, shared wording, and the closing pointer.
	for _, bad := range []string{"quick-pick", "d y ", "Enter submits", "ctrl+j newline"} {
		if strings.Contains(out, bad) {
			t.Errorf("help still contains %q", bad)
		}
	}
	for _, want := range []string{
		"reopen a saved session; clear or clear [n] erases",
		"answer a question, with cited sources",
		"find the most relevant source passages for a query",
		"start the local services",
		"stop the local services",
		"show whether each local service is running",
		"check qdrant, embed_server, and the LLM",
		"check the whole setup and say what to fix",
		"run one Hermes agent turn with the knowledge base",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help lacks the shared wording %q", want)
		}
	}
	if last := lines[len(lines)-1]; strings.TrimSpace(last) != "Press ? for keyboard shortcuts." {
		t.Errorf("last line = %q, want the shortcuts pointer", last)
	}
	for _, g := range []string{"ASK AND SEARCH", "MODES", "SESSION", "SERVICES", "AGENT (HERMES)", "SETUP"} {
		if !strings.Contains(out, g) {
			t.Errorf("help lacks the %s section", g)
		}
	}
}

func TestHelpBlockFitsNarrowTerminals(t *testing.T) {
	noColor(t)
	for _, w := range []int{40, 60, 80, 120} {
		if got := widestLine(helpBlock(w)); got > w {
			t.Errorf("help at %d columns has a %d column line", w, got)
		}
	}
}

func TestStatusLineLabelsEveryValue(t *testing.T) {
	noColor(t)
	m := layoutModel(t, 200, 24)
	m.ragModel, m.sessTitle = "gemma", "new session"
	line := m.statusLine()
	for _, want := range []string{"rag", "model gemma", "reasoning medium", "checking services", "new session"} {
		if !strings.Contains(line, want) {
			t.Errorf("status %q lacks %q", line, want)
		}
	}
	m.servicesChecked, m.servicesOK = true, true
	if line := m.statusLine(); !strings.Contains(line, "services ok") {
		t.Errorf("status %q lacks the services label", line)
	}
	m.mode, m.agentXport, m.agentChecked = "agent", "gateway", true
	if line := m.statusLine(); !strings.Contains(line, "agent") || !strings.Contains(line, "via gateway") {
		t.Errorf("agent status %q lacks the transport label", line)
	}
}

// The model name has priority: at 80 columns at least 24 characters of a long
// id show, and the other segments go first, in order: the session title, the
// reasoning, then the word "services". No row is ever wider than the terminal.
func TestStatusLineGivesTheModelPriority(t *testing.T) {
	noColor(t)
	long := "supergemma4-26b-uncensored-mlx-4bit-v2"
	base := layoutModel(t, 80, 24)
	base.ragModel, base.sessTitle, base.servicesChecked, base.servicesOK = long, "new session", true, true
	base.health = &serviceHealth{Qdrant: true, EmbedServer: true, LLM: true}
	base.prefs = defaultPrefs()

	for _, rerankUp := range []bool{true, false} {
		m := base
		m.rerankUp = rerankUp
		line := m.statusLine()
		if !strings.Contains(line, "model "+long[:24]) {
			t.Errorf("rerankUp=%v: 80 columns shows less than 24 characters of the model: %q", rerankUp, line)
		}
		for _, want := range []string{"embed ok", "rerank "} {
			if !strings.Contains(line, want) {
				t.Errorf("rerankUp=%v: status %q lacks %q", rerankUp, line, want)
			}
		}
	}

	for w := 200; w >= 20; w-- {
		nm, _ := base.Update(tea.WindowSizeMsg{Width: w, Height: 24})
		m := nm.(model)
		line := m.statusLine()
		title := strings.Contains(line, "new session")
		reasoning := strings.Contains(line, "reasoning")
		services := strings.Contains(line, "services")
		if title && !reasoning || reasoning && !services {
			t.Errorf("width %d: segments dropped out of order: %q", w, line)
		}
		if w >= 40 && !strings.Contains(line, "ok") {
			t.Errorf("width %d: the health state was lost: %q", w, line)
		}
		if w <= 120 {
			for i, ln := range strings.Split(m.View(), "\n") {
				if lipgloss.Width(ln) > w {
					t.Errorf("width %d: row %d is %d columns: %q", w, i, lipgloss.Width(ln), ln)
				}
			}
		}
	}
	m := base
	m.width = 50
	if line := m.statusLine(); strings.Contains(line, "reasoning") || strings.Contains(line, "new session") || strings.Contains(line, "embed") {
		t.Errorf("50 columns should collapse to mode, model, and health: %q", line)
	}
}

// The status line shows the embedder and reranker from the health probe and
// the reranker switch, in words.
func TestStatusLineShowsTheRetrievalModels(t *testing.T) {
	noColor(t)
	m := layoutModel(t, 200, 24)
	m.prefs = defaultPrefs()
	if line := m.statusLine(); strings.Contains(line, "embed") || strings.Contains(line, "rerank") {
		t.Errorf("before the first probe there is nothing to show: %q", line)
	}
	nm, _ := m.Update(healthMsg{h: &serviceHealth{Qdrant: true, EmbedServer: true, LLM: true}, rerank: true})
	m = nm.(model)
	if line := m.statusLine(); !strings.Contains(line, "embed ok") || !strings.Contains(line, "rerank ok") {
		t.Errorf("both up: %q", line)
	}
	nm, _ = m.Update(healthMsg{h: &serviceHealth{Qdrant: true, EmbedServer: true, LLM: true}})
	m = nm.(model)
	if line := m.statusLine(); !strings.Contains(line, "rerank down") {
		t.Errorf("reranker unavailable: %q", line)
	}
	m.prefs.Rerank = false
	if line := m.statusLine(); !strings.Contains(line, "rerank off") {
		t.Errorf("reranker turned off: %q", line)
	}
	nm, _ = m.Update(healthMsg{h: &serviceHealth{Qdrant: true, LLM: true}})
	if line := nm.(model).statusLine(); !strings.Contains(line, "embed down") || !strings.Contains(line, "rerank off") {
		t.Errorf("embed_server down: %q", line)
	}

	// A switch changed in the panel shows at once.
	pm := panelModel(t, 200, 24)
	pm = selectRow(t, pm, "reranker")
	pm, _ = step(t, pm, keySpace)
	if line := pm.statusLine(); !strings.Contains(line, "rerank off") {
		t.Errorf("status line does not follow the panel: %q", line)
	}
}

func TestStatusLineShowsRagSwitch(t *testing.T) {
	noColor(t)
	m := layoutModel(t, 200, 24)
	m.prefs = defaultPrefs() // Rag on by default: implied by rag mode, not labeled
	if line := m.statusLine(); strings.Contains(line, "rag off") {
		t.Errorf("rag on (the default) should not surface a rag-off label: %q", line)
	}
	m.prefs.Rag = false
	if line := m.statusLine(); !strings.Contains(line, "rag off") {
		t.Errorf("rag off should show when grounding is switched off: %q", line)
	}
	// Agent mode uses a separate status line with no retrieval group, so the
	// rag switch never shows there.
	am := layoutModel(t, 200, 24)
	am.mode, am.agentXport, am.agentChecked = "agent", "gateway", true
	am.prefs = defaultPrefs()
	am.prefs.Rag = false
	if line := am.statusLine(); strings.Contains(line, "rag off") {
		t.Errorf("agent mode must not show the rag switch: %q", line)
	}
}

func TestFirstDownProbePrintsOneHint(t *testing.T) {
	noColor(t)
	t.Setenv("OMLX_BASE_URL", "http://user:hunter2@127.0.0.1:8000/v1?token=abc")
	m := layoutModel(t, 100, 24)

	probe := func(h serviceHealth) tea.Msg { return healthMsg{h: &h} }
	nm, cmd := m.Update(probe(serviceHealth{LLM: true}))
	got := nm.(model)
	out := printed(t, cmd)
	if !strings.Contains(out, "qdrant and embed_server are down. Run /up to start them.") {
		t.Errorf("hint = %q", out)
	}
	if strings.Count(out, "\n") != 0 {
		t.Errorf("the hint must be one line: %q", out)
	}
	// Once per session: a second probe stays quiet.
	if _, cmd := got.Update(probe(serviceHealth{LLM: true})); cmd != nil {
		t.Error("a later probe must not print the hint again")
	}

	// A healthy first probe prints nothing, and spends the hint: a service that
	// drops later is shown in the status line, not announced again.
	nm, cmd = m.Update(probe(serviceHealth{Qdrant: true, EmbedServer: true, LLM: true}))
	if cmd != nil {
		t.Error("a healthy probe must not print a hint")
	}
	if _, cmd := nm.(model).Update(probe(serviceHealth{LLM: true})); cmd != nil {
		t.Error("only the first probe of a session prints the hint")
	}

	// One local service down uses the singular.
	_, cmd = m.Update(probe(serviceHealth{Qdrant: true, LLM: true}))
	if out := printed(t, cmd); !strings.Contains(out, "embed_server is down. Run /up to start it.") {
		t.Errorf("singular hint = %q", out)
	}

	// The LLM alone: say where to start it, without credentials.
	_, cmd = m.Update(probe(serviceHealth{Qdrant: true, EmbedServer: true}))
	out = printed(t, cmd)
	if !strings.Contains(out, "start the LLM server at http://127.0.0.1:8000/v1") {
		t.Errorf("LLM hint = %q", out)
	}
	for _, leak := range []string{"hunter2", "token=abc", "user:"} {
		if strings.Contains(out, leak) {
			t.Errorf("LLM hint leaks %q: %q", leak, out)
		}
	}
	if strings.Contains(out, "/up") {
		t.Errorf("the LLM is not started by /up: %q", out)
	}

	// Both: name both fixes, and wrap inside a narrow terminal.
	_, cmd = m.Update(probe(serviceHealth{}))
	if out := printed(t, cmd); !strings.Contains(out, "/up") || !strings.Contains(out, "LLM server") {
		t.Errorf("combined hint = %q", out)
	}
	for _, w := range []int{40, 80} {
		hint := downHint(&serviceHealth{}, w)
		if got := widestLine(hint); got > w {
			t.Errorf("width %d: hint has a %d column line:\n%s", w, got, hint)
		}
	}
}

func TestKeyPanelFooterOffersScrollOnlyWhenCut(t *testing.T) {
	tall := openKeyPanel(t, layoutModel(t, 80, 40))
	if got := helpText(tall.footerKeys().short); strings.Contains(got, "scroll") {
		t.Errorf("a panel that fits needs no scroll hint: %q", got)
	}
	short := openKeyPanel(t, layoutModel(t, 40, 10))
	if got := helpText(short.footerKeys().short); !strings.Contains(got, "scroll") {
		t.Errorf("a cut panel needs the scroll hint: %q", got)
	}
}

// An answer made with the reranker off says so in its sources block, in words,
// in both the TUI and blk ask; one made with it on does not.
func TestAnswerSaysWhenTheRerankerWasOff(t *testing.T) {
	noColor(t)
	resp := &answerResponse{Answer: "x [1]", Citations: []citation{{Source: "wstg", Path: "a.md"}}}
	if out := formatAnswer(resp, time.Second, 80, true); !strings.Contains(out, "reranker was off") {
		t.Errorf("TUI answer lacks the reranker note:\n%s", out)
	}
	if out := formatAnswer(resp, time.Second, 80, false); strings.Contains(out, "reranker") {
		t.Errorf("TUI answer mentions the reranker while it was on:\n%s", out)
	}
	out := captureStdout(t, func() { printSources(resp.Citations, false, true) })
	if !strings.Contains(out, "reranker was off") {
		t.Errorf("blk ask sources lack the reranker note:\n%s", out)
	}
}

// The in-memory history keeps at most historyMaxEntries, the newest.
func TestTUIHistoryInMemoryIsCapped(t *testing.T) {
	m := newKeyModel(t)
	m.history = nil
	for i := 0; i < historyMaxEntries+5; i++ {
		m.history = append(m.history, fmt.Sprint("old ", i))
	}
	m.ta.SetValue("/help")
	nm, _ := m.submit()
	m = nm.(model)
	if len(m.history) != historyMaxEntries || m.history[len(m.history)-1] != "/help" || m.histIdx != len(m.history) {
		t.Errorf("history has %d entries ending %q (idx %d), want %d ending /help", len(m.history), m.history[len(m.history)-1], m.histIdx, historyMaxEntries)
	}
}

// Every footer keeps its way out: at 24 columns or more the close, quit, or
// cancel hint is there, dropped last when other hints do not fit. The welcome
// banner keeps its quit hint too.
func TestEveryFooterKeepsItsWayOut(t *testing.T) {
	noColor(t)
	for _, w := range []int{24, 32, 40, 80} {
		sized := func(m model) model {
			nm, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: 30})
			return nm.(model)
		}
		with := func(ov overlayModel) model {
			m := sized(newKeyModel(t))
			m.overlay = ov
			return m
		}
		confirm := newHistoryPicker(manySessions(2), "", w)
		confirm.confirm = true
		working := sized(newKeyModel(t))
		working.working = true
		queued := working
		queued.queue = []string{"next"}
		rsearch := sized(newKeyModel(t))
		rsearch.rsearch.open = true
		pal := sized(newKeyModel(t))
		pal.pal = palette{open: true, items: filterCommands(slashCommands(), "")}
		armed := panelModel(t, w, 30)
		armed, _ = step(t, armed, keyRunes("u"))
		cases := []struct {
			name string
			m    model
			want string
		}{
			{"idle", sized(newKeyModel(t)), "ctrl+d quit"},
			{"working", working, "ctrl+d quit"},
			{"working with a queue", queued, "ctrl+d quit"},
			{"key panel", openKeyPanel(t, sized(newKeyModel(t))), "esc close"},
			{"reverse search", rsearch, "esc/ctrl+c cancel"},
			{"palette", pal, "esc/ctrl+c close"},
			{"resume", with(newHistoryPicker(manySessions(2), "", w)), "esc/ctrl+c close"},
			{"resume confirm", with(confirm), "y confirm delete"},
			{"model picker", with(newModelPicker(manyModels(2), "model-00", "low", w)), "esc/ctrl+c close"},
			{"file picker", with(newFilePicker(t.TempDir(), w)), "esc/ctrl+c close"},
			{"models panel", panelModel(t, w, 30), "esc/ctrl+c close"},
			{"models panel, unload armed", armed, "u confirm unload"},
		}
		for _, c := range cases {
			f := c.m.footer()
			if !strings.Contains(f, c.want) {
				t.Errorf("%d columns, %s: footer %q lacks %q", w, c.name, f, c.want)
			}
			if lipgloss.Width(f) > w || strings.Contains(f, "\n") {
				t.Errorf("%d columns, %s: footer %q does not fit one row", w, c.name, f)
			}
		}
		if w == 80 {
			// With room for everything, nothing is dropped.
			if f := sized(newKeyModel(t)).footer(); !strings.Contains(f, "enter ask") || !strings.Contains(f, "? keys") {
				t.Errorf("80 columns: idle footer %q lost hints", f)
			}
		}
	}
}

// In a confirm state the pending confirmation matters most: the confirm hint
// is kept longest, then the cancel hint, then quit.
func TestConfirmFootersKeepTheConfirmKey(t *testing.T) {
	noColor(t)
	for _, w := range []int{24, 32, 40, 80} {
		confirm := newHistoryPicker(manySessions(2), "", w)
		confirm.confirm = true
		resume := newKeyModel(t)
		nm, _ := resume.Update(tea.WindowSizeMsg{Width: w, Height: 30})
		resume = nm.(model)
		resume.overlay = confirm
		armed, _ := step(t, panelModel(t, w, 30), keyRunes("u"))
		for name, c := range map[string]struct {
			m       model
			confirm string
		}{"resume delete": {resume, "y confirm delete"}, "armed unload": {armed, "u confirm unload"}} {
			f := c.m.footer()
			has := func(s string) bool { return strings.Contains(f, s) }
			if !has(c.confirm) {
				t.Errorf("%d columns, %s: footer %q lacks %q", w, name, f, c.confirm)
			}
			if has("ctrl+d quit") && !has("any other key cancel") {
				t.Errorf("%d columns, %s: footer %q keeps quit over cancel", w, name, f)
			}
			if w == 80 && (!has("any other key cancel") || !has("ctrl+d quit")) {
				t.Errorf("80 columns, %s: footer %q should show every hint", name, f)
			}
			if lipgloss.Width(f) > w {
				t.Errorf("%d columns, %s: footer %q is too wide", w, name, f)
			}
		}
	}
}

// The idle footer drops ctrl+j newline first, then enter ask, then ? keys,
// and ctrl+d quit last: ? keys opens the full key list.
func TestIdleFooterKeepsTheKeysHint(t *testing.T) {
	noColor(t)
	order := []string{"ctrl+d quit", "? keys", "enter ask", "ctrl+j newline"}
	for _, w := range []int{24, 32, 40} {
		m := newKeyModel(t)
		nm, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: 30})
		f := nm.(model).footer()
		if !strings.Contains(f, "? keys") || !strings.Contains(f, "ctrl+d quit") {
			t.Errorf("%d columns: idle footer %q lacks ? keys or ctrl+d quit", w, f)
		}
		for i := 1; i < len(order); i++ {
			if strings.Contains(f, order[i]) && !strings.Contains(f, order[i-1]) {
				t.Errorf("%d columns: idle footer %q keeps %q but dropped %q", w, f, order[i], order[i-1])
			}
		}
	}
}

// The ribbon status line keeps the collapse order and never exceeds the width.
func TestStatusRibbonCollapsesNarrow(t *testing.T) {
	noColor(t)
	m := newTestModel(t)
	m.width = 30
	m.servicesChecked = true
	m.servicesOK = true
	line := m.statusLine()
	if lipgloss.Width(line) > 30 {
		t.Fatalf("status width %d exceeds 30: %q", lipgloss.Width(line), line)
	}
	if !strings.Contains(line, "rag") {
		t.Fatalf("collapsed status lost the mode: %q", line)
	}
}

// The viz segment follows the viz preference (ascii tier).
func TestStatusRibbonShowsViz(t *testing.T) {
	noColor(t)
	m := layoutModel(t, 200, 24)
	m.prefs = defaultPrefs()
	if line := m.statusLine(); !strings.Contains(line, "viz") || strings.Contains(line, "viz off") {
		t.Errorf("viz on: status %q should show a plain viz segment", line)
	}
	m.prefs.Viz = false
	if line := m.statusLine(); !strings.Contains(line, "viz off") {
		t.Errorf("viz off: status %q lacks \"viz off\"", line)
	}
}

// The colored ribbon (unicode tier) fits the width, carries the segment
// content, and uses both hard arrows and thin separators.
func colorStatusLine(t *testing.T, powerline string) string {
	t.Helper()
	oldC, oldU := useColor, useUnicode
	useColor, useUnicode = true, true
	t.Cleanup(func() { useColor, useUnicode = oldC, oldU })
	t.Setenv("BLKCHAIN_POWERLINE", powerline)

	m := newTestModel(t)
	m.width = 120
	m.ragModel = "gemma"
	m.reasoning = "medium"
	m.servicesChecked, m.servicesOK = true, true
	// The embed and rerank segments share a fill, so they join with a thin separator.
	m.health, m.rerankUp = &serviceHealth{EmbedServer: true}, true
	m.prefs = defaultPrefs()
	line := m.statusLine()
	if w := lipgloss.Width(line); w > 120 {
		t.Errorf("colored status width %d exceeds 120: %q", w, line)
	}
	for _, want := range []string{"rag", "model gemma", "services ok", "viz"} {
		if !strings.Contains(line, want) {
			t.Errorf("colored status %q lacks %q", line, want)
		}
	}
	return line
}

func TestStatusRibbonColorTier(t *testing.T) {
	line := colorStatusLine(t, "0")
	if !strings.Contains(line, "\u25B6") {
		t.Errorf("unicode status lacks a hard arrow: %q", line)
	}
	if !strings.Contains(line, "\u2502") {
		t.Errorf("unicode status lacks a thin separator: %q", line)
	}
	if strings.Contains(line, "\U000F2B00") || strings.Contains(line, "\U000F2B03") {
		t.Errorf("unicode status carries nerd icons: %q", line)
	}
}

func TestStatusRibbonNerdTier(t *testing.T) {
	for _, env := range []string{"", "1"} {
		line := colorStatusLine(t, env)
		for name, want := range map[string]string{
			"separator": "\ue0b0", "mode database icon": "\U000F2B00", "model icon": "\U000F2B01",
			"reasoning icon": "\U000F2B02", "services heartbeat icon": "\U000F2B03", "viz icon": "\U000F2B04",
		} {
			if !strings.Contains(line, want) {
				t.Errorf("POWERLINE=%q nerd status lacks %s %q: %q", env, name, want, line)
			}
		}
		if strings.Contains(line, "\u25B6") {
			t.Errorf("POWERLINE=%q nerd status uses the unicode arrow: %q", env, line)
		}
	}
}

func TestVizBarShowsStageAndMeter(t *testing.T) {
	m := newTestModel(t)
	m.prefs.Viz = true
	stub := newStubEngagement("acme")
	stub.setSnapshot(eng.Engagement{ActiveID: "t2", Stage: eng.Stage{Label: "web: SQLi on /login", Step: 3, Total: 6, Tool: "run_command"}})
	m.engagement = stub
	bar := stripANSI(m.vizBar())
	for _, want := range []string{"web: SQLi on /login", "3/6", "run_command"} {
		if !strings.Contains(bar, want) {
			t.Fatalf("vizBar missing %q: %q", want, bar)
		}
	}
	m.prefs.Viz = false
	if m.vizBar() != "" {
		t.Fatalf("vizBar should be empty when viz off")
	}
}

var tsReadoutRe = regexp.MustCompile(`~\d+ t/s`)

func TestVizBarShowsLiveTokensPerSec(t *testing.T) {
	m := newTestModel(t)
	m.prefs.Viz = true
	stub := newStubEngagement("acme")
	stub.setSnapshot(eng.Engagement{Stage: eng.Stage{Label: "web: SQLi on /login", Step: 3, Total: 6, Tool: "run_command"}})
	m.engagement = stub
	m.firstTokAt = time.Now().Add(-2 * time.Second)
	m.liveTokens = 300 // 300 chunks / ~2s = ~150/s
	bar := stripANSI(m.vizBar())
	// The rate is approximate (a delta can carry several tokens, so the chunk count
	// under-reports): a leading "~" qualifier, an integer, labeled t/s (section 4).
	if !tsReadoutRe.MatchString(bar) {
		t.Fatalf("vizBar should show an approximate integer t/s rate while streaming: %q", bar)
	}
	if strings.Contains(bar, "150.0") {
		t.Fatalf("an approximate rate should carry no decimal: %q", bar)
	}
	if !strings.Contains(bar, "150") {
		t.Fatalf("vizBar should show the real rate ~150: %q", bar)
	}
	if strings.Contains(bar, "tok/s") {
		t.Fatalf("vizBar should use the t/s label, not tok/s: %q", bar)
	}
	// absent when the model has not streamed this turn
	m.liveTokens = 0
	m.firstTokAt = time.Time{}
	if strings.Contains(stripANSI(m.vizBar()), "t/s") {
		t.Fatalf("vizBar must not show a t/s rate before the first token")
	}
}

// The t/s number is wTanFg (palette "t/s"), never the old wSageFg.
func TestVizBarTokensPerSecColoredTan(t *testing.T) {
	vizForceColor(t)
	vizForceTier(t, plNerd)
	m := newTestModel(t)
	m.prefs.Viz = true
	stub := newStubEngagement("acme")
	stub.setSnapshot(eng.Engagement{Stage: eng.Stage{Label: "web: SQLi on /login", Step: 3, Total: 6, Tool: "run_command"}})
	m.engagement = stub
	m.firstTokAt = time.Now().Add(-2 * time.Second)
	m.liveTokens = 300
	bar := m.vizBar() // colored, not stripped
	// Derive the exact foreground escapes the active profile emits for each token
	// (termenv rounds truecolor), so the assertion does not hardcode RGB.
	fgRe := regexp.MustCompile(`38;2;\d+;\d+;\d+`)
	tanFg := fgRe.FindString(lipgloss.NewStyle().Foreground(wTanFg).Render("x"))
	sageFg := fgRe.FindString(lipgloss.NewStyle().Foreground(wSageFg).Render("x"))
	if tanFg == "" || sageFg == "" {
		t.Fatalf("could not derive fg escapes (tan=%q sage=%q)", tanFg, sageFg)
	}
	if !strings.Contains(bar, tanFg) {
		t.Fatalf("t/s number must be rendered wTanFg (%s): %q", tanFg, bar)
	}
	if strings.Contains(bar, sageFg) {
		t.Fatalf("t/s number must not keep the old sage color (%s): %q", sageFg, bar)
	}
}

// Nerd tier leads the bar with the play glyph (F2B06) and spins with the loader
// glyph (F2B05), reconciling the section-4 loader with the section-7 icon map.
func TestVizBarNerdTierUsesPlayAndLoaderGlyphs(t *testing.T) {
	vizForceTier(t, plNerd)
	m := newTestModel(t)
	m.prefs.Viz = true
	stub := newStubEngagement("acme")
	stub.setSnapshot(eng.Engagement{Stage: eng.Stage{Label: "recon: scan", Step: 1, Total: 4, Tool: "run_command"}})
	m.engagement = stub
	bar := stripANSI(m.vizBar())
	for name, glyph := range map[string]string{"play F2B06": "\U000F2B06", "loader F2B05": "\U000F2B05"} {
		if !strings.Contains(bar, glyph) {
			t.Fatalf("nerd viz bar lacks %s: %q", name, bar)
		}
	}
	for _, old := range []string{"⠿", "▎"} {
		if strings.Contains(bar, old) {
			t.Fatalf("nerd viz bar should not keep %q: %q", old, bar)
		}
	}
}

// Unicode and ascii tiers keep the braille loader and accent; no Plane-15 glyph
// leaks into a terminal without the patched font.
func TestVizBarNonNerdKeepsBrailleLoader(t *testing.T) {
	for _, tier := range []plTier{plASCII, plUnicode} {
		vizForceTier(t, tier)
		m := newTestModel(t)
		m.prefs.Viz = true
		stub := newStubEngagement("acme")
		stub.setSnapshot(eng.Engagement{Stage: eng.Stage{Label: "recon: scan", Step: 1, Total: 4}})
		m.engagement = stub
		bar := stripANSI(m.vizBar())
		if !strings.Contains(bar, "⠿") || !strings.Contains(bar, "▎") {
			t.Fatalf("tier %v should keep the braille loader and accent: %q", tier, bar)
		}
		for _, r := range bar {
			if r >= 0xF2B00 && r <= 0xF2BFF {
				t.Fatalf("tier %v leaked a Plane-15 glyph %U: %q", tier, r, bar)
			}
		}
	}
}

func TestVizBarEmptyWithoutEngagementOrTotal(t *testing.T) {
	m := newTestModel(t)
	m.prefs.Viz = true
	m.engagement = nil
	if got := m.vizBar(); got != "" {
		t.Fatalf("vizBar with nil engagement = %q, want empty", got)
	}
	stub := newStubEngagement("acme")
	stub.setSnapshot(eng.Engagement{Stage: eng.Stage{Label: "idle", Step: 0, Total: 0}})
	m.engagement = stub
	if got := m.vizBar(); got != "" {
		t.Fatalf("vizBar with zero Total = %q, want empty", got)
	}
}

func TestViewPrefersVizBarWhileWorking(t *testing.T) {
	m := newTestModel(t)
	m.prefs.Viz = true
	m.working = true
	m.workingVerb = "Thinking"
	m.turnStart = time.Now()
	stub := newStubEngagement("acme")
	stub.setSnapshot(eng.Engagement{Stage: eng.Stage{Label: "web: SQLi on /login", Step: 3, Total: 6}})
	m.engagement = stub
	out := stripANSI(m.View())
	if !strings.Contains(out, "web: SQLi on /login") || strings.Contains(out, "Thinking") {
		t.Fatalf("View should show the viz bar in place of the spinner line: %q", out)
	}
	m.engagement = nil
	out = stripANSI(m.View())
	if !strings.Contains(out, "Thinking") {
		t.Fatalf("View should fall back to the spinner line: %q", out)
	}
}

func TestVizCommitOnlyOnRevisionChange(t *testing.T) {
	r := newVizRenderer(&fakeRunner{out: "web: SQLi on /login"})
	stub := newStubEngagement("acme")
	stub.setSnapshot(sampleEngagement(0)) // rev 1
	block, changed, _ := r.Block(context.Background(), stub)
	if !changed || stripANSI(block) == "" {
		t.Fatalf("first poll should produce a block")
	}
	if _, changed2, _ := r.Block(context.Background(), stub); changed2 {
		t.Fatalf("no revision change must not recommit")
	}
	stub.setSnapshot(sampleEngagement(0)) // rev 2
	if _, changed3, _ := r.Block(context.Background(), stub); !changed3 {
		t.Fatalf("revision change must recommit")
	}
}

func TestVizCommitCmdGatingAndMessages(t *testing.T) {
	m := newTestModel(t)
	if m.vizCommitCmd() != nil {
		t.Fatalf("nil engagement must yield no command")
	}
	stub := newStubEngagement("acme")
	stub.setSnapshot(sampleEngagement(0))
	m.engagement = stub
	m.viz = newVizRenderer(&fakeRunner{out: "web: SQLi on /login"})
	m.prefs.Viz = false
	if m.vizCommitCmd() != nil {
		t.Fatalf("viz off must yield no command")
	}
	m.prefs.Viz = true
	cmd := m.vizCommitCmd()
	if cmd == nil {
		t.Fatalf("viz on with an engagement must yield a command")
	}
	msg, ok := cmd().(vizBlockMsg)
	if !ok || stripANSI(msg.block) == "" {
		t.Fatalf("first poll should emit a vizBlockMsg with a block, got %#v", msg)
	}
	if got := m.vizCommitCmd()(); got != nil {
		t.Fatalf("unchanged revision must emit no message, got %#v", got)
	}
}

func TestVizBlockMsgPrintsBlockOnly(t *testing.T) {
	m := newTestModel(t)
	if _, cmd := m.Update(vizBlockMsg{}); cmd != nil {
		t.Fatalf("empty vizBlockMsg must be ignored")
	}
	_, cmd := m.Update(vizBlockMsg{block: "graph"})
	if cmd == nil {
		t.Fatalf("non-empty vizBlockMsg must print")
	}
	if cmd() == nil {
		t.Fatalf("print command must produce a message")
	}
}

func TestVizTickPollsInBothMotionModes(t *testing.T) {
	for _, reduced := range []bool{false, true} {
		m := newTestModel(t)
		m.working, m.reduceMotion, m.tickGen = true, reduced, 3
		m.engagement = newStubEngagement("acme")
		m.viz = newVizRenderer(&fakeRunner{out: "x"})
		m.prefs.Viz = true
		if _, cmd := m.Update(vizTickMsg{gen: 3}); cmd == nil {
			t.Fatalf("reduceMotion=%v: current-gen vizTick must poll and re-arm", reduced)
		}
		if _, cmd := m.Update(vizTickMsg{gen: 2}); cmd != nil {
			t.Fatalf("reduceMotion=%v: stale-gen vizTick must be dropped", reduced)
		}
		idle := m
		idle.working = false
		if _, cmd := idle.Update(vizTickMsg{gen: 3}); cmd != nil {
			t.Fatalf("reduceMotion=%v: idle model must drop vizTick", reduced)
		}
	}
}

func TestVizTickDroppedWithoutEngagement(t *testing.T) {
	m := newTestModel(t)
	m.working, m.tickGen = true, 1
	if _, cmd := m.Update(vizTickMsg{gen: 1}); cmd != nil {
		t.Fatalf("vizTick without an engagement must be dropped")
	}
	if m.startVizPoll() != nil {
		t.Fatalf("no engagement must not start the poll")
	}
	m.engagement = newStubEngagement("acme")
	if m.startVizPoll() == nil {
		t.Fatalf("an engagement must start the poll")
	}
}

func TestVizCommandTogglesPref(t *testing.T) {
	m := newTestModel(t)
	m.prefs.Viz = true

	nm, _ := m.dispatchInput("/viz off")
	m = nm.(model)
	if m.prefs.Viz {
		t.Fatalf("/viz off should set Viz false")
	}
	if loadPrefs().Viz {
		t.Fatalf("/viz off should persist Viz false")
	}

	nm, _ = m.dispatchInput("/viz on")
	m = nm.(model)
	if !m.prefs.Viz {
		t.Fatalf("viz on should set Viz true")
	}

	nm, _ = m.dispatchInput("/viz")
	m = nm.(model)
	if m.prefs.Viz {
		t.Fatalf("bare /viz should toggle Viz to false")
	}
	nm, _ = m.dispatchInput("/viz toggle")
	m = nm.(model)
	if !m.prefs.Viz {
		t.Fatalf("/viz toggle should flip Viz back to true")
	}

	nm, _ = m.dispatchInput("/viz maybe")
	m = nm.(model)
	if !m.prefs.Viz {
		t.Fatalf("an unknown arg must leave Viz unchanged")
	}
}

// /help <command> shows that one command's help (the CLI renderer), /help alone
// shows the full list, and an unknown name is reported.
func TestHelpResponseScopesToCommand(t *testing.T) {
	noColor(t)
	c, ok := lookupCommand("ask")
	if !ok {
		t.Fatal("ask missing from the command registry")
	}
	got := helpResponse("ask", 100)
	if want := strings.TrimRight(renderCommandHelp(c, 100), "\n"); got != want {
		t.Errorf("helpResponse(ask) is not the ask command help.\n got: %q\nwant: %q", got, want)
	}
	if strings.Contains(got, "/mode") {
		t.Errorf("per-command help leaked the full command list: %q", got)
	}
	// only the first token names the command; trailing text is ignored.
	if helpResponse("ask --json foo", 100) != got {
		t.Error("only the first token should name the command")
	}
	// no argument keeps the full command list.
	if full := helpResponse("", 100); !strings.Contains(full, "/mode") {
		t.Errorf("bare /help should render the full list: %q", full)
	}
	// an unknown command is reported with the shared suggestion phrasing.
	if bad := helpResponse("nope", 100); !strings.Contains(bad, "unknown command") {
		t.Errorf("unknown command should be reported: %q", bad)
	}
}

// /generate uses an explicit argument, else the last search query.
func TestGenerateQuestionPrefersArgThenLastQuery(t *testing.T) {
	if got := generateQuestion("  specific ask  ", "last search"); got != "specific ask" {
		t.Errorf("arg should win (trimmed): %q", got)
	}
	if got := generateQuestion("", "last search"); got != "last search" {
		t.Errorf("empty arg should fall back to the last query: %q", got)
	}
	if got := generateQuestion("   ", "last search"); got != "last search" {
		t.Errorf("whitespace arg should fall back to the last query: %q", got)
	}
}

// A /search retains its query and results so /generate can synthesize from them.
func TestSearchMsgRetainsResultsForGenerate(t *testing.T) {
	m := newTestModel(t)
	m.working = true
	res := []retrieval.Result{{ID: "a", Payload: retrieval.Payload{Path: "x.md"}}}
	nm, _ := m.Update(searchMsg{query: "ssrf", results: res, elapsed: time.Second})
	got := nm.(model)
	if got.lastQuery != "ssrf" {
		t.Errorf("searchMsg should retain the query, got %q", got.lastQuery)
	}
	if len(got.lastResults) != 1 || got.lastResults[0].ID != "a" {
		t.Errorf("searchMsg should retain the results, got %+v", got.lastResults)
	}
}

// /generate does nothing until a search has run, then starts a turn.
func TestGenerateGatedUntilSearch(t *testing.T) {
	m := newTestModel(t)
	m.width, m.height = 100, 24
	nm, _ := m.dispatchInput("/generate")
	if nm.(model).working {
		t.Fatal("/generate with no prior search must not start a turn")
	}
	m.lastResults = []retrieval.Result{{ID: "a", Payload: retrieval.Payload{Path: "x.md"}}}
	m.lastQuery = "ssrf"
	nm, _ = m.dispatchInput("/generate")
	if !nm.(model).working {
		t.Fatal("/generate after a search should start a turn")
	}
}

// generateCmd synthesizes from the given results via the seam and ends the turn,
// and the done message sets the last answer and the /open targets.
func TestGenerateCmdSynthesizesAndEndsTurn(t *testing.T) {
	noColor(t)
	var gotQ string
	var gotN int
	orig := synthFromResultsFn
	synthFromResultsFn = func(ctx context.Context, cfg ragconfig.Config, question string, results []retrieval.Result, opts AnswerOpts) (string, []citation, int, error) {
		gotQ, gotN = question, len(results)
		return "SYNTH ANSWER", []citation{{Source: "wstg", Path: "ssrf.md", Section: "imds"}}, 9, nil
	}
	t.Cleanup(func() { synthFromResultsFn = orig })

	m := newTestModel(t)
	res := []retrieval.Result{{ID: "a"}, {ID: "b"}}
	msg := m.generateCmd(context.Background(), "my question", res, time.Now())()
	done, ok := msg.(streamDoneMsg)
	if !ok {
		t.Fatalf("generateCmd should return streamDoneMsg, got %T", msg)
	}
	if gotQ != "my question" || gotN != 2 {
		t.Fatalf("SynthesizeFromResults got question=%q n=%d; want (my question, 2)", gotQ, gotN)
	}
	if done.full != "SYNTH ANSWER" || done.tokens != 9 || len(done.citations) != 1 {
		t.Fatalf("done msg = %+v", done)
	}
	m.working = true
	nm, _ := m.Update(done)
	gm := nm.(model)
	if gm.lastAnswer != "SYNTH ANSWER" {
		t.Errorf("lastAnswer = %q", gm.lastAnswer)
	}
	if len(gm.openTargets) != 1 || gm.openTargets[0].Path != "ssrf.md" {
		t.Errorf("openTargets = %+v", gm.openTargets)
	}
}

func TestVizCommandIsRegisteredAndInReplHelp(t *testing.T) {
	if _, ok := slashCommand("viz"); !ok {
		t.Fatalf("viz is not in the slash registry")
	}
	found := false
	for _, g := range replGroups() {
		for _, r := range g.rows {
			if strings.HasPrefix(r.name, "/viz") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("plain REPL help has no /viz row")
	}
}

// The TUI's rag-mode turn goes through the adaptive router, with the enabled
// routes from the saved switches and the one-shot force flag.
func TestStreamCmdUsesAdaptiveRouter(t *testing.T) {
	useDeadServices(t)
	old := adaptiveAnswerFn
	var gotEnabled enabledRoutes
	var gotForce bool
	called := false
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, enabled enabledRoutes, force bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		gotEnabled, gotForce, called = enabled, force, true
		if opts.Stream != nil {
			opts.Stream([]byte("hi"))
		}
		return "hi", nil, false, nil, 1, "skip", nil
	}
	defer func() { adaptiveAnswerFn = old }()

	m := frameModel(t)
	cmd := m.streamCmd(context.Background(), "q", "", time.Now(), true)
	if cmd == nil {
		t.Fatal("streamCmd returned nil")
	}
	if _, ok := cmd().(streamDoneMsg); !ok {
		t.Error("streamCmd did not finish with a streamDoneMsg")
	}
	if !called {
		t.Fatal("streamCmd did not call the adaptive router")
	}
	if !gotForce {
		t.Error("force not threaded into the router")
	}
	if !gotEnabled.Local {
		t.Error("enabled.Local should reflect the default rag switch")
	}
}

// /safe and /auto set the session autonomy mode held on the model, and /safe
// clears a prior /auto override. These feed buildEngageGate via runReplEngage.
func TestSafeAutoCommandsSetEngageMode(t *testing.T) {
	m := newTestModel(t)
	if m.engageMode != secgate.Safe || m.engageOverride {
		t.Fatalf("a fresh model should default to Safe with no override, got mode=%v override=%v", m.engageMode, m.engageOverride)
	}

	nm, _ := m.dispatchInput("/auto")
	m = nm.(model)
	if m.engageMode != secgate.Auto {
		t.Fatalf("/auto should set engageMode Auto, got %v", m.engageMode)
	}
	if m.engageOverride {
		t.Fatalf("bare /auto must not set the scope override")
	}

	nm, _ = m.dispatchInput("/auto override")
	m = nm.(model)
	if m.engageMode != secgate.Auto || !m.engageOverride {
		t.Fatalf("/auto override should set Auto with override, got mode=%v override=%v", m.engageMode, m.engageOverride)
	}

	// EqualFold: the override keyword is case-insensitive.
	nm, _ = m.dispatchInput("/safe")
	m = nm.(model)
	nm, _ = m.dispatchInput("/auto OVERRIDE")
	m = nm.(model)
	if m.engageMode != secgate.Auto || !m.engageOverride {
		t.Fatalf("/auto OVERRIDE should set override (case-insensitive), got mode=%v override=%v", m.engageMode, m.engageOverride)
	}

	// A non-"override" argument is not the override keyword.
	nm, _ = m.dispatchInput("/auto scope")
	m = nm.(model)
	if m.engageMode != secgate.Auto || m.engageOverride {
		t.Fatalf("/auto <other> must not set the override, got mode=%v override=%v", m.engageMode, m.engageOverride)
	}

	// /safe returns to Safe and clears the override.
	nm, _ = m.dispatchInput("/auto override")
	m = nm.(model)
	nm, _ = m.dispatchInput("/safe")
	m = nm.(model)
	if m.engageMode != secgate.Safe || m.engageOverride {
		t.Fatalf("/safe should reset to Safe and clear the override, got mode=%v override=%v", m.engageMode, m.engageOverride)
	}
}

// autoModeNote states the autonomy posture: override takes precedence, a missing
// scope warns that commands still prompt, and an in-scope run notes LOCAL still
// confirms.
func TestAutoModeNote(t *testing.T) {
	cases := []struct {
		override, scope bool
		want            string
	}{
		{true, false, "override on"},
		{true, true, "override on"}, // override takes precedence over scope detection
		{false, false, "no scope detected"},
		{false, true, "within scope"},
	}
	for _, tc := range cases {
		got := autoModeNote(tc.override, tc.scope)
		if !strings.Contains(got, tc.want) {
			t.Errorf("autoModeNote(override=%v, scope=%v) = %q; want it to contain %q", tc.override, tc.scope, got, tc.want)
		}
		if tc.override && strings.Contains(got, "no scope detected") {
			t.Errorf("autoModeNote(override=%v, scope=%v) = %q; override must not warn about a missing scope", tc.override, tc.scope, got)
		}
	}
}

// --- Slice 3: ribbon engage-mode (autonomy) safety segment ------------------

// engageModeSeg is the autonomy-mode label: safe, auto, auto (hitl) when the
// unattended bound is empty, and an override marker when the scope override is on.
func TestEngageModeSeg(t *testing.T) {
	cases := []struct {
		mode             secgate.Mode
		override, hitl   bool
		want, wantAbsent string
	}{
		{secgate.Safe, false, false, "safe", "auto"},
		{secgate.Safe, true, true, "safe", "auto"}, // override/hitl are meaningless in Safe
		{secgate.Auto, false, false, "auto", "hitl"},
		{secgate.Auto, false, true, "auto (hitl)", ""},
		{secgate.Auto, true, false, "auto override", "hitl"},
		{secgate.Auto, true, true, "auto (hitl) override", ""},
	}
	for _, tc := range cases {
		got := engageModeSeg(tc.mode, tc.override, tc.hitl)
		if got != tc.want {
			t.Errorf("engageModeSeg(%v,%v,%v) = %q; want %q", tc.mode, tc.override, tc.hitl, got, tc.want)
		}
		if tc.wantAbsent != "" && strings.Contains(got, tc.wantAbsent) {
			t.Errorf("engageModeSeg(%v,%v,%v) = %q; should not contain %q", tc.mode, tc.override, tc.hitl, got, tc.wantAbsent)
		}
	}
}

// The status ribbon carries the autonomy segment: safe by default, auto after
// /auto, with the override and hitl markers. It is a safety indicator, shown in
// both rag and agent lines.
func TestStatusRibbonShowsEngageMode(t *testing.T) {
	noColor(t)
	m := layoutModel(t, 200, 24)
	m.ragModel = "gemma"
	if line := m.statusLine(); !strings.Contains(line, "safe") {
		t.Errorf("Safe default: status %q lacks the safe segment", line)
	}
	if line := m.statusLine(); strings.Contains(line, "auto") {
		t.Errorf("Safe default: status %q must not show auto", line)
	}
	m.engageMode = secgate.Auto
	if line := m.statusLine(); !strings.Contains(line, "auto") || strings.Contains(line, "safe") {
		t.Errorf("Auto: status %q should show auto and not safe", line)
	}
	m.engageOverride = true
	if line := m.statusLine(); !strings.Contains(line, "override") {
		t.Errorf("Auto+override: status %q lacks the override marker", line)
	}
	m.engageOverride = false
	m.engageHITL = true
	if line := m.statusLine(); !strings.Contains(line, "hitl") {
		t.Errorf("Auto+hitl: status %q lacks the hitl marker", line)
	}
	// Agent mode also carries the safety segment.
	m.engageMode, m.engageHITL = secgate.Auto, false
	m.mode, m.agentXport, m.agentChecked = "agent", "gateway", true
	if line := m.statusLine(); !strings.Contains(line, "auto") {
		t.Errorf("agent mode: status %q lacks the autonomy segment", line)
	}
}

// /auto computes the HITL-fallback state from the cwd config (empty bound => HITL);
// /safe clears it.
func TestAutoCommandSetsHITLFromCwd(t *testing.T) {
	t.Chdir(t.TempDir()) // no .blkchain/config.yaml => unattended bound is empty => HITL
	m := newTestModel(t)
	nm, _ := m.dispatchInput("/auto")
	m = nm.(model)
	if !m.engageHITL {
		t.Fatalf("/auto in a config-less cwd should set engageHITL (unattended bound empty)")
	}
	nm, _ = m.dispatchInput("/safe")
	m = nm.(model)
	if m.engageHITL {
		t.Fatalf("/safe should clear engageHITL")
	}
}

// webStatusSegment is shown only when web search is actually in use: a provider
// is available and the switch is on. It names the active provider (ddg for the
// DuckDuckGo fallback).
func TestWebStatusSegment(t *testing.T) {
	cases := []struct {
		provider string
		on       bool
		wantSeg  string
		wantOK   bool
	}{
		{webProviderTavily, true, "web tavily", true},
		{webProviderDuckDuckGo, true, "web ddg", true},
		{webProviderTavily, false, "", false},
		{webProviderDuckDuckGo, false, "", false},
		{webProviderNone, true, "", false},
		{webProviderNone, false, "", false},
	}
	for _, c := range cases {
		seg, ok := webStatusSegment(c.provider, c.on)
		if seg != c.wantSeg || ok != c.wantOK {
			t.Errorf("webStatusSegment(%q,%v) = (%q,%v), want (%q,%v)", c.provider, c.on, seg, ok, c.wantSeg, c.wantOK)
		}
	}
}

// The rag status ribbon carries the active web provider when the switch is on,
// and no web segment when it is off (width-budget discipline).
func TestStatusLineShowsWebProvider(t *testing.T) {
	noColor(t)
	t.Setenv(webFallbackEnv, "")
	t.Setenv(tavilyAPIKeyEnv, "k")
	on := model{mode: "rag", width: 200, servicesChecked: true, servicesOK: true, prefs: modelPrefs{Web: true}}
	if line := on.statusLine(); !strings.Contains(line, "web tavily") {
		t.Errorf("web on, tavily configured: status = %q, want web tavily", line)
	}
	off := model{mode: "rag", width: 200, servicesChecked: true, servicesOK: true, prefs: modelPrefs{Web: false}}
	if line := off.statusLine(); strings.Contains(line, "web tavily") {
		t.Errorf("web switch off: status = %q, want no web segment", line)
	}
}
