package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// newTestModel builds a minimal model for exercising submit/queue logic without a
// TTY. History is redirected to a temp dir so tests never touch the real store.
func newTestModel(t *testing.T) model {
	t.Helper()
	isolateUserDirs(t)
	return model{ta: textarea.New()}
}

func TestQueueWhileBusyFIFO(t *testing.T) {
	m := newTestModel(t)
	m.working = true

	m.ta.SetValue("first question")
	nm, _ := m.submit()
	m = nm.(model)
	if len(m.queue) != 1 || m.queue[0] != "first question" {
		t.Fatalf("after first submit queue = %v, want [first question]", m.queue)
	}

	m.ta.SetValue("second question")
	nm, _ = m.submit()
	m = nm.(model)
	if len(m.queue) != 2 || m.queue[1] != "second question" {
		t.Fatalf("after second submit queue = %v, want [.. second question]", m.queue)
	}

	// A non-turn slash command runs immediately instead of queuing.
	m.ta.SetValue("/rag")
	nm, _ = m.submit()
	m = nm.(model)
	if len(m.queue) != 2 {
		t.Errorf("slash command should not queue; queue = %v", m.queue)
	}
}

func TestClearQueue(t *testing.T) {
	m := newTestModel(t)
	m.queue = []string{"a", "b", "c"}
	nm, _ := m.clearQueue()
	m = nm.(model)
	if len(m.queue) != 0 {
		t.Errorf("clearQueue left %d items", len(m.queue))
	}
}

func TestDequeueFIFO(t *testing.T) {
	m := newTestModel(t)
	m.queue = []string{"alpha", "beta"}
	nm, _ := m.Update(dequeueMsg{})
	m = nm.(model)
	if len(m.queue) != 1 || m.queue[0] != "beta" {
		t.Fatalf("after dequeue queue = %v, want [beta]", m.queue)
	}
	if !m.working {
		t.Error("dequeue of a plain question should start a turn (working=true)")
	}
}

func TestDecideCtrlC(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * time.Second)
	recent := now.Add(-200 * time.Millisecond)

	cases := []struct {
		name       string
		last       time.Time
		working    bool
		draftEmpty bool
		want       ctrlCAction
	}{
		{"first press while working cancels", old, true, true, ccCancel},
		{"first press idle nonempty clears", old, false, false, ccClear},
		{"first press idle empty hints", old, false, true, ccHint},
		{"zero last idle empty hints", time.Time{}, false, true, ccHint},
		{"second press idle empty quits", recent, false, true, ccQuit},
		{"second press within window quits", recent, false, false, ccQuit},
		{"second press quits even while working", recent, true, true, ccQuit},
	}
	for _, tc := range cases {
		if got := decideCtrlC(now, tc.last, tc.working, tc.draftEmpty); got != tc.want {
			t.Errorf("%s: decideCtrlC = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestEditorArgv(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")
	if got := editorArgv(); len(got) != 1 || got[0] != "vi" {
		t.Errorf("no env editor should fall back to [vi], got %v", got)
	}
	t.Setenv("EDITOR", "code --wait")
	if got := editorArgv(); len(got) != 2 || got[0] != "code" || got[1] != "--wait" {
		t.Errorf("EDITOR should split into argv, got %v", got)
	}
	t.Setenv("VISUAL", "nvim")
	if got := editorArgv(); got[0] != "nvim" {
		t.Errorf("VISUAL should win over EDITOR, got %v", got)
	}
}

func TestReverseSearchMatch(t *testing.T) {
	hist := []string{"how to tune hnsw", "what is ssrf", "tune the index"}

	if m, _ := reverseSearchMatch(hist, "", 0); m != "" {
		t.Errorf("empty query should match nothing, got %q", m)
	}
	m, count := reverseSearchMatch(hist, "tune", 0)
	if m != "tune the index" || count != 2 {
		t.Errorf("newest 'tune' match = %q (count %d), want 'tune the index' (2)", m, count)
	}
	// Cycling reaches the older match, then wraps.
	if m, _ := reverseSearchMatch(hist, "tune", 1); m != "how to tune hnsw" {
		t.Errorf("cycle 1 = %q, want 'how to tune hnsw'", m)
	}
	if m, _ := reverseSearchMatch(hist, "tune", 2); m != "tune the index" {
		t.Errorf("cycle 2 should wrap to newest, got %q", m)
	}
	if m, _ := reverseSearchMatch(hist, "zzz", 0); m != "" {
		t.Errorf("no match should return empty, got %q", m)
	}
}

// The reverse-search prompt never exceeds the terminal width. The label
// shrinks or goes before the query is cut, and the match tail is what gets
// the ASCII ellipsis.
func TestReverseSearchViewFitsEveryWidth(t *testing.T) {
	long := strings.Repeat("payload ", 40)
	states := map[string]reverseSearch{
		"match with hint": {open: true, query: "ssrf", match: long, count: 3},
		"single match":    {open: true, query: "ssrf", match: long, count: 1},
		"long query":      {open: true, query: strings.Repeat("q", 90), match: long, count: 2},
		"empty":           {open: true},
		"no match":        {open: true, query: "zz"},
	}
	for name, rs := range states {
		for w := 20; w <= 120; w++ {
			m := layoutModel(t, w, 24)
			m.rsearch = rs
			view := m.reverseSearchView()
			if strings.Contains(view, "\n") || lipgloss.Width(view) > w {
				t.Fatalf("%s width %d: prompt is %d columns: %q", name, w, lipgloss.Width(view), view)
			}
			if rs.query == "ssrf" && !strings.Contains(view, "`ssrf'") {
				t.Errorf("%s width %d: the query was cut: %q", name, w, view)
			}
		}
	}
}

func TestReverseSearchViewShrinksLabelThenTail(t *testing.T) {
	m := layoutModel(t, 80, 24)
	m.rsearch = reverseSearch{open: true, query: "ssrf", match: "what is ssrf", count: 2}
	if v := m.reverseSearchView(); !strings.Contains(v, "(reverse-i-search)") || !strings.Contains(v, "what is ssrf") || !strings.Contains(v, "(ctrl+r for next)") {
		t.Errorf("a roomy prompt keeps everything: %q", v)
	}

	m.rsearch.match = strings.Repeat("long match ", 20)
	m = layoutModelWidth(t, m, 50)
	v := m.reverseSearchView()
	if !strings.Contains(v, "(reverse-i-search)") || !strings.Contains(v, "`ssrf'") || !strings.HasSuffix(v, "...") {
		t.Errorf("width 50 should keep label and query and cut the match with an ASCII ellipsis: %q", v)
	}
	if strings.Contains(v, "ctrl+r for next") {
		t.Errorf("the hint goes before the match is cut: %q", v)
	}

	m = layoutModelWidth(t, m, 26)
	v = m.reverseSearchView()
	if strings.Contains(v, "(reverse-i-search)") || !strings.Contains(v, "`ssrf'") {
		t.Errorf("width 26 should shorten the label and keep the query: %q", v)
	}

	m = layoutModelWidth(t, m, 20)
	v = m.reverseSearchView()
	if strings.Contains(v, "i-search") || !strings.Contains(v, "`ssrf'") {
		t.Errorf("width 20 should drop the label and keep the query: %q", v)
	}
}

func TestReverseSearchViewSanitizesMatchAndQuery(t *testing.T) {
	m := layoutModel(t, 80, 24)
	m.rsearch = reverseSearch{open: true, query: "a\x1b]0;q-title\x07b", match: "hit \x1b]0;evil\x07tail\nsecond line", count: 1}
	v := m.reverseSearchView()
	if strings.ContainsAny(v, "\x1b\x07\n") || strings.Contains(v, "evil") || strings.Contains(v, "q-title") {
		t.Errorf("control sequences reached the prompt: %q", v)
	}
	if !strings.Contains(v, "hit") || !strings.Contains(v, "tail") {
		t.Errorf("printable match text was lost: %q", v)
	}
}

// layoutModelWidth resizes m to w columns through Update, keeping its state.
func layoutModelWidth(t *testing.T, m model, w int) model {
	t.Helper()
	nm, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: 24})
	return nm.(model)
}

func TestReadAttachmentSizeBound(t *testing.T) {
	dir := t.TempDir()

	ok := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(ok, []byte("hello context"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := readAttachment(ok); err != nil || got != "hello context" {
		t.Errorf("readAttachment(small) = (%q, %v)", got, err)
	}

	big := filepath.Join(dir, "big.txt")
	if err := os.WriteFile(big, make([]byte, maxAttachBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAttachment(big); err == nil {
		t.Error("readAttachment should refuse a file over the size cap")
	}

	if _, err := readAttachment(dir); err == nil {
		t.Error("readAttachment should refuse a directory")
	}
}

func TestLoadInitContext(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	if _, ok := loadInitContext(); ok {
		t.Error("loadInitContext should report false when .blk/context.md is absent")
	}

	if err := os.MkdirAll(".blk", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(".blk", "context.md"), []byte("  project rules  "), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := loadInitContext()
	if !ok || got != "project rules" {
		t.Errorf("loadInitContext = (%q, %v), want ('project rules', true)", got, ok)
	}
}

func TestCostFooter(t *testing.T) {
	elapsedOnly := costFooter(turnCost{elapsed: 1500 * time.Millisecond})
	if strings.Contains(elapsedOnly, "tokens") {
		t.Errorf("cost footer without tokens should omit 'tokens': %q", elapsedOnly)
	}
	withTokens := costFooter(turnCost{elapsed: time.Second, completionTokens: 42, hasTokens: true})
	if !strings.Contains(withTokens, "42 tokens") {
		t.Errorf("cost footer should show token count: %q", withTokens)
	}
}

func TestBuildContextPreface(t *testing.T) {
	m := model{
		ambient:     "be terse",
		attachments: []attachment{{path: "/tmp/notes.md", content: "meeting notes"}},
	}
	got := m.buildContextPreface()
	if !strings.Contains(got, "be terse") || !strings.Contains(got, "meeting notes") || !strings.Contains(got, "notes.md") {
		t.Errorf("preface missing ambient/attachment content: %q", got)
	}
	if (model{}).buildContextPreface() != "" {
		t.Error("empty model should build an empty preface")
	}
}
