package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/client"

	"github.com/charmbracelet/bubbles/textarea"
)

// newTestModel builds a minimal model for exercising submit/queue logic without a
// TTY. History is redirected to a temp dir so tests never touch the real store.
func newTestModel(t *testing.T) model {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	return model{ta: textarea.New(), client: client.NewClient()}
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
		{"first press idle empty quits", old, false, true, ccQuit},
		{"zero last idle empty quits", time.Time{}, false, true, ccQuit},
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
