package main

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")

func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

type fakeRunner struct {
	out   string
	err   error
	calls int
}

func (f *fakeRunner) Render(_ context.Context, _ string, _ bool) (string, error) {
	f.calls++
	return f.out, f.err
}

func sampleEngagement(rev int64) Engagement {
	return Engagement{Revision: rev, Name: "acme", Tasks: []Task{
		{ID: "t1", Kind: "recon", Objective: "enumerate host", Status: TaskDone},
		{ID: "t2", Kind: "web", Objective: "SQLi on /login", Status: TaskActive, DependsOn: []string{"t1"}},
	}}
}

func TestVizSanitizeBlocksInjection(t *testing.T) {
	bad := "pwn\"]-->x{{evil}}\n%%directive [a] (b) c|d"
	got := vizSanitizeLabel(bad)
	for _, banned := range []string{"\n", "\"", "-->", "%%", "{{", "}}", "[", "]", "(", ")", "|"} {
		if strings.Contains(got, banned) {
			t.Fatalf("sanitized label still contains %q: %q", banned, got)
		}
	}
}

func TestVizMermaidHasNodesAndEdges(t *testing.T) {
	m := vizMermaid(sampleEngagement(1))
	if !strings.Contains(m, "flowchart TD") || !strings.Contains(m, "t1") || !strings.Contains(m, "t2") || !strings.Contains(m, "t1 --> t2") {
		t.Fatalf("mermaid missing nodes/edges: %q", m)
	}
}

func TestVizCacheRerendersOnlyOnRevisionChange(t *testing.T) {
	fr := &fakeRunner{out: "recon: enumerate host\nweb: SQLi on /login"}
	r := newVizRenderer(fr)
	stub := newStubEngagement("acme")
	stub.setSnapshot(sampleEngagement(0)) // becomes rev 1
	ctx := context.Background()
	_, changed, err := r.Block(ctx, stub)
	if err != nil || !changed {
		t.Fatalf("first Block changed=%v err=%v; want true,nil", changed, err)
	}
	_, changed2, _ := r.Block(ctx, stub) // same revision
	if changed2 || fr.calls != 1 {
		t.Fatalf("second Block changed=%v calls=%d; want false,1 (no re-render, no runner call)", changed2, fr.calls)
	}
}

func TestVizFallbackOnRunnerError(t *testing.T) {
	fr := &fakeRunner{err: errors.New("boom")}
	r := newVizRenderer(fr)
	stub := newStubEngagement("acme")
	stub.setSnapshot(sampleEngagement(0))
	block, changed, err := r.Block(context.Background(), stub)
	if err != nil || !changed {
		t.Fatalf("fallback Block should not error: changed=%v err=%v", changed, err)
	}
	if !strings.Contains(stripANSI(block), "recon: enumerate host") || !strings.Contains(stripANSI(block), "renderer unavailable") {
		t.Fatalf("fallback block should list tasks and note unavailability: %q", stripANSI(block))
	}
}

func TestVizMermaidCyclicAndDanglingSafe(t *testing.T) {
	e := Engagement{Revision: 1, Tasks: []Task{
		{ID: "a", Kind: "x", Objective: "a", DependsOn: []string{"b"}},
		{ID: "b", Kind: "x", Objective: "b", DependsOn: []string{"a", "ghost"}},
	}}
	m := vizMermaid(e) // must return, not loop; dangling edge to "ghost" dropped
	if strings.Contains(m, "ghost") {
		t.Fatalf("mermaid referenced a missing node: %q", m)
	}
}

func TestVizMermaidDropsInvalidIDs(t *testing.T) {
	e := Engagement{Revision: 1, Tasks: []Task{
		{ID: "ok1", Kind: "recon", Objective: "fine"},
		{ID: `x["evil"]`, Kind: "x", Objective: "quote"},
		{ID: "a --> b", Kind: "x", Objective: "arrow"},
		{ID: "esc\x1b[31m", Kind: "x", Objective: "escape"},
		{ID: "", Kind: "x", Objective: "empty"},
		{ID: "ok2", Kind: "web", Objective: "child", DependsOn: []string{"ok1", `x["evil"]`, "a --> b"}},
		{ID: "bad id", Kind: "x", Objective: "space", DependsOn: []string{"ok1"}},
	}}
	m := vizMermaid(e)
	for _, banned := range []string{"evil", "a --> b", "\x1b", "quote", "arrow", "escape", "empty", "space", "bad id"} {
		if strings.Contains(m, banned) {
			t.Fatalf("mermaid kept invalid id content %q: %q", banned, m)
		}
	}
	if !strings.Contains(m, "ok1[recon: fine]") || !strings.Contains(m, "ok2[web: child]") || !strings.Contains(m, "ok1 --> ok2") {
		t.Fatalf("valid siblings missing: %q", m)
	}
	if n := strings.Count(m, "-->"); n != 1 {
		t.Fatalf("want exactly one edge, got %d: %q", n, m)
	}
}

func TestVizBlockSanitizesRunnerOutput(t *testing.T) {
	fr := &fakeRunner{out: "recon: enumerate host \x1b]0;pwn\x07\x1b[31mred\x1b[0m"}
	r := newVizRenderer(fr)
	stub := newStubEngagement("acme")
	stub.setSnapshot(sampleEngagement(0))
	block, _, err := r.Block(context.Background(), stub)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(block, "pwn") || strings.Contains(block, "\x07") || strings.Contains(stripANSI(block), "\x1b") {
		t.Fatalf("runner escapes reached the block: %q", block)
	}
}

func vizForceColor(t *testing.T) {
	t.Helper()
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(prev) })
}

func TestVizColorizeStylesEachSpanOnSharedRow(t *testing.T) {
	vizForceColor(t)
	e := Engagement{Tasks: []Task{
		{ID: "a", Kind: "recon", Objective: "scan", Status: TaskActive},
		{ID: "b", Kind: "web", Objective: "SQLi", Status: TaskDone},
	}}
	body := "| recon: scan |   | web: SQLi |\n+-------------+"
	got := vizColorize(body, e)
	want := "| " + vizStatusStyle(TaskActive).Render("recon: scan") + " |   | " +
		vizStatusStyle(TaskDone).Render("web: SQLi") + " |\n+-------------+"
	if got != want {
		t.Fatalf("spans not styled independently:\n got %q\nwant %q", got, want)
	}
	if vizStatusStyle(TaskActive).Render("x") == vizStatusStyle(TaskDone).Render("x") {
		t.Fatal("test needs distinct status styles")
	}
	if stripANSI(got) != body {
		t.Fatalf("colorize changed text: %q", stripANSI(got))
	}
	for i := 0; i < 20; i++ {
		if vizColorize(body, e) != got {
			t.Fatal("colorize output not stable across runs")
		}
	}
}

func TestVizColorizeSubstringLabelDoesNotWin(t *testing.T) {
	vizForceColor(t)
	e := Engagement{Tasks: []Task{
		{ID: "a", Kind: "web", Objective: "", Status: TaskDone},       // label "web:"
		{ID: "b", Kind: "web", Objective: "SQLi", Status: TaskActive}, // label "web: SQLi"
	}}
	body := "| web: SQLi |  | web: |"
	got := vizColorize(body, e)
	want := "| " + vizStatusStyle(TaskActive).Render("web: SQLi") + " |  | " +
		vizStatusStyle(TaskDone).Render("web:") + " |"
	if got != want {
		t.Fatalf("substring pair miscolored:\n got %q\nwant %q", got, want)
	}
	for i := 0; i < 20; i++ {
		if vizColorize(body, e) != got {
			t.Fatal("colorize output not stable across runs")
		}
	}
}

func TestVizCapWriterDropsPastCap(t *testing.T) {
	w := &vizCapWriter{max: 5}
	for _, chunk := range []string{"abc", "defgh", "ij"} {
		n, err := w.Write([]byte(chunk))
		if n != len(chunk) || err != nil {
			t.Fatalf("Write(%q) = %d,%v; want %d,nil", chunk, n, err, len(chunk))
		}
	}
	if got := w.buf.String(); got != "abcde" {
		t.Fatalf("kept %q; want %q", got, "abcde")
	}
}

func TestVizRunnerWithoutBinaryErrors(t *testing.T) {
	if _, err := (&mmdfluxRunner{}).Render(context.Background(), "flowchart TD\n", false); err == nil {
		t.Fatal("empty path should error")
	}
}
