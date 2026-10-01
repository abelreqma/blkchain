package main

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	eng "blkchain/cli/internal/engagement"
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

func sampleEngagement(rev int64) eng.Engagement {
	return eng.Engagement{Revision: rev, Name: "acme", Tasks: []eng.Task{
		{ID: "t1", Kind: "recon", Objective: "enumerate host", Status: eng.StatusDone},
		{ID: "t2", Kind: "web", Objective: "SQLi on /login", Status: eng.StatusActive, DependsOn: []string{"t1"}},
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
	e := eng.Engagement{Revision: 1, Tasks: []eng.Task{
		{ID: "a", Kind: "x", Objective: "a", DependsOn: []string{"b"}},
		{ID: "b", Kind: "x", Objective: "b", DependsOn: []string{"a", "ghost"}},
	}}
	m := vizMermaid(e) // must return, not loop; dangling edge to "ghost" dropped
	if strings.Contains(m, "ghost") {
		t.Fatalf("mermaid referenced a missing node: %q", m)
	}
}

func TestVizMermaidDropsInvalidIDs(t *testing.T) {
	e := eng.Engagement{Revision: 1, Tasks: []eng.Task{
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
	e := eng.Engagement{Tasks: []eng.Task{
		{ID: "a", Kind: "recon", Objective: "scan", Status: eng.StatusActive},
		{ID: "b", Kind: "web", Objective: "SQLi", Status: eng.StatusDone},
	}}
	body := "| recon: scan |   | web: SQLi |\n+-------------+"
	got := vizColorize(body, e)
	want := "| " + vizStatusStyle(eng.StatusActive).Render("recon: scan") + " |   | " +
		vizStatusStyle(eng.StatusDone).Render("web: SQLi") + " |\n+-------------+"
	if got != want {
		t.Fatalf("spans not styled independently:\n got %q\nwant %q", got, want)
	}
	if vizStatusStyle(eng.StatusActive).Render("x") == vizStatusStyle(eng.StatusDone).Render("x") {
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
	e := eng.Engagement{Tasks: []eng.Task{
		{ID: "a", Kind: "web", Objective: "", Status: eng.StatusDone},       // label "web:"
		{ID: "b", Kind: "web", Objective: "SQLi", Status: eng.StatusActive}, // label "web: SQLi"
	}}
	body := "| web: SQLi |  | web: |"
	got := vizColorize(body, e)
	want := "| " + vizStatusStyle(eng.StatusActive).Render("web: SQLi") + " |  | " +
		vizStatusStyle(eng.StatusDone).Render("web:") + " |"
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

// vizForceTier sets the package color/unicode globals so plCurrentTier returns
// the wanted tier, and restores them afterward.
func vizForceTier(t *testing.T, tier plTier) {
	t.Helper()
	prevColor, prevUnicode := useColor, useUnicode
	t.Cleanup(func() { useColor, useUnicode = prevColor, prevUnicode })
	t.Setenv("BLKCHAIN_POWERLINE", "")
	if tier == plUnicode {
		t.Setenv("BLKCHAIN_POWERLINE", "0")
	}
	useColor, useUnicode = tier != plASCII, tier != plASCII
	if got := plCurrentTier(); got != tier {
		t.Fatalf("tier = %v; want %v", got, tier)
	}
}

func vizNodeLine(t *testing.T, mermaid, id string) string {
	t.Helper()
	for _, ln := range strings.Split(mermaid, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), id+"[") {
			return ln
		}
	}
	t.Fatalf("no node line for %q in %q", id, mermaid)
	return ""
}

func basisEngagement(tasks ...eng.Task) eng.Engagement {
	return eng.Engagement{Revision: 1, Name: "acme", Tasks: tasks}
}

func TestVizMermaidBasisEdgeEmitted(t *testing.T) {
	m := vizMermaid(basisEngagement(
		eng.Task{ID: "t1", Kind: "recon", Objective: "scan"},
		eng.Task{ID: "t2", Kind: "web", Objective: "probe", BasisIDs: []string{"t1"}},
	))
	if !strings.Contains(m, "t1 -.-> t2") {
		t.Fatalf("missing basis edge: %q", m)
	}
}

func TestVizMermaidBasisDedupsAgainstDependsOn(t *testing.T) {
	m := vizMermaid(basisEngagement(
		eng.Task{ID: "t1", Kind: "recon", Objective: "scan"},
		eng.Task{ID: "t2", Kind: "web", Objective: "probe", DependsOn: []string{"t1"}, BasisIDs: []string{"t1"}},
	))
	if strings.Count(m, "t1 --> t2") != 1 {
		t.Fatalf("want exactly one solid edge: %q", m)
	}
	if strings.Contains(m, "-.->") {
		t.Fatalf("dotted edge duplicates a dep edge: %q", m)
	}
}

func TestVizMermaidBasisUnknownAndSelfDropped(t *testing.T) {
	m := vizMermaid(basisEngagement(
		eng.Task{ID: "t1", Kind: "recon", Objective: "scan", BasisIDs: []string{"t1"}},
		eng.Task{ID: "t2", Kind: "web", Objective: "probe", BasisIDs: []string{"nope", "bad id\n-->x"}},
	))
	if strings.Contains(m, "-.->") {
		t.Fatalf("unknown or self basis produced an edge: %q", m)
	}
}

func TestVizMermaidDomainIconNerdTier(t *testing.T) {
	vizForceTier(t, plNerd)
	m := vizMermaid(basisEngagement(
		eng.Task{ID: "a", Kind: "recon", Objective: "scan"},
		eng.Task{ID: "b", Kind: " Web ", Objective: "probe"},
		eng.Task{ID: "c", Kind: "mystery", Objective: "x"},
		eng.Task{ID: "d", Kind: "local", Objective: "privesc"},
		eng.Task{ID: "e", Kind: "target-analysis", Objective: "parse"},
	))
	for id, glyph := range map[string]string{"a": "\U000F2B10", "b": "\U000F2B11", "c": "\U000F2B17", "d": "\U000F2B18", "e": "\U000F2B19"} {
		if ln := vizNodeLine(t, m, id); !strings.Contains(ln, "["+glyph+" ") {
			t.Fatalf("node %s missing glyph %U: %q", id, []rune(glyph)[0], ln)
		}
	}
}

func TestVizMermaidDomainIconAbsentOutsideNerd(t *testing.T) {
	for _, tier := range []plTier{plASCII, plUnicode} {
		vizForceTier(t, tier)
		m := vizMermaid(basisEngagement(
			eng.Task{ID: "a", Kind: "recon", Objective: "scan"},
			eng.Task{ID: "b", Kind: "web", Objective: "probe"},
		))
		for _, r := range m {
			if r >= 0xF2B00 && r <= 0xF2BFF {
				t.Fatalf("tier %v leaked glyph %U: %q", tier, r, m)
			}
		}
		if ln := vizNodeLine(t, m, "a"); !strings.Contains(ln, "[recon: scan]") {
			t.Fatalf("tier %v label not plain: %q", tier, ln)
		}
	}
}

func TestVizMultipleActiveNodesStyledWarn(t *testing.T) {
	vizForceColor(t)
	vizForceTier(t, plNerd)
	e := basisEngagement(
		eng.Task{ID: "a", Kind: "recon", Objective: "scan", Status: eng.StatusActive},
		eng.Task{ID: "b", Kind: "web", Objective: "SQLi", Status: eng.StatusActive},
	)
	m := vizMermaid(e)
	if !strings.Contains(m, "a[") || !strings.Contains(m, "b[") {
		t.Fatalf("both active nodes must render: %q", m)
	}
	fr := &fakeRunner{out: "| \U000F2B10 recon: scan |   | \U000F2B11 web: SQLi |"}
	block := newVizRenderer(fr).blockFor(context.Background(), e)
	for _, label := range []string{"recon: scan", "web: SQLi"} {
		if !strings.Contains(block, vizStatusStyle(eng.StatusActive).Render(label)) {
			t.Fatalf("%q not styled Warn: %q", label, block)
		}
	}
}

// Unarmed exploit/post-ex tasks are candidates: vizMermaid marks their node with
// a bracket-free caution glyph (triangle in unicode tiers, "!" in ascii), and only
// them.
func TestVizMermaidMarksExploitCandidates(t *testing.T) {
	vizForceTier(t, plNerd)
	m := vizMermaid(basisEngagement(
		eng.Task{ID: "a", Kind: "recon", Objective: "scan", Phase: eng.PhaseRecon},
		eng.Task{ID: "b", Kind: "web", Objective: "SQLi", Phase: eng.PhaseExploit},
		eng.Task{ID: "c", Kind: "web", Objective: "armed", Phase: eng.PhaseExploit, Armed: true},
		eng.Task{ID: "d", Kind: "local", Objective: "privesc", Phase: eng.PhasePostEx},
	))
	if ln := vizNodeLine(t, m, "b"); !strings.Contains(ln, "▲") {
		t.Fatalf("unarmed exploit node b should carry the caution mark: %q", ln)
	}
	if ln := vizNodeLine(t, m, "d"); !strings.Contains(ln, "▲") {
		t.Fatalf("unarmed post-ex node d should carry the caution mark: %q", ln)
	}
	if ln := vizNodeLine(t, m, "a"); strings.Contains(ln, "▲") {
		t.Fatalf("recon node a must not be marked: %q", ln)
	}
	if ln := vizNodeLine(t, m, "c"); strings.Contains(ln, "▲") {
		t.Fatalf("armed exploit node c must not be marked a candidate: %q", ln)
	}
}

// In the ascii tier the candidate mark is a bracket-free "!" (not "[!]", which
// would break the mermaid node), and never the unicode triangle.
func TestVizMermaidCandidateMarkAsciiTier(t *testing.T) {
	vizForceTier(t, plASCII)
	m := vizMermaid(basisEngagement(
		eng.Task{ID: "b", Kind: "web", Objective: "SQLi", Phase: eng.PhaseExploit},
	))
	ln := vizNodeLine(t, m, "b")
	if strings.Contains(m, "▲") {
		t.Fatalf("ascii tier must not use the triangle: %q", m)
	}
	if strings.Contains(ln, "[!]") {
		t.Fatalf("ascii candidate mark must be bracket-free, not [!]: %q", ln)
	}
	if !strings.Contains(ln, "! web: SQLi") {
		t.Fatalf("ascii candidate node should read '! web: SQLi': %q", ln)
	}
}

// The frame caption counts the unarmed exploit/post-ex candidates.
func TestVizFrameCountsCandidates(t *testing.T) {
	noColor(t)
	fr := vizFrame(basisEngagement(
		eng.Task{ID: "a", Kind: "recon", Objective: "scan", Phase: eng.PhaseRecon, Status: eng.StatusDone},
		eng.Task{ID: "b", Kind: "web", Objective: "SQLi", Phase: eng.PhaseExploit},
		eng.Task{ID: "c", Kind: "local", Objective: "privesc", Phase: eng.PhasePostEx},
	), "body")
	if !strings.Contains(fr, "2 candidates") {
		t.Fatalf("caption should count 2 unarmed exploit/post-ex candidates: %q", fr)
	}
}

func TestVizColorizeCandidateIsCaution(t *testing.T) {
	vizForceColor(t)
	vizForceTier(t, plNerd)
	e := basisEngagement(eng.Task{ID: "b", Kind: "web", Objective: "SQLi", Phase: eng.PhaseExploit, Status: eng.StatusTodo})
	fr := &fakeRunner{out: "| \U000F2B11 web: SQLi |"}
	block := newVizRenderer(fr).blockFor(context.Background(), e)
	want := lipgloss.NewStyle().Foreground(Warn).Render("web: SQLi")
	if !strings.Contains(block, want) {
		t.Fatalf("unarmed exploit candidate label should be caution(Warn)-styled, not muted: %q", block)
	}
}

// A coverage-gap task is marked distinctly in the DAG (not the actionable-candidate
// caution mark), styled rose, and counted separately from candidates and blocked.
func TestVizMermaidMarksCoverageGapDistinctly(t *testing.T) {
	vizForceTier(t, plNerd)
	m := vizMermaid(basisEngagement(
		eng.Task{ID: "b", Kind: "web", Objective: "SQLi", Phase: eng.PhaseExploit},
		eng.Task{ID: "g", Kind: "ai-security", Objective: "pi", Phase: eng.PhaseExploit, CoverageGap: true, Status: eng.StatusBlocked},
	))
	gl := vizNodeLine(t, m, "g")
	if !strings.Contains(gl, "\u2205") {
		t.Errorf("coverage-gap node should carry the gap mark: %q", gl)
	}
	if strings.Contains(gl, "\u25B2") {
		t.Errorf("coverage-gap node must not carry the candidate caution mark: %q", gl)
	}
	if bl := vizNodeLine(t, m, "b"); strings.Contains(bl, "\u2205") {
		t.Errorf("an actionable candidate must not carry the gap mark: %q", bl)
	}
}

func TestVizMermaidCoverageGapMarkAsciiTier(t *testing.T) {
	vizForceTier(t, plASCII)
	m := vizMermaid(basisEngagement(
		eng.Task{ID: "g", Kind: "ai-security", Objective: "pi", Phase: eng.PhaseExploit, CoverageGap: true, Status: eng.StatusBlocked},
	))
	if strings.Contains(m, "\u2205") {
		t.Errorf("ascii tier must not use the unicode gap glyph: %q", m)
	}
	if gl := vizNodeLine(t, m, "g"); !strings.Contains(gl, "x ") {
		t.Errorf("ascii gap mark should be 'x': %q", gl)
	}
}

func TestVizFrameCountsCoverageGapSeparately(t *testing.T) {
	noColor(t)
	fr := vizFrame(basisEngagement(
		eng.Task{ID: "b", Kind: "web", Objective: "SQLi", Phase: eng.PhaseExploit},
		eng.Task{ID: "g", Kind: "ai-security", Objective: "pi", Phase: eng.PhaseExploit, CoverageGap: true, Status: eng.StatusBlocked},
		eng.Task{ID: "x", Kind: "cloud", Objective: "enum", Phase: eng.PhaseRecon, Status: eng.StatusBlocked},
	), "body")
	for _, w := range []string{"1 candidates", "1 coverage-gap", "1 blocked"} {
		if !strings.Contains(fr, w) {
			t.Errorf("caption missing %q: %q", w, fr)
		}
	}
}

func TestVizTaskStyleCoverageGapIsErr(t *testing.T) {
	gap := eng.Task{ID: "g", Phase: eng.PhaseExploit, CoverageGap: true, Status: eng.StatusBlocked}
	got := vizTaskStyle(gap).GetForeground()
	want := lipgloss.NewStyle().Foreground(Err).GetForeground()
	if got != want {
		t.Errorf("coverage-gap node style = %v, want Err(rose)", got)
	}
}
