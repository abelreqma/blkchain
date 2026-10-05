package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	eng "blkchain/cli/internal/engagement"
	"github.com/charmbracelet/lipgloss"
)

// viz.go turns an engagement snapshot into a Mermaid flowchart, renders it to
// ASCII through mmdflux (an injected runner), caches by revision, colors nodes
// by status, and falls back to a plain list when the renderer is unavailable.

const (
	vizLabelMax   = 48
	vizOutputCap  = 1 << 16 // 64 KiB of mmdflux output
	vizRunTimeout = 5 * time.Second
	vizWaitDelay  = 2 * time.Second // grace after the timeout kill for pipe drain
)

// vizIDRe is the only shape of task id allowed into Mermaid source.
var vizIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

var vizBadMermaid = regexp.MustCompile(`-->|%%|\{\{|\}\}|[\[\]\(\)\{\}"|<>#;]`)

// vizSanitizeLabel makes a task label safe to embed in a Mermaid node. It first
// strips terminal control sequences, collapses whitespace, removes Mermaid
// metacharacters, and caps length.
func vizSanitizeLabel(s string) string {
	s = sanitizeTerminal(s)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	s = vizBadMermaid.ReplaceAllString(s, " ")
	s = strings.Join(strings.Fields(s), " ")
	return ellipsize(s, vizLabelMax)
}

// vizDomainIcons maps domains to diagram icons.
var vizDomainIcons = map[string]string{
	"recon":           "\U0001f50e",
	"web":             "\U0001f310",
	"ad":              "\U0001faaa",
	"cloud":           "\u2601\ufe0f",
	"k8s":             "\u2638\ufe0f",
	"wifi":            "\U0001f4e1",
	"exploit-dev":     "\U0001f41b",
	"generic":         "\U0001f9ed",
	"local":           "\U0001f4bb",
	"target-analysis": "\U0001f52c",
}

// vizCandidateMark is the bracket-free caution glyph that marks an unarmed
// exploit/post-ex candidate node: a warning emoji when unicode is available,
// "!" in the ascii tier. It must stay bracket-free because it is rendered inside
// a mermaid node label ("id[...]").
func vizCandidateMark() string {
	if plCurrentTier() == plASCII {
		return "!"
	}
	return "\u26a0\ufe0f"
}

// vizCoverageGapMark is the bracket-free mark for a coverage-gap node: a detection
// the corpus has no playbook for (non-actionable). It is a stop emoji when
// unicode is available, "x" in the ascii tier, and must stay bracket-free because
// it is rendered inside a mermaid node label. It is distinct from vizCandidateMark
// so a non-actionable gap never reads as an armable candidate.
func vizCoverageGapMark() string {
	if plCurrentTier() == plASCII {
		return "x"
	}
	return "\U0001f6ab"
}

// domainIcon returns the node glyph for a task kind, generic when unknown.
func domainIcon(kind string) string {
	if g, ok := vizDomainIcons[strings.ToLower(strings.TrimSpace(kind))]; ok {
		return g
	}
	return vizDomainIcons["generic"]
}

// vizMermaid builds a flowchart TD from the DAG. Edges to unknown ids are
// dropped, and so are tasks whose id is not a plain identifier (an id is
// emitted raw, so it must never carry Mermaid syntax). Node label is
// "kind: objective", sanitized, with a leading domain glyph in the nerd tier.
// A task's basis ids become dotted edges unless a dependency edge already
// covers the pair. It only reads e.
func vizMermaid(e eng.Engagement) string {
	known := make(map[string]bool, len(e.Tasks))
	for _, t := range e.Tasks {
		if vizIDRe.MatchString(t.ID) {
			known[t.ID] = true
		}
	}
	nerd := plCurrentTier() == plNerd
	var b strings.Builder
	b.WriteString("flowchart TD\n")
	for _, t := range e.Tasks {
		if !known[t.ID] {
			continue
		}
		label := vizSanitizeLabel(t.Kind + ": " + t.Objective)
		if nerd {
			// The glyph is a compiled-in constant, never task data, so it is
			// added after the sanitizer on purpose.
			label = domainIcon(t.Kind) + " " + label
		}
		if isExploitCandidateTask(t) {
			// A compiled-in, bracket-free caution mark on an unarmed exploit/post-ex
			// candidate (it goes inside the mermaid node, so it must never be "[!]").
			label = vizCandidateMark() + " " + label
		} else if t.CoverageGap {
			// A coverage-gap detection is non-actionable: mark it distinctly from an
			// armable candidate (also bracket-free for the mermaid node).
			label = vizCoverageGapMark() + " " + label
		}
		fmt.Fprintf(&b, "  %s[%s]\n", t.ID, label)
	}
	emitted := map[string]bool{}
	for _, t := range e.Tasks {
		if !known[t.ID] {
			continue
		}
		for _, dep := range t.DependsOn {
			if known[dep] {
				fmt.Fprintf(&b, "  %s --> %s\n", dep, t.ID)
				emitted[dep+"\x00"+t.ID] = true
			}
		}
	}
	for _, t := range e.Tasks {
		if !known[t.ID] {
			continue
		}
		for _, basis := range t.BasisIDs {
			if known[basis] && basis != t.ID && !emitted[basis+"\x00"+t.ID] {
				fmt.Fprintf(&b, "  %s -.-> %s\n", basis, t.ID)
				emitted[basis+"\x00"+t.ID] = true
			}
		}
	}
	return b.String()
}

type diagramRunner interface {
	Render(ctx context.Context, mermaid string, ascii bool) (string, error)
}

// mmdfluxRunner shells out to mmdflux (stdin only, no shell, bounded time and
// output). The binary is resolved once at construction.
type mmdfluxRunner struct{ path string }

func newMmdfluxRunner() *mmdfluxRunner {
	path := os.Getenv("BLKCHAIN_MMDFLUX")
	if path == "" {
		if p, err := exec.LookPath("mmdflux"); err == nil {
			path = p
		}
	}
	return &mmdfluxRunner{path: path}
}

// vizCapWriter keeps at most max bytes and silently drops the rest, so a
// runaway child cannot grow memory without bound.
type vizCapWriter struct {
	buf bytes.Buffer
	max int
}

func (w *vizCapWriter) Write(p []byte) (int, error) {
	if room := w.max - w.buf.Len(); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		w.buf.Write(p[:room])
	}
	return len(p), nil
}

func (r *mmdfluxRunner) Render(ctx context.Context, mermaid string, ascii bool) (string, error) {
	if r.path == "" {
		return "", fmt.Errorf("mmdflux not found")
	}
	ctx, cancel := context.WithTimeout(ctx, vizRunTimeout)
	defer cancel()
	format := "text"
	if ascii {
		format = "ascii"
	}
	cmd := exec.CommandContext(ctx, r.path, "-f", format, "--color", "off")
	cmd.WaitDelay = vizWaitDelay
	cmd.Stdin = strings.NewReader(mermaid)
	out := &vizCapWriter{max: vizOutputCap}
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.buf.String(), nil
}

// vizRenderer holds a runner and the last (revision, block) rendered.
type vizRenderer struct {
	run     diagramRunner
	lastRev int64
	lastOut string
	have    bool
}

func newVizRenderer(run diagramRunner) *vizRenderer { return &vizRenderer{run: run} }

// Block returns the committed DAG block for the current revision. changed is
// true only when the revision advanced (or on first call); when false the
// cached block is returned and the runner is not called. A transient runner
// failure (for example a timeout) is cached as the fallback for that revision
// and only retried when the revision changes.
func (r *vizRenderer) Block(ctx context.Context, v EngagementView) (string, bool, error) {
	rev, err := v.Revision(ctx)
	if err != nil {
		return "", false, err
	}
	if r.have && rev == r.lastRev {
		return r.lastOut, false, nil
	}
	e, err := v.Snapshot(ctx)
	if err != nil {
		return "", false, err
	}
	block := r.blockFor(ctx, e)
	r.lastRev, r.lastOut, r.have = rev, block, true
	return block, true, nil
}

// blockFor renders one snapshot to a framed DAG block, or the plain list when
// the renderer fails or returns nothing. It does no caching and no polling.
func (r *vizRenderer) blockFor(ctx context.Context, e eng.Engagement) string {
	body, rerr := r.run.Render(ctx, vizMermaid(e), plCurrentTier() == plASCII)
	body = sanitizeTerminal(body) // renderer output is data: no escapes reach the screen
	if rerr != nil || strings.TrimSpace(body) == "" {
		return vizFallbackList(e)
	}
	return vizFrame(e, vizColorize(body, e))
}

func vizStatusStyle(s eng.Status) lipgloss.Style {
	switch s {
	case eng.StatusDone:
		return lipgloss.NewStyle().Foreground(Success)
	case eng.StatusActive:
		return lipgloss.NewStyle().Foreground(Warn)
	case eng.StatusNA:
		return lipgloss.NewStyle().Foreground(Muted).Strikethrough(true)
	}
	return lipgloss.NewStyle().Foreground(Muted)
}

type vizSpan struct{ start, end, task int }

func vizTaskStyle(t eng.Task) lipgloss.Style {
	if isExploitCandidateTask(t) {
		return lipgloss.NewStyle().Foreground(Warn)
	}
	if t.CoverageGap {
		return lipgloss.NewStyle().Foreground(Err)
	}
	return vizStatusStyle(t.Status)
}

func vizColorize(body string, e eng.Engagement) string {
	labels := make([]string, len(e.Tasks))
	order := make([]int, 0, len(e.Tasks))
	seen := map[string]bool{}
	for i, t := range e.Tasks {
		labels[i] = vizSanitizeLabel(t.Kind + ": " + t.Objective)
		if labels[i] == "" || seen[labels[i]] {
			continue
		}
		seen[labels[i]] = true
		order = append(order, i)
	}
	sort.SliceStable(order, func(a, b int) bool {
		return len(labels[order[a]]) > len(labels[order[b]])
	})
	lines := strings.Split(body, "\n")
	for li, ln := range lines {
		var spans []vizSpan
		for _, ti := range order {
			label := labels[ti]
			for from := 0; from < len(ln); {
				k := strings.Index(ln[from:], label)
				if k < 0 {
					break
				}
				sp := vizSpan{from + k, from + k + len(label), ti}
				if !vizOverlaps(spans, sp) {
					spans = append(spans, sp)
					break
				}
				from = sp.start + 1
			}
		}
		if len(spans) == 0 {
			continue
		}
		sort.Slice(spans, func(a, b int) bool { return spans[a].start < spans[b].start })
		var b strings.Builder
		pos := 0
		for _, sp := range spans {
			b.WriteString(ln[pos:sp.start])
			b.WriteString(vizTaskStyle(e.Tasks[sp.task]).Render(ln[sp.start:sp.end]))
			pos = sp.end
		}
		b.WriteString(ln[pos:])
		lines[li] = b.String()
	}
	return strings.Join(lines, "\n")
}

func vizOverlaps(spans []vizSpan, s vizSpan) bool {
	for _, o := range spans {
		if s.start < o.end && o.start < s.end {
			return true
		}
	}
	return false
}

// vizFrame wraps the body in a header and a status caption ribbon.
func vizFrame(e eng.Engagement, body string) string {
	var done, active, todo, blocked, na, cand, gap int
	for _, t := range e.Tasks {
		if t.CoverageGap {
			// Counted as a coverage gap, not as blocked (its status is blocked).
			gap++
			continue
		}
		if isExploitCandidateTask(t) {
			cand++
		}
		switch t.Status {
		case eng.StatusDone:
			done++
		case eng.StatusActive:
			active++
		case eng.StatusBlocked:
			blocked++
		case eng.StatusNA:
			na++
		default:
			todo++
		}
	}
	header := Meta.Render(fmt.Sprintf("engagement %s rev %d", vizSanitizeLabel(e.Name), e.Revision))
	segs := []plSegment{
		{Text: fmt.Sprintf("%d done", done), FG: Success},
		{Text: fmt.Sprintf("%d active", active), FG: Warn},
		{Text: fmt.Sprintf("%d todo", todo), FG: Muted},
	}
	if cand > 0 {
		// A caution count of the unarmed exploit/post-ex detections awaiting arming.
		segs = append(segs, plSegment{Text: fmt.Sprintf("%d candidates", cand), FG: Warn})
	}
	if gap > 0 {
		// Non-actionable coverage gaps: detected, no corpus playbook.
		segs = append(segs, plSegment{Text: fmt.Sprintf("%d coverage-gap", gap), FG: Err})
	}
	if blocked > 0 {
		segs = append(segs, plSegment{Text: fmt.Sprintf("%d blocked", blocked), FG: Err})
	}
	if na > 0 {
		segs = append(segs, plSegment{Text: fmt.Sprintf("%d na", na), FG: Muted})
	}
	caption := plRenderRibbon(segs, nil, plCurrentTier(), 0)
	return header + "\n" + body + "\n" + caption
}

// vizFallbackList renders a plain indented task list when mmdflux is absent or
// failed.
func vizFallbackList(e eng.Engagement) string {
	var b strings.Builder
	b.WriteString(Meta.Render(fmt.Sprintf("engagement %s rev %d (diagram renderer unavailable)", vizSanitizeLabel(e.Name), e.Revision)))
	b.WriteString("\n")
	for _, t := range e.Tasks {
		mark := Glyph(GlyphBullet)
		fmt.Fprintf(&b, "   %s %s: %s (%s)\n", mark, vizSanitizeLabel(t.Kind), vizSanitizeLabel(t.Objective), t.Status)
	}
	return strings.TrimRight(b.String(), "\n")
}
