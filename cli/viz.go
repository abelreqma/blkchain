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

// vizMermaid builds a flowchart TD from the DAG. Edges to unknown ids are
// dropped, and so are tasks whose id is not a plain identifier (an id is
// emitted raw, so it must never carry Mermaid syntax). Node label is
// "kind: objective", sanitized. It only reads e.
func vizMermaid(e Engagement) string {
	known := make(map[string]bool, len(e.Tasks))
	for _, t := range e.Tasks {
		if vizIDRe.MatchString(t.ID) {
			known[t.ID] = true
		}
	}
	var b strings.Builder
	b.WriteString("flowchart TD\n")
	for _, t := range e.Tasks {
		if !known[t.ID] {
			continue
		}
		label := vizSanitizeLabel(t.Kind + ": " + t.Objective)
		fmt.Fprintf(&b, "  %s[%s]\n", t.ID, label)
	}
	for _, t := range e.Tasks {
		if !known[t.ID] {
			continue
		}
		for _, dep := range t.DependsOn {
			if known[dep] {
				fmt.Fprintf(&b, "  %s --> %s\n", dep, t.ID)
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
	body, rerr := r.run.Render(ctx, vizMermaid(e), plCurrentTier() == plASCII)
	body = sanitizeTerminal(body) // renderer output is data: no escapes reach the screen
	var block string
	if rerr != nil || strings.TrimSpace(body) == "" {
		block = vizFallbackList(e)
	} else {
		block = vizFrame(e, vizColorize(body, e))
	}
	r.lastRev, r.lastOut, r.have = rev, block, true
	return block, true, nil
}

func vizStatusStyle(s TaskStatus) lipgloss.Style {
	switch s {
	case TaskDone:
		return lipgloss.NewStyle().Foreground(Success)
	case TaskActive:
		return lipgloss.NewStyle().Foreground(Warn)
	case TaskNA:
		return lipgloss.NewStyle().Foreground(Muted).Strikethrough(true)
	}
	return lipgloss.NewStyle().Foreground(Muted)
}

type vizSpan struct{ start, end, task int }

// vizColorize styles each task's label span by status. Labels are matched
// longest first (ties by task order) so a label that is a substring of another
// does not win, and each match is claimed once so spans never overlap. Only the
// matched span is styled, so boxes sharing a text row keep their own colors.
func vizColorize(body string, e Engagement) string {
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
			b.WriteString(vizStatusStyle(e.Tasks[sp.task].Status).Render(ln[sp.start:sp.end]))
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
func vizFrame(e Engagement, body string) string {
	var done, active, todo, blocked, na int
	for _, t := range e.Tasks {
		switch t.Status {
		case TaskDone:
			done++
		case TaskActive:
			active++
		case TaskBlocked:
			blocked++
		case TaskNA:
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
func vizFallbackList(e Engagement) string {
	var b strings.Builder
	b.WriteString(Meta.Render(fmt.Sprintf("engagement %s rev %d (diagram renderer unavailable)", vizSanitizeLabel(e.Name), e.Revision)))
	b.WriteString("\n")
	for _, t := range e.Tasks {
		mark := Glyph(GlyphBullet)
		fmt.Fprintf(&b, "   %s %s: %s (%s)\n", mark, vizSanitizeLabel(t.Kind), vizSanitizeLabel(t.Objective), t.Status)
	}
	return strings.TrimRight(b.String(), "\n")
}
