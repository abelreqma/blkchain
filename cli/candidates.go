package main

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	eng "blkchain/cli/internal/engagement"
)

// candidateSourceFallback is the source line shown until structured provenance is
// on the snapshot.
const candidateSourceFallback = "finding evidence"

// isExploitCandidateTask reports whether a task is an unarmed exploit or post-ex
// task: a detection that needs operator arming before it runs. Shared by the
// /candidates list and the DAG marking so they agree on what a candidate is.
func isExploitCandidateTask(t eng.Task) bool {
	return (t.Phase == eng.PhaseExploit || t.Phase == eng.PhasePostEx) && !t.Armed
}

// exploitCandidates returns the unarmed exploit and post-ex tasks (the detections
// that need arming before they run), in snapshot order.
func exploitCandidates(e eng.Engagement) []eng.Task {
	var out []eng.Task
	for _, t := range e.Tasks {
		if isExploitCandidateTask(t) {
			out = append(out, t)
		}
	}
	return out
}

// candidateBasis is the basis provenance line value: the task's basis ids, or a
// dash when it has none.
func candidateBasis(t eng.Task) string {
	if len(t.BasisIDs) == 0 {
		return Glyph(GlyphDash)
	}
	return strings.Join(t.BasisIDs, ", ")
}

// candidateSource renders a candidate's source provenance and whether it is
// untrusted. When the task carries a Citation it shows the structured corpus
// pointer ("kb <source> <section> (<cwe>)", or a "web ..." lead for an untrusted
// web origin); when the Citation is empty it falls back to "finding evidence".
func candidateSource(t eng.Task) (string, bool) {
	c := t.Citation
	if c.Source == "" && c.Path == "" && c.Section == "" && c.CWEClass == "" {
		return candidateSourceFallback, false
	}
	untrusted := c.Origin == "untrusted"
	lead := "kb"
	if untrusted {
		lead = "web"
	}
	parts := []string{lead}
	if c.Source != "" {
		parts = append(parts, c.Source)
	}
	if c.Path != "" && c.Source == "" {
		parts = append(parts, c.Path)
	}
	if c.Section != "" {
		parts = append(parts, c.Section)
	}
	out := strings.Join(parts, " "+Glyph(GlyphSep)+" ")
	if c.CWEClass != "" {
		out += " (" + c.CWEClass + ")"
	}
	return out, untrusted
}

// candidateSourceLine is the muted "source  <provenance>" line, with a rose
// "(untrusted)" tag for a web-origin candidate (the same posture web citations
// carry in /ask answers).
func candidateSourceLine(t eng.Task) string {
	text, untrusted := candidateSource(t)
	line := Meta.Render("source  " + text)
	if untrusted {
		line += " " + Fail.Render("(untrusted)")
	}
	return line
}

// renderCandidates renders the /candidates review block: one entry per detection
// with its label, surface, armed state, basis, and source. An empty list renders
// a clear empty state.
func renderCandidates(cands []eng.Task) string {
	if len(cands) == 0 {
		return "   " + Meta.Render("no exploit candidates yet - recon and correlation surface them first")
	}
	var b strings.Builder
	for i, t := range cands {
		if i > 0 {
			b.WriteString("\n")
		}
		label := vizSanitizeLabel(t.Kind + ": " + t.Objective)
		surface := strings.TrimSpace(string(t.Surface))
		head := Caut.Render(Glyph(GlyphWarn)) + " " + Key.Render(label)
		if surface != "" {
			head += "  " + Meta.Render("surface "+surface+" "+Glyph(GlyphSep)+" unarmed")
		} else {
			head += "  " + Meta.Render("unarmed")
		}
		fmt.Fprintf(&b, "%s\n   %s\n   %s\n",
			head,
			Meta.Render("basis   "+candidateBasis(t)),
			candidateSourceLine(t),
		)
	}
	return strings.TrimRight(b.String(), "\n")
}

// candidateNotice is the one-line detection notice committed to scrollback when a
// new exploit/post-ex candidate first appears: a caution mark, the label, the
// surface, and the source (finding-evidence fallback until structured provenance
// lands). It is plain scrollback text, so the bracketed ascii caution glyph is
// safe here (unlike the mermaid node mark).
func candidateNotice(t eng.Task) string {
	label := vizSanitizeLabel(t.Kind + ": " + t.Objective)
	s := " " + Caut.Render(Glyph(GlyphWarn)) + " " + Meta.Render("candidate ") + Key.Render(label)
	if surface := strings.TrimSpace(string(t.Surface)); surface != "" {
		s += Meta.Render("  surface " + surface)
	}
	text, untrusted := candidateSource(t)
	s += Meta.Render("  " + Glyph(GlyphSep) + " source " + text)
	if untrusted {
		s += " " + Fail.Render("(untrusted)")
	}
	return s
}

// unnoticedCandidates returns the candidates whose ids are not yet in noticed, in
// order, so each detection is announced exactly once across polls.
func unnoticedCandidates(noticed map[string]bool, cands []eng.Task) []eng.Task {
	var out []eng.Task
	for _, t := range cands {
		if !noticed[t.ID] {
			out = append(out, t)
		}
	}
	return out
}

// candidateScanMsg carries the current exploit/post-ex candidates from a poll so
// the base Update can announce the newly-seen ones (the diff + the noticed-set
// mutation happen in Update, never in this command).
type candidateScanMsg struct{ cands []eng.Task }

// candidateScanCmd reads the engagement snapshot off the UI goroutine and returns
// the current candidates. nil-safe: no engagement means no scan.
func (m model) candidateScanCmd() tea.Cmd {
	v := m.engagement
	if v == nil {
		return nil
	}
	return func() tea.Msg {
		e, err := v.Snapshot(context.Background())
		if err != nil {
			return nil
		}
		return candidateScanMsg{cands: exploitCandidates(e)}
	}
}

// candidatesBlock renders the /candidates output from a live engagement view. A
// nil view (no engagement running) and a snapshot error both render a one-line
// note rather than failing the command.
func candidatesBlock(v EngagementView) string {
	if v == nil {
		return "   " + Meta.Render("no engagement running - start one with /engage")
	}
	e, err := v.Snapshot(context.Background())
	if err != nil {
		return styleErr(fmt.Errorf("candidates: %w", err))
	}
	return renderCandidates(exploitCandidates(e))
}
