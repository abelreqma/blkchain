package main

import (
	"context"
	"fmt"
	"strings"
)

// evidenceBlock renders /evidence for a live engagement view: each task that has
// evidence, with its verified quotes. A nil view means no engagement; a view with
// no evidence on any task (including after the engagement ended and the source was
// cleared) says so and points at the report.
func evidenceBlock(v EngagementView) string {
	if v == nil {
		return "   " + Meta.Render("no engagement running - start one with /engage")
	}
	e, err := v.Snapshot(context.Background())
	if err != nil {
		return styleErr(fmt.Errorf("evidence: %w", err))
	}
	var b strings.Builder
	capped := false
	for _, t := range e.Tasks {
		rows, c := EngageEvidence(t.ID)
		if len(rows) == 0 {
			continue
		}
		capped = capped || c
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(Key.Render(vizSanitizeLabel(t.Kind+": "+t.Objective)) + "\n")
		for _, r := range rows {
			b.WriteString(evidenceRowLine(r))
		}
	}
	if b.Len() == 0 {
		return "   " + Meta.Render("no evidence recorded yet (a finished engagement's full record is in the report)")
	}
	head := " " + OK.Render(Glyph(GlyphOK)) + " " + Meta.Render("evidence (verified)")
	if capped {
		head += Meta.Render("  (capped)")
	}
	return head + "\n" + strings.TrimRight(b.String(), "\n")
}

// evidenceRowLine renders one evidence row: an E<id> marker and the sanitized
// quote, with multi-line quotes indented under the marker and a truncation note.
func evidenceRowLine(r evidenceRow) string {
	quote := strings.ReplaceAll(sanitizeTerminal(r.Quote), "\n", "\n     ")
	marker := ""
	if r.Truncated {
		marker = Meta.Render(" (truncated)")
	}
	return fmt.Sprintf("   %s  %s%s\n", Meta.Render(fmt.Sprintf("E%d", r.ID)), Body.Render(quote), marker)
}
