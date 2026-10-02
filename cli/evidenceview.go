package main

import (
	"context"
	"fmt"
	"strings"
)

// evidenceview.go is the REPL /evidence view: the verified evidence the current
// engagement has captured, read on demand via the bounded accessor (EngageEvidence
// in engageevidence.go). Evidence is not on the polled Snapshot, so
// this is a point-in-time read, useful while an engagement runs (the source is
// registered for the engagement's lifetime). The exploitSummary receipt rides the
// engage done output (formatEngageDone); the full evidence record is written to the
// report (the report footer names the files).
//
// Every stored quote is verified by construction (the model cannot register an
// unverified quote), so the view does not repeat a per-row "verified"
// tag; it heads the block once. Quotes are captured tool output, so each is
// sanitized before display.

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
