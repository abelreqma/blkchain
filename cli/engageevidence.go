package main

import (
	"sync"
	"unicode/utf8"

	"blkchain/cli/internal/engagement"
)

// engageevidence.go is the REPL's bounded, session-scoped, on-demand evidence
// accessor. The REPL/TUI model holds only the read-only Snapshot,
// not the engagement Store (ws.Store lives inside runReplEngage's goroutine), so
// a structured /evidence view cannot read evidence directly. runReplEngage
// registers the current engagement's evidence source here while it runs; the TUI
// calls EngageEvidence(taskID) on demand (when the operator opens the view), and
// the result is bounded so a large evidence set cannot bloat the UI or stall the
// ~10Hz render. Evidence is deliberately NOT embedded in the polled Snapshot.

const (
	// maxEvidenceRows caps how many evidence rows the accessor returns for a task.
	maxEvidenceRows = 50
	// maxEvidenceQuoteBytes caps each returned quote (rune-safe truncation).
	maxEvidenceQuoteBytes = 4096
)

// evidenceRow is a bounded evidence row for the REPL /evidence view.
type evidenceRow struct {
	ID        int64
	Quote     string
	Truncated bool // the quote was truncated to maxEvidenceQuoteBytes
}

// engageEvidenceMu guards the process-wide evidence source: runReplEngage sets it
// (to the current engagement's Store.EvidenceRowsFor) on its own goroutine while
// the engagement runs and clears it on exit; the TUI reads it from the UI
// goroutine via EngageEvidence.
var (
	engageEvidenceMu sync.Mutex
	engageEvidenceFn func(taskID string) ([]engagement.EvidenceRow, error)
)

// SetEngageEvidenceSource registers the current engagement's evidence source so
// the REPL /evidence view can read it on demand, paralleling SetReplArmRequester.
// runReplEngage registers ws.Store.EvidenceRowsFor while it runs and clears it
// (nil) on exit. With no source registered (no active engagement) EngageEvidence
// returns nothing.
func SetEngageEvidenceSource(fn func(taskID string) ([]engagement.EvidenceRow, error)) {
	engageEvidenceMu.Lock()
	engageEvidenceFn = fn
	engageEvidenceMu.Unlock()
}

// EngageEvidence returns the current engagement's evidence for taskID, bounded to
// at most maxEvidenceRows rows with each quote capped to maxEvidenceQuoteBytes
// (rune-safe). The second return reports whether any row was dropped or any quote
// truncated, so the view can show a "capped" marker. With no source registered or
// on a read error it returns (nil, false).
func EngageEvidence(taskID string) ([]evidenceRow, bool) {
	engageEvidenceMu.Lock()
	fn := engageEvidenceFn
	engageEvidenceMu.Unlock()
	if fn == nil {
		return nil, false
	}
	rows, err := fn(taskID)
	if err != nil {
		return nil, false
	}
	capped := false
	if len(rows) > maxEvidenceRows {
		rows = rows[:maxEvidenceRows]
		capped = true
	}
	out := make([]evidenceRow, 0, len(rows))
	for _, r := range rows {
		q, truncated := capQuote(r.Quote, maxEvidenceQuoteBytes)
		if truncated {
			capped = true
		}
		out = append(out, evidenceRow{ID: r.ID, Quote: q, Truncated: truncated})
	}
	return out, capped
}

// capQuote truncates s to at most maxBytes, backing up to a rune boundary so a
// multibyte rune is never split. It returns the (possibly truncated) string and
// whether it was truncated.
func capQuote(s string, maxBytes int) (string, bool) {
	if len(s) <= maxBytes {
		return s, false
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}
