package main

import (
	"fmt"
	"time"
)

// cost.go is the per-turn /cost footer: a muted one-line
// summary of latency plus completion tokens, printed after each answer when the
// transport exposes usage. RAG usage comes from the langchaingo response when the
// model returns it; agent usage comes from the gateway run.completed event.

// turnCost is one turn's usage. completionTokens is 0 when the transport did
// not report token counts, in which case the footer shows latency only.
type turnCost struct {
	completionTokens int
	elapsed          time.Duration
}

// costFooter renders the muted one-line footer: latency, plus completion tokens
// when they are available.
func costFooter(c turnCost) string {
	parts := []string{c.elapsed.Round(100 * time.Millisecond).String()}
	if c.completionTokens > 0 {
		parts = append(parts, fmt.Sprintf("%d tokens", c.completionTokens))
	}
	return "   " + Meta.Render(Glyph(GlyphBullet)+" "+joinSep(parts...))
}
