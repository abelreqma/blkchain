package main

import (
	"fmt"
	"strings"
	"time"
)

// cost.go is the per-turn /cost footer (V2-BRIEF.md T5): a muted one-line
// summary of latency plus completion tokens, printed after each answer when the
// transport exposes usage. RAG usage comes from the langchaingo response when the
// model returns it; agent usage comes from the gateway run.completed event.

// turnCost is one turn's usage. hasTokens is false when the transport did not
// report token counts, in which case the footer shows latency only.
type turnCost struct {
	completionTokens int
	totalTokens      int
	elapsed          time.Duration
	hasTokens        bool
}

// costFooter renders the muted one-line footer: latency, plus completion tokens
// (and the total when larger) when they are available.
func costFooter(c turnCost) string {
	parts := []string{c.elapsed.Round(100 * time.Millisecond).String()}
	if c.hasTokens {
		tok := fmt.Sprintf("%d tokens", c.completionTokens)
		if c.totalTokens > c.completionTokens {
			tok = fmt.Sprintf("%d/%d tokens", c.completionTokens, c.totalTokens)
		}
		parts = append(parts, tok)
	}
	return "   " + Meta.Render(Glyph(GlyphBullet)+" "+strings.Join(parts, " · "))
}
