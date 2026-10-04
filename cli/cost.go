package main

import (
	"fmt"
	"strings"
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
	calls            []llmCallStats
	partial          bool
}

func costDetails(c turnCost) string {
	lines := []string{costFooter(c)}
	for _, call := range c.calls {
		detail := fmt.Sprintf("%s: %s", sanitizeTerminal(call.Stage), (time.Duration(call.DurationMS) * time.Millisecond).String())
		if call.Cached {
			detail += ", cached"
		} else if call.UsageReported {
			detail += fmt.Sprintf(", %d input tokens, %d output tokens", call.PromptTokens, call.CompletionTokens)
		} else {
			detail += ", usage unavailable"
		}
		if call.Status != "ok" {
			detail += ", " + sanitizeTerminal(call.Status)
		}
		lines = append(lines, "   "+Meta.Render(detail))
	}
	if c.partial {
		lines = append(lines, "   "+Meta.Render("additional calls omitted"))
	}
	return strings.Join(lines, "\n")
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
