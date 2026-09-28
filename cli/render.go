package main

import (
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/glamour/styles"
	"github.com/charmbracelet/lipgloss"
)

// render.go implements the "Glow-format markdown output" requirement from
// BUILD-BRIEF.md: a single glowRender used everywhere blk shows an answer or
// other long-form markdown, so it looks like the `glow` binary's output. It
// also holds headerLine, a small layout helper for the banner-style rows in
// DESIGN-SPEC.md's mockups (title/version, SEARCH banner, ranked rows).

// glowRender renders md the way the `glow` binary does: glamour's
// auto-selected dark/light style, word-wrapped to width (capped at 100
// columns, glow's own cap; <= 0 also means "use the cap"). When the theme's
// capability detection (see theme.go) says color is off, it forces glamour's
// plain notty/ascii style instead of letting glamour auto-detect, so piped
// or NO_COLOR output never carries ANSI. On any renderer error it falls back
// to the raw markdown so an answer is never lost.
func glowRender(md string, width int) string {
	w := width
	if w <= 0 || w > 100 {
		w = 100
	}

	opt := glamour.WithAutoStyle()
	if !useColor {
		opt = glamour.WithStandardStyle(styles.NoTTYStyle)
	}

	r, err := glamour.NewTermRenderer(opt, glamour.WithWordWrap(w))
	if err != nil {
		return md
	}
	out, err := r.Render(md)
	if err != nil {
		return md
	}
	return out
}

// headerLine right-aligns right against left within the wrap width (capped
// at 78 columns, matching DESIGN-SPEC.md's mockups), for banner-style rows
// like "blk · knowledge-base client ... v0.4.1" or a search result's
// "title ... score". Widths are measured with lipgloss.Width so ANSI styling
// already applied to left or right doesn't throw off the padding.
func headerLine(left, right string) string {
	width := wrapWidth(terminalWidth(), 78)
	pad := width - lipgloss.Width(left) - lipgloss.Width(right)
	if pad < 1 {
		pad = 1
	}
	return left + strings.Repeat(" ", pad) + right
}
