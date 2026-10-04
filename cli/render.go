package main

import (
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/rivo/uniseg"
)

// render.go holds glowRender, used everywhere blk shows an answer or other
// long-form markdown, so it looks like the `glow` binary's output. It also
// holds headerLine, a small layout helper for banner-style rows (title/version,
// SEARCH banner, ranked rows).

// glowRender renders md the way the `glow` binary does: glamour's
// auto-selected dark/light style, word-wrapped to width (capped at 100
// columns, glow's own cap; <= 0 also means "use the cap"). When the theme's
// capability detection (see theme.go) says color is off, it forces glamour's
// plain notty/ascii style instead of letting glamour auto-detect, so piped
// or NO_COLOR output never carries ANSI. On any renderer error it falls back
// to the raw markdown so an answer is never lost. md is untrusted (corpus,
// web, LLM output), so it is stripped of terminal control sequences first;
// that also covers the raw fallback.
func glowRender(md string, width int) string {
	md = sanitizeTerminal(md)
	w := width
	if w <= 0 || w > 100 {
		w = 100
	}

	// mdStyle is resolved once at startup (theme.go); using a fixed style here
	// instead of glamour.WithAutoStyle avoids a per-render OSC 11 background
	// query, whose "rgb:..." reply would otherwise leak into the TUI input.
	opts := []glamour.TermRendererOption{glamour.WithStandardStyle(mdStyle), glamour.WithWordWrap(w)}
	if useUnicode {
		opts = append(opts, glamour.WithEmoji())
	}
	r, err := glamour.NewTermRenderer(opts...)
	if err != nil {
		return md
	}
	out, err := r.Render(md)
	if err != nil {
		return md
	}
	return out
}

// headerLine right-aligns right against left within the wrap width derived
// from width (the caller's terminal or model width; capped at 78 columns),
// for banner-style rows like "blk ...
// knowledge-base client ... v0.4.1" or a search result's "title ... score".
// Widths are measured with lipgloss.Width so ANSI styling already applied to
// left or right doesn't throw off the padding. The result never exceeds the
// wrap width: an oversized left is cut, and right is dropped when there is no
// room for both.
func headerLine(left, right string, width int) string {
	w := wrapWidth(width, 78)
	rw := lipgloss.Width(right)
	if w-rw-1 < 1 {
		right, rw = "", 0
	}
	room := w - rw
	if rw > 0 {
		room--
	}
	if lipgloss.Width(left) > room {
		left = lipgloss.NewStyle().MaxWidth(room).Render(left)
	}
	pad := w - lipgloss.Width(left) - rw
	if pad < 0 {
		pad = 0
	}
	if rw > 0 && pad < 1 {
		pad = 1
	}
	return left + strings.Repeat(" ", pad) + right
}

// ellipsize shortens plain text s to at most n display columns, ending in an
// ASCII "..." when it was cut. n <= 0 yields "", and n <= 3 yields only dots.
// s must be unstyled: styled text is cut with lipgloss MaxWidth instead.
func ellipsize(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= n {
		return s
	}
	if n <= 3 {
		return strings.Repeat(".", n)
	}
	var b strings.Builder
	used := 0
	g := uniseg.NewGraphemes(s)
	for g.Next() {
		rw := g.Width()
		if used+rw > n-3 {
			break
		}
		b.WriteString(g.Str())
		used += rw
	}
	return b.String() + "..."
}

// wrapIndent word-wraps plain text s so every line, indent columns of leading
// space included, fits in total columns. A token longer than the room is
// hard-broken instead of overflowing, so URLs, base64, and payload strings
// stay inside the width. total and indent are guarded so the text width is
// always at least 1.
func wrapIndent(s string, indent, total int) string {
	if indent < 0 {
		indent = 0
	}
	if indent > total-1 {
		indent = total - 1
	}
	if indent < 0 {
		indent = 0
	}
	w := total - indent
	if w < 1 {
		w = 1
	}
	pad := strings.Repeat(" ", indent)
	lines := strings.Split(lipgloss.NewStyle().Width(w).Render(s), "\n")
	for i, ln := range lines {
		lines[i] = pad + strings.TrimRight(ln, " ")
	}
	return strings.Join(lines, "\n")
}
