package main

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// powerline.go renders powerlevel10k-style segment ribbons in three capability
// tiers, held to the theme palette. Segment content and colors are identical
// across tiers; only separators, icons, and background fills change.

type plTier int

const (
	plASCII   plTier = iota // NO_COLOR, dumb terminal, or piped: no fills, '>'/'<'
	plUnicode               // default: filled triangles U+25B6/U+25C0, bg fills
	plNerd                  // BLKCHAIN_POWERLINE=1: real powerline glyphs + icons
)

// plCurrentTier layers the nerd opt-in over the existing color/unicode flags.
func plCurrentTier() plTier {
	if !useColor {
		return plASCII
	}
	if os.Getenv("BLKCHAIN_POWERLINE") == "1" && useUnicode {
		return plNerd
	}
	if useUnicode {
		return plUnicode
	}
	return plASCII
}

// plSegment is one ribbon cell. Icon is a leading glyph (nerd tier only); FG/BG
// are theme colors. A zero BG means no fill (ascii tier ignores BG entirely).
type plSegment struct {
	Text string
	FG   lipgloss.TerminalColor
	BG   lipgloss.TerminalColor
	Icon string
}

// plSeparators returns the (rightArrow, leftArrow) glyphs for a tier.
func plSeparators(t plTier) (string, string) {
	switch t {
	case plNerd:
		return "\uE0B0", "\uE0B2"
	case plUnicode:
		return "\u25B6", "\u25C0"
	default:
		return ">", "<"
	}
}

// plRenderRibbon renders a left cluster and an optional right cluster. In the
// ascii tier it joins segment text with ' > ' / ' < ' and applies no fills. In
// the unicode/nerd tiers each segment is text on its BG, and the separator
// between A and B is the arrow colored as A's BG on B's BG (seamless powerline),
// or a thin line when A and B share a BG. The ascii tier ignores BG, so it never
// uses the thin separator.
// width is advisory; callers cut to terminal width with lipgloss.
func plRenderRibbon(left, right []plSegment, t plTier, width int) string {
	if t == plASCII {
		var parts []string
		for _, s := range left {
			parts = append(parts, s.Text)
		}
		out := strings.Join(parts, " > ")
		if len(right) > 0 {
			var rp []string
			for _, s := range right {
				rp = append(rp, s.Text)
			}
			out += "   " + strings.Join(rp, " < ")
		}
		return out
	}
	rightArrow, leftArrow := plSeparators(t)
	thinRight, thinLeft := plThinSeparators(t)
	termBG := lipgloss.Color("") // default terminal background
	var b strings.Builder
	// left cluster: seg, then a separator, ... , trailing arrow to termBG. Between
	// neighbors with the same BG the separator is a thin line; otherwise it is the
	// arrow (segBG on nextBG, seamless powerline).
	for i, s := range left {
		b.WriteString(plSegText(s, t))
		var nextBG lipgloss.TerminalColor = termBG
		if i+1 < len(left) {
			nextBG = left[i+1].BG
			if s.BG == nextBG {
				b.WriteString(lipgloss.NewStyle().Foreground(Muted).Background(s.BG).Render(thinRight))
				continue
			}
		}
		b.WriteString(lipgloss.NewStyle().Foreground(s.BG).Background(nextBG).Render(rightArrow))
	}
	if len(left) > 0 && len(right) > 0 {
		b.WriteString(" ")
	}
	// right cluster: leading arrow (firstBG on termBG), then seg; between same-BG
	// neighbors a thin line, otherwise arrow(segBG on prevBG).
	for i, s := range right {
		var prevBG lipgloss.TerminalColor = termBG
		if i > 0 {
			prevBG = right[i-1].BG
		}
		if i > 0 && s.BG == prevBG {
			b.WriteString(lipgloss.NewStyle().Foreground(Muted).Background(s.BG).Render(thinLeft))
		} else {
			b.WriteString(lipgloss.NewStyle().Foreground(s.BG).Background(prevBG).Render(leftArrow))
		}
		b.WriteString(plSegText(s, t))
	}
	return b.String()
}

// plThinSeparators returns the (right, left) thin separators used between
// segments that share a background. The ascii tier uses the flat " > " / " < "
// join, so thin separators do not apply there.
func plThinSeparators(t plTier) (string, string) {
	if t == plNerd {
		return "\uE0B1", "\uE0B3"
	}
	return "\u2502", "\u2502"
}

func plSegText(s plSegment, t plTier) string {
	txt := s.Text
	if t == plNerd && s.Icon != "" {
		txt = s.Icon + " " + txt
	}
	st := lipgloss.NewStyle().Padding(0, 1)
	if s.FG != nil {
		st = st.Foreground(s.FG)
	}
	if s.BG != nil {
		st = st.Background(s.BG)
	}
	return st.Render(txt)
}

// plMeter renders a solid progress meter of cells columns. ascii tier wraps the
// fill in brackets; color tiers use block glyphs colored Success (filled) and
// Muted (empty). frac is clamped to [0,1].
func plMeter(frac float64, cells int, t plTier) string {
	// NaN guard: NaN != NaN by IEEE 754.
	if frac != frac {
		frac = 0
	}
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	if cells < 1 {
		cells = 1
	}
	if cells > 200 {
		cells = 200
	}
	filled := int(frac*float64(cells) + 0.5)
	if t == plASCII {
		return "[" + strings.Repeat("#", filled) + strings.Repeat(".", cells-filled) + "]"
	}
	fill := lipgloss.NewStyle().Foreground(Success).Render(strings.Repeat("\u2588", filled))
	rest := lipgloss.NewStyle().Foreground(Muted).Render(strings.Repeat("\u2591", cells-filled))
	return fill + rest
}
