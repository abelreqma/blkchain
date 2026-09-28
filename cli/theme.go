package main

import (
	"os"
	"strings"

	"github.com/charmbracelet/glamour/styles"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

// theme.go is the terminal visual design system: the semantic color palette,
// the derived styles, glyph/ASCII fallback, and small rendering helpers
// (scoreStyle, wrap). It is the single styling source for the whole CLI; the
// older raw-ANSI helpers were retired once every caller moved onto these styles.

// c builds a CompleteAdaptiveColor from light/dark hex, ANSI256, and ANSI-16
// values, per DESIGN-SPEC.md §1.
func c(lHex, l256, l16, dHex, d256, d16 string) lipgloss.CompleteAdaptiveColor {
	return lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{TrueColor: lHex, ANSI256: l256, ANSI: l16},
		Dark:  lipgloss.CompleteColor{TrueColor: dHex, ANSI256: d256, ANSI: d16},
	}
}

// Palette tokens (V2-BRIEF.md "Black/gray design"). Never set the terminal
// background. Accent is brightness (off-white), reserved for marks only
// (prompt glyph, blk label, [n] citation index, selected marker, ● dot) —
// H2 and Key use Heading instead so color stays under 10% of glyphs.
var (
	Accent  = c("#18181B", "234", "0", "#FAFAFA", "231", "15")
	Heading = c("#18181B", "234", "0", "#E4E4E7", "255", "15")
	FgBody  = c("#27272A", "235", "0", "#D4D4D8", "253", "7")
	Muted   = c("#71717A", "243", "8", "#A1A1AA", "246", "8")
	Rule    = c("#D4D4D8", "252", "7", "#3F3F46", "238", "8")
	Surface = c("#F4F4F5", "255", "15", "#27272A", "235", "0") // overlay fill only
	Success = c("#4F7355", "65", "2", "#6E9B77", "108", "2")   // muted sage
	Warn    = c("#8A6D3B", "94", "3", "#C9A26B", "179", "3")   // muted tan
	Err     = c("#9B4A4A", "131", "1", "#C77B7B", "167", "1")  // muted rose
)

// slateAccent is the BLK_ACCENT=slate opt-in: a low-chroma blue instead of
// the off-white default, applied once at init below.
var slateAccent = c("#3E5C82", "60", "4", "#8AA2C8", "110", "12")

// Styles (DESIGN-SPEC.md §2, restyled per V2-BRIEF.md black/gray palette).
var (
	H1     = lipgloss.NewStyle().Foreground(Heading).Bold(true)
	H2     = lipgloss.NewStyle().Foreground(Heading).Bold(true)
	Body   = lipgloss.NewStyle().Foreground(FgBody)
	Meta   = lipgloss.NewStyle().Foreground(Muted).Faint(true)
	Code   = lipgloss.NewStyle().Foreground(FgBody).Faint(true)
	RuleS  = lipgloss.NewStyle().Foreground(Rule)
	Key    = lipgloss.NewStyle().Foreground(Heading).Bold(true)
	OK     = lipgloss.NewStyle().Foreground(Success).Bold(true)
	Fail   = lipgloss.NewStyle().Foreground(Err).Bold(true)
	Caut   = lipgloss.NewStyle().Foreground(Warn).Bold(true)
	Prompt = lipgloss.NewStyle().Foreground(Accent).Bold(true)
)

// scoreStyle bands a relevance score per DESIGN-SPEC.md §3/§6:
// Success >= 0.85, Warn 0.65-0.84, Muted < 0.65.
func scoreStyle(score float64) lipgloss.Style {
	switch {
	case score >= 0.85:
		return lipgloss.NewStyle().Foreground(Success)
	case score >= 0.65:
		return lipgloss.NewStyle().Foreground(Warn)
	default:
		return lipgloss.NewStyle().Foreground(Muted)
	}
}

// --- capability detection (DESIGN-SPEC.md §1, §4) ---

// GlyphName identifies a themed glyph that has both a unicode and an ASCII
// rendering (DESIGN-SPEC.md §4).
type GlyphName int

const (
	GlyphOK GlyphName = iota
	GlyphErr
	GlyphWarn
	GlyphInfo
	GlyphPrompt
	GlyphBullet
	GlyphNest
	GlyphArrow
	GlyphDot
	GlyphBar
)

// glyphPairs maps each glyph to its {unicode, ascii} rendering.
var glyphPairs = map[GlyphName][2]string{
	GlyphOK:     {"✓", "[ok]"},
	GlyphErr:    {"✗", "[x]"},
	GlyphWarn:   {"▲", "[!]"},
	GlyphInfo:   {"•", "-"},
	GlyphPrompt: {"❯", ">"},
	GlyphBullet: {"·", "-"},
	GlyphNest:   {"▸", ">"},
	GlyphArrow:  {"→", "->"},
	GlyphDot:    {"●", "*"},
	GlyphBar:    {"│", "|"},
}

var spinnerUnicodeFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
var spinnerASCIIFrames = []string{"|", "/", "-", "\\"}

// glyphFor is the pure glyph-selection function: given a glyph name and
// whether unicode glyphs are usable, it returns the correct rendering. It is
// factored out of Glyph so the selection logic can be unit tested without
// depending on package-level capability detection.
func glyphFor(name GlyphName, unicode bool) string {
	pair, ok := glyphPairs[name]
	if !ok {
		return ""
	}
	if unicode {
		return pair[0]
	}
	return pair[1]
}

// spinnerFramesFor is the pure counterpart of SpinnerFrames.
func spinnerFramesFor(unicode bool) []string {
	if unicode {
		return spinnerUnicodeFrames
	}
	return spinnerASCIIFrames
}

// Glyph returns the glyph for name using the capability detection decided
// once at startup.
func Glyph(name GlyphName) string {
	return glyphFor(name, useUnicode)
}

// SpinnerFrames returns the spinner animation frames for the current
// capability detection.
func SpinnerFrames() []string {
	return spinnerFramesFor(useUnicode)
}

// capabilities is the result of detectCapabilities: whether to use color and
// whether to use unicode glyphs.
type capabilities struct {
	color   bool
	unicode bool
}

// detectCapabilities is pure given its inputs so it can be unit tested
// without touching the real environment or a real terminal. Rules
// (DESIGN-SPEC.md §1, BUILD-BRIEF.md):
//   - NO_COLOR (any non-empty value) disables color, unless CLICOLOR_FORCE is
//     also set (CLICOLOR_FORCE wins).
//   - TERM=dumb or a non-TTY stdout disables color and unicode glyphs.
//   - Otherwise unicode glyphs are used when stdout is a TTY and LC_ALL/LANG
//     mention UTF-8.
func detectCapabilities(isTTY bool, termEnv, noColor, cliColorForce, lcAll, lang string) capabilities {
	dumb := termEnv == "dumb"

	color := true
	if noColor != "" && cliColorForce == "" {
		color = false
	}
	if dumb || !isTTY {
		color = false
	}

	unicode := isTTY && !dumb && isUTF8Locale(lcAll, lang)

	return capabilities{color: color, unicode: unicode}
}

func isUTF8Locale(lcAll, lang string) bool {
	for _, v := range []string{lcAll, lang} {
		u := strings.ToUpper(v)
		if strings.Contains(u, "UTF-8") || strings.Contains(u, "UTF8") {
			return true
		}
	}
	return false
}

// isTerminalStdout reports whether stdout is a real character device (a TTY),
// not a pipe or file.
func isTerminalStdout() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// useColor and useUnicode are decided once at startup and drive Glyph,
// SpinnerFrames, and the NO_COLOR handling in init below.
var (
	useColor   bool
	useUnicode bool
	// mdStyle is glamour's markdown style name, resolved ONCE at startup (see
	// init). Rendering with a fixed style avoids glamour.WithAutoStyle's
	// per-Render OSC 11 background query, which inside the TUI leaks the
	// terminal's "rgb:..." reply into the input line.
	mdStyle string
)

func init() {
	caps := detectCapabilities(
		isTerminalStdout(),
		os.Getenv("TERM"),
		os.Getenv("NO_COLOR"),
		os.Getenv("CLICOLOR_FORCE"),
		os.Getenv("LC_ALL"),
		os.Getenv("LANG"),
	)
	useColor = caps.color
	useUnicode = caps.unicode

	// BLK_ACCENT=slate opts into a low-chroma blue accent instead of the
	// off-white default (V2-BRIEF.md "Black/gray design"). Prompt is
	// recomputed here because it's a package-level var initialized before
	// init() runs, so it would otherwise bake in the pre-switch Accent value.
	if os.Getenv("BLK_ACCENT") == "slate" {
		Accent = slateAccent
	}
	Prompt = lipgloss.NewStyle().Foreground(Accent).Bold(true)

	// lipgloss v1.1's default renderer already auto-detects NO_COLOR (via
	// termenv's EnvColorProfile), but it does NOT honor our CLICOLOR_FORCE
	// override, and relying on implicit detection would leave the "explicit"
	// half of the requirement unmet. So: when our own detection says color is
	// off, force the default renderer's profile to termenv.Ascii explicitly
	// via lipgloss.SetColorProfile. When color is on, leave the renderer's
	// own detection in place so it can still pick ANSI/ANSI256/TrueColor
	// correctly for the terminal.
	if !useColor {
		lipgloss.SetColorProfile(termenv.Ascii)
	}

	// Resolve the markdown style once, here, before any Bubble Tea program
	// takes over the tty. Detecting the background now (rather than per Render
	// via glamour.WithAutoStyle) keeps the terminal's OSC 11 "rgb:..." reply
	// out of the TUI input.
	switch {
	case !useColor:
		mdStyle = styles.NoTTYStyle
	case isTerminalStdout() && lipgloss.HasDarkBackground():
		mdStyle = styles.DarkStyle
	case isTerminalStdout():
		mdStyle = styles.LightStyle
	default:
		mdStyle = styles.DarkStyle
	}
}

// --- prose wrapping (DESIGN-SPEC.md §2) ---

// terminalWidth reads the terminal width via golang.org/x/term, defaulting to
// 80 columns when it can't be determined (non-TTY, error).
func terminalWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return 80
	}
	return w
}

// wrapWidth is the pure width calculation behind wrap: the terminal width
// minus a 2-column gutter, capped at max (a max <= 0 means "no cap"), never
// less than 1.
func wrapWidth(termWidth, max int) int {
	w := termWidth - 2
	if max > 0 && w > max {
		w = max
	}
	if w < 1 {
		w = 1
	}
	return w
}

// wrap word-wraps prose to fit the terminal width capped at max columns.
func wrap(s string, max int) string {
	return lipgloss.NewStyle().Width(wrapWidth(terminalWidth(), max)).Render(s)
}
