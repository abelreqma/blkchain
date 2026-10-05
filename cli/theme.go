package main

import (
	"io"
	"os"
	"strconv"
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
// values.
func c(lHex, l256, l16, dHex, d256, d16 string) lipgloss.CompleteAdaptiveColor {
	return lipgloss.CompleteAdaptiveColor{
		Light: lipgloss.CompleteColor{TrueColor: lHex, ANSI256: l256, ANSI: l16},
		Dark:  lipgloss.CompleteColor{TrueColor: dHex, ANSI256: d256, ANSI: d16},
	}
}

// Palette tokens. Never set the terminal
// background. Accent is brightness (off-white), reserved for marks only
// (prompt glyph, blk label, [n] citation index, selected marker, status dot).
// H2 and Key use Heading instead so color stays under 10% of glyphs.
var (
	Accent  = c("#18181B", "234", "0", "#FAFAFA", "231", "15")
	Heading = c("#18181B", "234", "0", "#E4E4E7", "255", "15")
	FgBody  = c("#27272A", "235", "0", "#D4D4D8", "253", "7")
	Muted   = c("#63636C", "242", "8", "#A1A1AA", "246", "7")
	Rule    = c("#85858E", "244", "7", "#767680", "244", "8")
	Surface = c("#F4F4F5", "255", "15", "#27272A", "235", "0") // overlay fill only
	Success = c("#4F7355", "22", "2", "#7AA783", "108", "2")   // muted sage
	Warn    = c("#7A5F2E", "94", "3", "#C9A26B", "179", "3")   // muted tan
	Err     = c("#9B4A4A", "95", "1", "#D08B8B", "174", "1")   // muted rose
)

// slateAccent is the BLK_ACCENT=slate opt-in: a low-chroma blue instead of
// the off-white default, applied once at init below.
var slateAccent = c("#3E5C82", "60", "4", "#8AA2C8", "110", "12")

// Styles.
var (
	H1     = lipgloss.NewStyle().Foreground(Heading).Bold(true)
	H2     = lipgloss.NewStyle().Foreground(Heading).Bold(true)
	Body   = lipgloss.NewStyle().Foreground(FgBody)
	Meta   = lipgloss.NewStyle().Foreground(Muted)
	Code   = lipgloss.NewStyle().Foreground(FgBody)
	RuleS  = lipgloss.NewStyle().Foreground(Rule)
	Key    = lipgloss.NewStyle().Foreground(Heading).Bold(true)
	OK     = lipgloss.NewStyle().Foreground(Success).Bold(true)
	Fail   = lipgloss.NewStyle().Foreground(Err).Bold(true)
	Caut   = lipgloss.NewStyle().Foreground(Warn).Bold(true)
	Prompt = lipgloss.NewStyle().Foreground(Accent).Bold(true)
)

// Help styles, one per level of the help pages' type hierarchy: the tool name,
// section headings, command names, argument placeholders (and the $ prompt),
// flags, and quoted strings in examples. Descriptions use Body, the version
// and notes Meta.
var (
	Title   = lipgloss.NewStyle().Foreground(Accent).Bold(true)
	Section = lipgloss.NewStyle().Foreground(slateAccent).Bold(true)
	Cmd     = lipgloss.NewStyle().Foreground(Heading).Bold(true)
	Arg     = lipgloss.NewStyle().Foreground(Muted)
	Flag    = lipgloss.NewStyle().Foreground(slateAccent)
	Str     = lipgloss.NewStyle().Foreground(Success)
)

// scoreStyle bands a relevance score: Success >= 0.85, Warn 0.65-0.84,
// Muted < 0.65.
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

// --- capability detection ---

// GlyphName identifies a themed glyph that has both a unicode and an ASCII
// rendering.
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
	GlyphSep
	GlyphDash
	GlyphUp
	GlyphDown
)

// glyphPairs maps each glyph to its {unicode, ascii} rendering.
var glyphPairs = map[GlyphName][2]string{
	GlyphOK:     {"\u2705", "[ok]"},
	GlyphErr:    {"\u274c", "[x]"},
	GlyphWarn:   {"\u26a0\ufe0f", "[!]"},
	GlyphInfo:   {"•", "-"},
	GlyphPrompt: {"❯", ">"},
	GlyphBullet: {"·", "-"},
	GlyphNest:   {"▸", ">"},
	GlyphArrow:  {"\u27a1\ufe0f", "->"},
	GlyphDot:    {"●", "*"},
	GlyphBar:    {"│", "|"},
	GlyphSep:    {"·", "|"},
	GlyphDash:   {"—", "-"},
	GlyphUp:     {"\u2b06\ufe0f", "up"},
	GlyphDown:   {"\u2b07\ufe0f", "down"},
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

// borderFor is the pure border selection: rounded box-drawing when unicode is
// usable, plain ASCII (+, -, |) otherwise.
func borderFor(unicode bool) lipgloss.Border {
	if unicode {
		return lipgloss.RoundedBorder()
	}
	return lipgloss.Border{
		Top: "-", Bottom: "-", Left: "|", Right: "|",
		TopLeft: "+", TopRight: "+", BottomLeft: "+", BottomRight: "+",
	}
}

// Border returns the box border for the current capability detection.
func Border() lipgloss.Border {
	return borderFor(useUnicode)
}

// joinSepFor joins parts with the themed separator glyph.
func joinSepFor(unicode bool, parts ...string) string {
	return strings.Join(parts, " "+glyphFor(GlyphSep, unicode)+" ")
}

// joinSep joins parts with the themed separator glyph for the current
// capability detection.
func joinSep(parts ...string) string {
	return joinSepFor(useUnicode, parts...)
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
// without touching the real environment or a real terminal. Rules:
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

// isTerminalStdout reports whether stdout is a terminal.
func isTerminalStdout() bool {
	return isTerminalFile(os.Stdout)
}

// parseThemeMode normalizes BLK_THEME to "light", "dark", or "auto". Anything
// else, including an empty value, is "auto".
func parseThemeMode(v string) string {
	switch m := strings.ToLower(strings.TrimSpace(v)); m {
	case "light", "dark":
		return m
	}
	return "auto"
}

// parseColorFGBG reads the COLORFGBG hint ("fg;bg" or "fg;default;bg"). Only
// the background matters: 7 and 15 are light, 0 to 6 and 8 are dark. Any other
// value, or a malformed string, reports ok=false.
func parseColorFGBG(v string) (dark, ok bool) {
	parts := strings.Split(v, ";")
	if len(parts) < 2 {
		return false, false
	}
	bg, err := strconv.Atoi(strings.TrimSpace(parts[len(parts)-1]))
	if err != nil {
		return false, false
	}
	switch {
	case bg == 7 || bg == 15:
		return false, true
	case (bg >= 0 && bg <= 6) || bg == 8:
		return true, true
	}
	return false, false
}

// resolveDarkBackground decides whether to use the dark palette. BLK_THEME
// light or dark wins. Under auto, a usable COLORFGBG is honored next, and the
// terminal probe runs last. The probe cannot report failure (tmux and SSH
// often drop the query and it then reads as dark), which is why the explicit
// hints come first.
func resolveDarkBackground(mode, colorFGBG string, probe func() bool) bool {
	switch parseThemeMode(mode) {
	case "light":
		return false
	case "dark":
		return true
	}
	if dark, ok := parseColorFGBG(colorFGBG); ok {
		return dark
	}
	return probe()
}

// newStderrRenderer builds the renderer used for styled stderr output. It
// decides color from stderr's own capabilities, not stdout's, and carries the
// already-resolved background so it never probes the terminal.
func newStderrRenderer(w io.Writer, caps capabilities, dark bool) *lipgloss.Renderer {
	r := lipgloss.NewRenderer(w)
	if !caps.color {
		r.SetColorProfile(termenv.Ascii)
	}
	r.SetHasDarkBackground(dark)
	return r
}

// errStyle renders text with style s for stderr.
func errStyle(s lipgloss.Style, text string) string {
	return s.Renderer(stderrRenderer).Render(text)
}

// errMark is the styled error glyph for stderr output.
func errMark() string {
	return errStyle(Fail, glyphFor(GlyphErr, useErrUnicode))
}

// isTerminalFile reports whether f is a terminal (not a pipe, a file, or
// another character device such as /dev/null).
func isTerminalFile(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// useColor and useUnicode are decided once at startup and drive Glyph,
// SpinnerFrames, and the NO_COLOR handling in init below.
var (
	useColor   bool
	useUnicode bool
	// useErrUnicode and stderrRenderer are the stderr counterparts: stderr can
	// be a TTY while stdout is piped, or the reverse.
	useErrUnicode  bool
	stderrRenderer *lipgloss.Renderer
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

	// Resolve the background once. BLK_THEME and COLORFGBG are consulted
	// before the terminal probe, and the probe only runs when color is on and
	// stdout is a TTY, so plain and piped runs never query the terminal.
	dark := resolveDarkBackground(os.Getenv("BLK_THEME"), os.Getenv("COLORFGBG"), func() bool {
		return !useColor || lipgloss.HasDarkBackground()
	})
	if useColor {
		lipgloss.SetHasDarkBackground(dark)
	}

	errCaps := detectCapabilities(
		isTerminalFile(os.Stderr),
		os.Getenv("TERM"),
		os.Getenv("NO_COLOR"),
		os.Getenv("CLICOLOR_FORCE"),
		os.Getenv("LC_ALL"),
		os.Getenv("LANG"),
	)
	useErrUnicode = errCaps.unicode
	stderrRenderer = newStderrRenderer(os.Stderr, errCaps, dark)

	// BLK_ACCENT=slate opts into a low-chroma blue accent instead of the
	// off-white default. Prompt and Title are
	// recomputed here because they are package-level vars initialized before
	// init() runs, so they would otherwise bake in the pre-switch Accent value.
	if os.Getenv("BLK_ACCENT") == "slate" {
		Accent = slateAccent
	}
	Prompt = lipgloss.NewStyle().Foreground(Accent).Bold(true)
	Title = lipgloss.NewStyle().Foreground(Accent).Bold(true)

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
	case dark:
		mdStyle = styles.DarkStyle
	default:
		mdStyle = styles.LightStyle
	}
}

// --- prose wrapping ---

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
