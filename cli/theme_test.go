package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/retrieval"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// relLuminance is the WCAG 2.x relative luminance of a #RRGGBB color.
func relLuminance(t *testing.T, hex string) float64 {
	t.Helper()
	if len(hex) != 7 || hex[0] != '#' {
		t.Fatalf("bad hex color %q", hex)
	}
	var ch [3]float64
	for i := 0; i < 3; i++ {
		v, err := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
		if err != nil {
			t.Fatalf("bad hex color %q: %v", hex, err)
		}
		f := float64(v) / 255
		if f <= 0.03928 {
			ch[i] = f / 12.92
		} else {
			ch[i] = math.Pow((f+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*ch[0] + 0.7152*ch[1] + 0.0722*ch[2]
}

// contrastRatio is the WCAG 2.x contrast ratio between two #RRGGBB colors.
func contrastRatio(t *testing.T, a, b string) float64 {
	t.Helper()
	la, lb := relLuminance(t, a), relLuminance(t, b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// xterm256Hex converts a color-cube (16-231) or grayscale (232-255) index of
// the standard xterm 256-color palette to #rrggbb. Indexes 0-15 are terminal
// defined and have no fixed RGB.
func xterm256Hex(t *testing.T, s string) string {
	t.Helper()
	idx, err := strconv.Atoi(s)
	if err != nil || idx < 16 || idx > 255 {
		t.Fatalf("ANSI256 %q is not a cube or grayscale index", s)
	}
	if idx >= 232 {
		v := 8 + 10*(idx-232)
		return fmt.Sprintf("#%02x%02x%02x", v, v, v)
	}
	lv := []int{0, 95, 135, 175, 215, 255}
	i := idx - 16
	return fmt.Sprintf("#%02x%02x%02x", lv[i/36], lv[(i/6)%6], lv[i%6])
}

// TestPaletteContrast is the acceptance gate for the palette: every text token
// must reach 4.5:1 on every background it can land on, and the Rule border must
// reach 3:1 (non-text) on the overlay Surface.
func TestPaletteContrast(t *testing.T) {
	text := map[string]lipgloss.CompleteAdaptiveColor{
		"Accent": Accent, "Heading": Heading, "FgBody": FgBody, "Muted": Muted,
		"Success": Success, "Warn": Warn, "Err": Err, "slateAccent": slateAccent,
	}
	darkBGs := []string{"#000000", "#1E1E1E", "#282C34", Surface.Dark.TrueColor}
	lightBGs := []string{"#FFFFFF", "#FDF6E3", Surface.Light.TrueColor}
	for name, tok := range text {
		for _, bg := range darkBGs {
			if r := contrastRatio(t, tok.Dark.TrueColor, bg); r < 4.5 {
				t.Errorf("%s dark %s on %s = %.2f:1, want >= 4.5", name, tok.Dark.TrueColor, bg, r)
			}
		}
		for _, bg := range lightBGs {
			if r := contrastRatio(t, tok.Light.TrueColor, bg); r < 4.5 {
				t.Errorf("%s light %s on %s = %.2f:1, want >= 4.5", name, tok.Light.TrueColor, bg, r)
			}
		}
	}
	// The 256-color fallbacks must clear the same bar on the backgrounds a
	// 256-color terminal shows, including the Surface fill as it renders there.
	dark256 := append(append([]string{}, darkBGs...), xterm256Hex(t, Surface.Dark.ANSI256))
	light256 := append(append([]string{}, lightBGs...), xterm256Hex(t, Surface.Light.ANSI256))
	for name, tok := range text {
		for _, bg := range dark256 {
			fg := xterm256Hex(t, tok.Dark.ANSI256)
			if r := contrastRatio(t, fg, bg); r < 4.5 {
				t.Errorf("%s dark 256 index %s (%s) on %s = %.2f:1, want >= 4.5", name, tok.Dark.ANSI256, fg, bg, r)
			}
		}
		for _, bg := range light256 {
			fg := xterm256Hex(t, tok.Light.ANSI256)
			if r := contrastRatio(t, fg, bg); r < 4.5 {
				t.Errorf("%s light 256 index %s (%s) on %s = %.2f:1, want >= 4.5", name, tok.Light.ANSI256, fg, bg, r)
			}
		}
	}
	if r := contrastRatio(t, Rule.Dark.TrueColor, Surface.Dark.TrueColor); r < 3.0 {
		t.Errorf("Rule dark %s on Surface %s = %.2f:1, want >= 3.0", Rule.Dark.TrueColor, Surface.Dark.TrueColor, r)
	}
	if r := contrastRatio(t, Rule.Light.TrueColor, Surface.Light.TrueColor); r < 3.0 {
		t.Errorf("Rule light %s on Surface %s = %.2f:1, want >= 3.0", Rule.Light.TrueColor, Surface.Light.TrueColor, r)
	}
}

// TestSuccessLight256Contrast pins the 256-color light Success index (it was
// index 65, 4.10:1 on cream) to one that clears 4.5:1 on the light backgrounds.
func TestSuccessLight256Contrast(t *testing.T) {
	idx, err := strconv.Atoi(Success.Light.ANSI256)
	if err != nil || idx < 16 || idx > 231 {
		t.Fatalf("Success light ANSI256 = %q, want a color-cube index", Success.Light.ANSI256)
	}
	i := idx - 16
	lv := []int{0, 95, 135, 175, 215, 255}
	hex := fmt.Sprintf("#%02x%02x%02x", lv[i/36], lv[(i/6)%6], lv[i%6])
	for _, bg := range []string{"#FFFFFF", "#FDF6E3", Surface.Light.TrueColor} {
		if r := contrastRatio(t, hex, bg); r < 4.5 {
			t.Errorf("Success light 256 index %d (%s) on %s = %.2f:1, want >= 4.5", idx, hex, bg, r)
		}
	}
}

func TestMetaAndCodeAreNotFaint(t *testing.T) {
	if Meta.GetFaint() {
		t.Error("Meta must not use Faint: it drops contrast below 4.5:1")
	}
	if Code.GetFaint() {
		t.Error("Code must not use Faint: it drops contrast below 4.5:1")
	}
}

func TestMuted16ColorFallback(t *testing.T) {
	if got := Muted.Dark.ANSI; got != "7" {
		t.Errorf("Muted dark ANSI-16 = %q, want 7 (bright black is invisible on many dark themes)", got)
	}
}

func TestScoreStyleBanding(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0.95, "success"},
		{0.85, "success"}, // boundary: >= 0.85 is success
		{0.849, "warn"},
		{0.65, "warn"}, // boundary: >= 0.65 is warn
		{0.649, "muted"},
		{0.0, "muted"},
	}
	for _, c := range cases {
		got := scoreStyle(c.score).GetForeground()
		var want interface{}
		switch c.want {
		case "success":
			want = Success
		case "warn":
			want = Warn
		case "muted":
			want = Muted
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("scoreStyle(%v) foreground = %v, want %v (%s)", c.score, got, want, c.want)
		}
	}
}

func TestGlyphFor(t *testing.T) {
	cases := []struct {
		name      GlyphName
		unicode   bool
		wantGlyph string
	}{
		{GlyphOK, true, "✓"},
		{GlyphOK, false, "[ok]"},
		{GlyphErr, true, "✗"},
		{GlyphErr, false, "[x]"},
		{GlyphWarn, true, "▲"},
		{GlyphWarn, false, "[!]"},
		{GlyphPrompt, true, "❯"},
		{GlyphPrompt, false, ">"},
		{GlyphBullet, true, "·"},
		{GlyphBullet, false, "-"},
		{GlyphArrow, true, "→"},
		{GlyphArrow, false, "->"},
	}
	for _, c := range cases {
		if got := glyphFor(c.name, c.unicode); got != c.wantGlyph {
			t.Errorf("glyphFor(%v, %v) = %q, want %q", c.name, c.unicode, got, c.wantGlyph)
		}
	}
}

func TestSpinnerFramesFor(t *testing.T) {
	if got := spinnerFramesFor(true); len(got) != 10 {
		t.Errorf("unicode spinner frames = %d, want 10", len(got))
	}
	if got := spinnerFramesFor(false); !reflect.DeepEqual(got, []string{"|", "/", "-", "\\"}) {
		t.Errorf("ascii spinner frames = %v", got)
	}
}

func TestDetectCapabilities(t *testing.T) {
	cases := []struct {
		name                                      string
		isTTY                                     bool
		term, noColor, cliColorForce, lcAll, lang string
		wantColor, wantUnicode                    bool
	}{
		{"plain tty utf8", true, "xterm-256color", "", "", "en_US.UTF-8", "", true, true},
		{"no_color disables", true, "xterm-256color", "1", "", "en_US.UTF-8", "", false, true},
		{"no_color overridden by force", true, "xterm-256color", "1", "1", "en_US.UTF-8", "", true, true},
		{"dumb disables color and unicode", true, "dumb", "", "", "en_US.UTF-8", "", false, false},
		{"non-tty disables color and unicode", false, "xterm-256color", "", "", "en_US.UTF-8", "", false, false},
		{"non-utf8 locale disables unicode only", true, "xterm-256color", "", "", "C", "", true, false},
		{"lang fallback utf8", true, "xterm", "", "", "", "en_US.utf8", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := detectCapabilities(c.isTTY, c.term, c.noColor, c.cliColorForce, c.lcAll, c.lang)
			if got.color != c.wantColor {
				t.Errorf("color = %v, want %v", got.color, c.wantColor)
			}
			if got.unicode != c.wantUnicode {
				t.Errorf("unicode = %v, want %v", got.unicode, c.wantUnicode)
			}
		})
	}
}

func TestParseThemeMode(t *testing.T) {
	cases := map[string]string{
		"light": "light", "dark": "dark", "auto": "auto",
		"LIGHT": "light", " Dark ": "dark",
		"": "auto", "bogus": "auto", "solarized": "auto",
	}
	for in, want := range cases {
		if got := parseThemeMode(in); got != want {
			t.Errorf("parseThemeMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseColorFGBG(t *testing.T) {
	cases := []struct {
		in       string
		wantDark bool
		wantOK   bool
	}{
		{"0;15", false, true},
		{"0;7", false, true},
		{"15;0", true, true},
		{"7;0", true, true},
		{"15;8", true, true},
		{"0;6", true, true},
		{"15;default;0", true, true},
		{"0;default;15", false, true},
		{"0;9", false, false},
		{"0;default", false, false},
		{"", false, false},
		{"garbage", false, false},
		{"0;x", false, false},
		{"0;-1", false, false},
		{"0;16", false, false},
	}
	for _, c := range cases {
		dark, ok := parseColorFGBG(c.in)
		if ok != c.wantOK || (ok && dark != c.wantDark) {
			t.Errorf("parseColorFGBG(%q) = (%v, %v), want (%v, %v)", c.in, dark, ok, c.wantDark, c.wantOK)
		}
	}
}

func TestResolveDarkBackground(t *testing.T) {
	probeDark := func() bool { return true }
	probeLight := func() bool { return false }
	panicProbe := func() bool { t.Fatal("probe must not run"); return true }
	cases := []struct {
		name       string
		mode, fgbg string
		probe      func() bool
		want       bool
	}{
		{"forced light beats fgbg", "light", "15;0", panicProbe, false},
		{"forced dark beats fgbg", "dark", "0;15", panicProbe, true},
		{"auto honors fgbg light", "auto", "0;15", panicProbe, false},
		{"auto honors fgbg dark", "auto", "15;0", panicProbe, true},
		{"empty mode is auto", "", "0;7", panicProbe, false},
		{"invalid mode falls back to auto", "neon", "0;15", panicProbe, false},
		{"auto without fgbg uses probe dark", "auto", "", probeDark, true},
		{"auto without fgbg uses probe light", "auto", "", probeLight, false},
		{"auto with unusable fgbg uses probe", "auto", "0;default", probeLight, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveDarkBackground(c.mode, c.fgbg, c.probe); got != c.want {
				t.Errorf("resolveDarkBackground(%q, %q) = %v, want %v", c.mode, c.fgbg, got, c.want)
			}
		})
	}
}

func TestSeparatorAndDashGlyphs(t *testing.T) {
	cases := []struct {
		name    GlyphName
		unicode bool
		want    string
	}{
		{GlyphSep, true, "·"},
		{GlyphSep, false, "|"},
		{GlyphDash, true, "—"},
		{GlyphDash, false, "-"},
		{GlyphUp, true, "↑"},
		{GlyphUp, false, "up"},
		{GlyphDown, true, "↓"},
		{GlyphDown, false, "down"},
	}
	for _, c := range cases {
		if got := glyphFor(c.name, c.unicode); got != c.want {
			t.Errorf("glyphFor(%v, %v) = %q, want %q", c.name, c.unicode, got, c.want)
		}
	}
}

func TestBorderFor(t *testing.T) {
	if got := borderFor(true); got != lipgloss.RoundedBorder() {
		t.Errorf("borderFor(true) = %+v, want rounded", got)
	}
	b := borderFor(false)
	if b.Top != "-" || b.Bottom != "-" || b.Left != "|" || b.Right != "|" ||
		b.TopLeft != "+" || b.TopRight != "+" || b.BottomLeft != "+" || b.BottomRight != "+" {
		t.Errorf("borderFor(false) = %+v, want ASCII +-|", b)
	}
}

func TestJoinSepFor(t *testing.T) {
	if got := joinSepFor(true, "a", "b", "c"); got != "a · b · c" {
		t.Errorf("unicode join = %q", got)
	}
	if got := joinSepFor(false, "a", "b", "c"); got != "a | b | c" {
		t.Errorf("ascii join = %q", got)
	}
}

// TestUserFacingStringsAreASCIIWhenUnicodeOff renders the footer hints, the
// welcome banner, the boxes and the REPL strings with unicode disabled and
// requires pure ASCII, so LANG=C terminals never see mojibake.
func TestUserFacingStringsAreASCIIWhenUnicodeOff(t *testing.T) {
	prev := useUnicode
	useUnicode = false
	t.Cleanup(func() { useUnicode = prev })

	isolateUserDirs(t)
	meta := sessionMeta{ID: "abc", Title: "t", MsgCount: 2, UpdatedAt: 1}
	pm := initialModel()
	pm.pal = palette{open: true, items: []paletteItem{{name: "help", desc: "show help"}}}
	got := map[string]string{
		"welcome":   welcomeBanner(80),
		"help":      helpBlock(80),
		"keys":      strings.Join(keyPanelLines(defaultKeys(), 100), "\n"),
		"histPrev":  defaultKeys().HistPrev.Help().Key,
		"histNext":  defaultKeys().HistNext.Help().Key,
		"resume":    newResumePicker([]sessionMeta{meta}, "", 80).View(80, 24),
		"resumeNil": newResumePicker(nil, "", 80).View(80, 24),
		"model":     newModelPicker([]string{"m1", "m2"}, "m1", "low", 80).View(80, 24),
		"palette":   pm.paletteView(80, 24),
		"repl":      replBanner(),
		"prompt":    replPrompt(),
		"reltime":   relTime(0),
		"status":    pm.View(),
	}
	for name, s := range got {
		for _, r := range s {
			if r > 0x7e {
				t.Errorf("%s contains non-ASCII rune %q in %q", name, r, s)
				break
			}
		}
	}
}

func TestPlaceholderStyleUsesMuted(t *testing.T) {
	isolateUserDirs(t)
	m := initialModel()
	want := lipgloss.NewStyle().Foreground(Muted)
	if got := m.ta.FocusedStyle.Placeholder.GetForeground(); !reflect.DeepEqual(got, want.GetForeground()) {
		t.Errorf("focused placeholder foreground = %v, want Muted", got)
	}
	if got := m.ta.BlurredStyle.Placeholder.GetForeground(); !reflect.DeepEqual(got, want.GetForeground()) {
		t.Errorf("blurred placeholder foreground = %v, want Muted", got)
	}
}

func TestStderrRendererUsesOwnCapabilities(t *testing.T) {
	// A non-TTY writer: stderr color off must force plain output.
	off := newStderrRenderer(&strings.Builder{}, capabilities{color: false, unicode: false}, true)
	if off.ColorProfile() != termenv.Ascii {
		t.Errorf("stderr renderer with color off has profile %v, want Ascii", off.ColorProfile())
	}
	if got := Fail.Renderer(off).Render("x"); got != "x" {
		t.Errorf("errored text with color off = %q, want plain", got)
	}
	// Color on leaves the renderer's own detection alone (Ascii for a
	// non-TTY writer here) and carries the resolved background.
	on := newStderrRenderer(&strings.Builder{}, capabilities{color: true}, false)
	if on.HasDarkBackground() {
		t.Error("stderr renderer must carry the resolved light background")
	}
	if !newStderrRenderer(&strings.Builder{}, capabilities{}, true).HasDarkBackground() {
		t.Error("stderr renderer must carry the resolved dark background")
	}
}

func TestWrapWidth(t *testing.T) {
	cases := []struct {
		termWidth, max, want int
	}{
		{80, 90, 78},  // termWidth-2 smaller than max
		{100, 90, 90}, // capped at max
		{0, 90, 1},    // never below 1
		{10, 0, 8},    // max<=0 means no cap
	}
	for _, c := range cases {
		if got := wrapWidth(c.termWidth, c.max); got != c.want {
			t.Errorf("wrapWidth(%d, %d) = %d, want %d", c.termWidth, c.max, got, c.want)
		}
	}
}

func TestLoadAppendHistory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	if got := loadHistory(); got != nil {
		t.Fatalf("loadHistory on missing file = %v, want nil", got)
	}

	if err := appendHistory("ask what is ssrf"); err != nil {
		t.Fatal(err)
	}
	if err := appendHistory("search vector index"); err != nil {
		t.Fatal(err)
	}
	// empty and duplicate-of-last should be skipped
	if err := appendHistory(""); err != nil {
		t.Fatal(err)
	}
	if err := appendHistory("   "); err != nil {
		t.Fatal(err)
	}
	if err := appendHistory("search vector index"); err != nil {
		t.Fatal(err)
	}

	got := loadHistory()
	want := []string{"ask what is ssrf", "search vector index"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loadHistory = %v, want %v", got, want)
	}

	p := filepath.Join(dir, "blkchain", "history")
	if fi, err := os.Stat(p); err != nil {
		t.Fatalf("history file not created: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("history file mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestFixedCLITextIsASCIIWhenUnicodeOff(t *testing.T) {
	prev := useUnicode
	useUnicode = false
	t.Cleanup(func() { useUnicode = prev })

	f, err := os.CreateTemp(t.TempDir(), "usage")
	if err != nil {
		t.Fatal(err)
	}
	usage(f)
	f.Close()
	usageText, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	results := []retrieval.Result{{Score: 0.9, Payload: retrieval.Payload{Source: "wstg", Path: "a.md", Section: "Intro", Text: "body"}}}
	got := map[string]string{
		"usage":   string(usageText),
		"results": formatResults("q", results, 120*time.Millisecond, 80),
		"cost":    costFooter(turnCost{elapsed: time.Second, completionTokens: 5}),
		"noroot":  errNoRoot.Error(),
		"noreach": retrieval.ErrUnreachable.Error(),
		"open":    fmt.Sprintf("open: %q not found, set $%s", "less", pagerOrEditor(false)),
	}
	got["completion bash"] = bashCompletion()
	got["completion zsh"] = zshCompletion()
	for name, s := range got {
		for _, r := range s {
			if r > 0x7e {
				t.Errorf("%s contains non-ASCII rune %q with unicode off: %q", name, r, s)
				break
			}
		}
	}
}
