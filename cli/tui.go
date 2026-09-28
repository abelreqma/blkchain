package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"blkchain/cli/internal/client"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// tui.go is the interactive Bubble Tea REPL (BUILD-BRIEF.md Task 3). Its
// architecture is deliberately constrained (CHARM-PATTERNS.md):
//   - inline program: NO WithAltScreen, so terminal scrollback is preserved
//     and tea.Println works.
//   - NO mouse capture: native click-drag selection and OS copy/paste keep
//     working. This is the #1 requirement.
//   - every finished exchange is committed to real scrollback with tea.Println;
//     View() renders ONLY the transient region (status line + input/spinner +
//     help hint), so finished Q&A is real, selectable, copyable terminal text.
//
// runREPL (repl.go) only reaches runTUI on a real TTY; otherwise it runs the
// plain line loop.

// runTUI starts the Bubble Tea program in inline mode with no mouse capture.
func runTUI() error {
	p := tea.NewProgram(initialModel())
	_, err := p.Run()
	return err
}

// --- keys + help ---

type keyMap struct {
	Submit, Newline, HistPrev, HistNext, Cancel, Quit, Help key.Binding
}

func defaultKeys() keyMap {
	return keyMap{
		Submit:   key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "ask")),
		Newline:  key.NewBinding(key.WithKeys("ctrl+j"), key.WithHelp("ctrl+j", "newline")),
		HistPrev: key.NewBinding(key.WithKeys("up"), key.WithHelp("↑", "prev")),
		HistNext: key.NewBinding(key.WithKeys("down"), key.WithHelp("↓", "next")),
		Cancel:   key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c", "cancel/quit")),
		Quit:     key.NewBinding(key.WithKeys("ctrl+d"), key.WithHelp("ctrl+d", "quit")),
		Help:     key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "keys")),
	}
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Submit, k.Newline, k.Help, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Submit, k.Newline, k.HistPrev, k.HistNext},
		{k.Help, k.Cancel, k.Quit},
	}
}

// --- messages ---

type answerMsg struct {
	resp    *client.AnswerResponse
	elapsed time.Duration
}
type searchMsg struct {
	query   string
	results []client.SearchResult
	elapsed time.Duration
}
type healthReportMsg struct {
	h   *client.HealthResponse
	err error
}
type healthMsg struct{ ok bool } // startup status-dot check
type errMsg struct{ err error }
type canceledMsg struct{}
type execDoneMsg struct{ err error }

// --- model ---

type model struct {
	client *client.Client

	ta   textarea.Model
	sp   spinner.Model
	help help.Model
	keys keyMap

	width int

	working     bool
	workingVerb string
	turnStart   time.Time
	cancel      context.CancelFunc

	history   []string
	histIdx   int
	histDraft string

	lastAnswer  string
	openTargets []string // paths for /open N (from the last answer or search)

	apiOK      bool
	apiChecked bool
}

func initialModel() model {
	ta := textarea.New()
	ta.Placeholder = randomPlaceholder()
	ta.Prompt = Glyph(GlyphPrompt) + " "
	ta.CharLimit = 4000
	ta.ShowLineNumbers = false
	ta.SetHeight(1)
	ta.FocusedStyle.Prompt = lipgloss.NewStyle().Foreground(Accent).Bold(true)
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle()
	ta.KeyMap.InsertNewline = key.NewBinding(key.WithKeys("ctrl+j"), key.WithHelp("ctrl+j", "newline"))
	ta.Focus()

	sp := spinner.New()
	sp.Spinner = spinner.Spinner{Frames: SpinnerFrames(), FPS: time.Second / 10}
	sp.Style = lipgloss.NewStyle().Foreground(Accent)

	hist := loadHistory()

	return model{
		client:  client.NewClient(),
		ta:      ta,
		sp:      sp,
		help:    help.New(),
		keys:    defaultKeys(),
		history: hist,
		histIdx: len(hist),
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		textarea.Blink,
		tea.Println(welcomeBanner()),
		healthCmd(m.client),
	)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.ta.SetWidth(msg.Width)
		m.help.Width = msg.Width
		return m, nil

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Cancel):
			if m.working {
				if m.cancel != nil {
					m.cancel()
				}
				return m, nil
			}
			return m, tea.Quit
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.keys.Help):
			// Only toggle the key list when the input is empty, so "?" can be
			// typed inside a question.
			if !m.working && strings.TrimSpace(m.ta.Value()) == "" {
				m.help.ShowAll = !m.help.ShowAll
				return m, nil
			}
		case key.Matches(msg, m.keys.Submit):
			return m.submit()
		case key.Matches(msg, m.keys.HistPrev):
			if m.working || strings.Contains(m.ta.Value(), "\n") {
				break // multi-line: let the textarea move the cursor
			}
			return m.recallPrev(), nil
		case key.Matches(msg, m.keys.HistNext):
			if m.working || strings.Contains(m.ta.Value(), "\n") {
				break
			}
			return m.recallNext(), nil
		}

		// Freeze editing while a turn is in flight.
		if m.working {
			return m, nil
		}
		var cmd tea.Cmd
		m.ta, cmd = m.ta.Update(msg)
		m.ta.SetHeight(clamp(m.ta.LineCount(), 1, 6))
		return m, cmd

	case spinner.TickMsg:
		if m.working {
			var cmd tea.Cmd
			m.sp, cmd = m.sp.Update(msg)
			return m, cmd
		}
		return m, nil

	case answerMsg:
		m.working = false
		m.cancel = nil
		m.lastAnswer = msg.resp.Answer
		m.openTargets = citationPaths(msg.resp.Citations)
		m.apiOK, m.apiChecked = true, true
		return m, tea.Println(formatAnswer(msg.resp, msg.elapsed, m.renderWidth()))

	case searchMsg:
		m.working = false
		m.cancel = nil
		m.openTargets = resultPaths(msg.results)
		m.apiOK, m.apiChecked = true, true
		return m, tea.Println(strings.TrimRight(formatResults(msg.query, msg.results, msg.elapsed), "\n"))

	case healthReportMsg:
		m.working = false
		m.cancel = nil
		m.apiChecked = true
		m.apiOK = msg.err == nil && msg.h != nil && msg.h.Status == "ok"
		return m, tea.Println(formatHealth(msg.h, msg.err, m.client.BaseURL))

	case errMsg:
		m.working = false
		m.cancel = nil
		if isUnreachable(msg.err) {
			m.apiOK, m.apiChecked = false, true
		}
		return m, tea.Println(styleErr(msg.err))

	case canceledMsg:
		m.working = false
		m.cancel = nil
		return m, tea.Println("   " + Meta.Render("canceled"))

	case execDoneMsg:
		if msg.err != nil {
			return m, tea.Println(styleErr(msg.err))
		}
		return m, nil

	case healthMsg:
		m.apiOK = msg.ok
		m.apiChecked = true
		return m, nil
	}

	return m, nil
}

// submit handles the Enter key: parse the input, echo it to scrollback, and
// dispatch the right command.
func (m model) submit() (tea.Model, tea.Cmd) {
	if m.working {
		return m, nil
	}
	q := strings.TrimSpace(m.ta.Value())
	if q == "" {
		return m, nil
	}
	m.ta.Reset()
	m.ta.SetHeight(1)
	_ = appendHistory(q)
	m.history = append(m.history, q)
	m.histIdx = len(m.history)
	m.histDraft = ""

	verb, arg := parseInput(q)
	echo := promptEcho(q)

	switch verb {
	case "quit":
		return m, tea.Quit
	case "help":
		return m, tea.Sequence(tea.Println(echo), tea.Println(helpBlock()))
	case "copy":
		return m, tea.Sequence(tea.Println(echo), tea.Println(m.doCopy()))
	case "open":
		return m, tea.Sequence(tea.Println(echo), m.openCmd(arg))
	case "hermes":
		if strings.TrimSpace(arg) == "" {
			return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(errors.New("hermes: give me a prompt"))))
		}
		return m, tea.Sequence(tea.Println(echo), execFuncCmd(func() error { return runHermes([]string{arg}) }))
	case "doctor":
		return m, tea.Sequence(tea.Println(echo), execFuncCmd(func() error { return runDoctor(nil) }))
	case "logs":
		var largs []string
		if strings.TrimSpace(arg) != "" {
			largs = strings.Fields(arg)
		}
		return m, tea.Sequence(tea.Println(echo), execFuncCmd(func() error { return runLogs(largs) }))
	case "search", "ask", "health":
		if (verb == "search" || verb == "ask") && strings.TrimSpace(arg) == "" {
			return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(fmt.Errorf("%s: give me something to %s", verb, verb))))
		}
		m.working = true
		m.workingVerb = workingVerbLabel(verb)
		m.turnStart = time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		m.cancel = cancel
		return m, tea.Batch(tea.Println(echo), m.sp.Tick, dispatchCmd(ctx, m.client, verb, arg, m.turnStart))
	}
	// Unknown /verb.
	return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(fmt.Errorf("unknown command /%s — try /help", verb))))
}

func (m model) recallPrev() model {
	if len(m.history) == 0 {
		return m
	}
	if m.histIdx == len(m.history) {
		m.histDraft = m.ta.Value()
	}
	if m.histIdx > 0 {
		m.histIdx--
	}
	m.ta.SetValue(m.history[m.histIdx])
	m.ta.CursorEnd()
	return m
}

func (m model) recallNext() model {
	if m.histIdx >= len(m.history) {
		return m
	}
	m.histIdx++
	if m.histIdx == len(m.history) {
		m.ta.SetValue(m.histDraft)
	} else {
		m.ta.SetValue(m.history[m.histIdx])
	}
	m.ta.CursorEnd()
	return m
}

func (m model) View() string {
	var b strings.Builder
	b.WriteString(m.statusLine())
	b.WriteByte('\n')
	if m.working {
		b.WriteString(m.spinnerLine())
	} else {
		b.WriteString(m.ta.View())
	}
	b.WriteByte('\n')
	b.WriteString(m.help.View(m.keys))
	return b.String()
}

// --- async dispatch ---

// dispatchCmd runs the network call for search/ask/health in a goroutine and
// selects it against ctx, so a Ctrl+C (which calls cancel) surfaces a
// canceledMsg immediately even though the underlying HTTP call keeps running
// until the client's own 30s timeout. A deadline exceeded is reported as a
// one-line timeout error.
func dispatchCmd(ctx context.Context, c *client.Client, verb, arg string, start time.Time) tea.Cmd {
	return func() tea.Msg {
		ch := make(chan tea.Msg, 1)
		go func() {
			switch verb {
			case "search":
				resp, err := c.Search(arg, 0, nil)
				if err != nil {
					ch <- errMsg{err}
					return
				}
				ch <- searchMsg{query: arg, results: resp.Results, elapsed: time.Since(start)}
			case "ask":
				resp, err := c.Answer(arg)
				if err != nil {
					ch <- errMsg{err}
					return
				}
				ch <- answerMsg{resp: resp, elapsed: time.Since(start)}
			case "health":
				h, err := c.Health()
				ch <- healthReportMsg{h: h, err: err}
			}
		}()
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				return errMsg{errors.New("request timed out after 30s")}
			}
			return canceledMsg{}
		case msg := <-ch:
			return msg
		}
	}
}

func healthCmd(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		h, err := c.Health()
		return healthMsg{ok: err == nil && h != nil && h.Status == "ok"}
	}
}

// --- exec (suspend the TUI to run an interactive/verbose command) ---

// funcExec adapts a plain func to tea.ExecCommand, so tea.Exec releases the
// terminal, runs the func (which writes straight to os.Stdout/Stderr like the
// existing openFile/runHermes/runDoctor/runLogs helpers), then restores the
// live region. The Set* methods are no-ops because those helpers already wire
// os.Std* themselves.
type funcExec struct{ fn func() error }

func (f funcExec) Run() error          { return f.fn() }
func (f funcExec) SetStdin(io.Reader)  {}
func (f funcExec) SetStdout(io.Writer) {}
func (f funcExec) SetStderr(io.Writer) {}

func execFuncCmd(fn func() error) tea.Cmd {
	return tea.Exec(funcExec{fn: fn}, func(err error) tea.Msg { return execDoneMsg{err} })
}

func (m model) openCmd(arg string) tea.Cmd {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return tea.Println(styleErr(errors.New("open: give a number (e.g. /open 2) or a path")))
	}
	if n, err := strconv.Atoi(arg); err == nil {
		if n < 1 || n > len(m.openTargets) {
			return tea.Println(styleErr(fmt.Errorf("open: no item %d (have %d)", n, len(m.openTargets))))
		}
		path := m.openTargets[n-1]
		if path == "" {
			return tea.Println(styleErr(fmt.Errorf("open: item %d has no file path", n)))
		}
		return execFuncCmd(func() error { return openFile(path, false) })
	}
	return execFuncCmd(func() error { return openFile(arg, false) })
}

// --- clipboard ---

// clipboardCandidates returns the ordered clipboard tools to try for goos,
// each as an argv (binary + fixed args). Pure, so it can be unit tested by
// GOOS without shelling out.
func clipboardCandidates(goos string) [][]string {
	switch goos {
	case "darwin":
		return [][]string{{"pbcopy"}}
	default:
		return [][]string{{"wl-copy"}, {"xclip", "-selection", "clipboard"}}
	}
}

func copyToClipboard(text string) error {
	for _, cand := range clipboardCandidates(runtime.GOOS) {
		bin, err := exec.LookPath(cand[0])
		if err != nil {
			continue
		}
		c := exec.Command(bin, cand[1:]...)
		c.Stdin = strings.NewReader(text)
		return c.Run()
	}
	return errors.New("no clipboard tool found (install pbcopy, wl-copy, or xclip)")
}

func (m model) doCopy() string {
	if strings.TrimSpace(m.lastAnswer) == "" {
		return styleErr(errors.New("copy: no answer to copy yet"))
	}
	if err := copyToClipboard(m.lastAnswer); err != nil {
		return styleErr(fmt.Errorf("copy: %w", err))
	}
	return " " + OK.Render(Glyph(GlyphOK)) + " " + Meta.Render("copied the last answer to the clipboard")
}

// --- input parsing ---

// parseInput classifies a submitted line. A leading "/" selects an explicit
// command; bare "s"/"search" is a search shorthand; anything else is an ask
// (the headline verb for a Q&A KB, per BUILD-BRIEF.md).
func parseInput(line string) (verb, arg string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	if strings.HasPrefix(line, "/") {
		v, rest := splitFirst(line[1:])
		return strings.ToLower(v), rest
	}
	first, rest := splitFirst(line)
	switch strings.ToLower(first) {
	case "s", "search":
		return "search", rest
	}
	return "ask", line
}

// --- rendering helpers (all return strings for tea.Println) ---

func (m model) statusLine() string {
	dot := Glyph(GlyphDot)
	style := Caut
	label := "checking"
	if m.apiChecked {
		if m.apiOK {
			style, label = OK, "api ok"
		} else {
			style, label = Fail, "api down"
		}
	}
	return " " + style.Render(dot) + " " + Meta.Render(label) + "  " + Meta.Render(m.client.BaseURL)
}

func (m model) spinnerLine() string {
	el := ""
	if d := time.Since(m.turnStart); d > 2*time.Second {
		el = " " + Meta.Render("("+d.Round(time.Second).String()+")")
	}
	return " " + m.sp.View() + " " + Meta.Render(m.workingVerb) + el
}

func (m model) renderWidth() int {
	w := m.width
	if w <= 0 {
		w = terminalWidth()
	}
	if w > 100 {
		w = 100
	}
	if w < 20 {
		w = 20
	}
	return w
}

func formatAnswer(resp *client.AnswerResponse, elapsed time.Duration, width int) string {
	var b strings.Builder
	fmt.Fprintf(&b, " %s %s\n", OK.Render(Glyph(GlyphOK)),
		Meta.Render("Answered in "+elapsed.Round(100*time.Millisecond).String()))
	b.WriteString(strings.TrimRight(glowRender(resp.Answer, width), "\n"))
	b.WriteString("\n\n " + H2.Render("SOURCES") + "\n")
	if len(resp.Citations) == 0 {
		b.WriteString("   " + Meta.Render("(none)") + "\n")
	}
	for i, cit := range resp.Citations {
		line := "   " + Key.Render(fmt.Sprintf("[%d]", i+1)) + "  " + Body.Render(cit.Source)
		meta := cit.Path
		if cit.Section != "" {
			if meta != "" {
				meta += " · "
			}
			meta += cit.Section
		}
		if meta != "" {
			line += "  " + Meta.Render(meta)
		}
		b.WriteString(line + "\n")
	}
	if resp.UsedWeb {
		b.WriteString("   " + Meta.Render("(this answer used a web search)") + "\n")
	}
	if len(resp.Citations) > 0 {
		b.WriteString("   " + Meta.Render("open a source with /open N") + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatHealth(h *client.HealthResponse, err error, baseURL string) string {
	if err != nil {
		return styleErr(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, " %s blkChain API: %s  %s\n", check(h.Status == "ok"), h.Status, Meta.Render("("+baseURL+")"))
	fmt.Fprintf(&b, "   %s qdrant\n", check(h.Qdrant))
	fmt.Fprintf(&b, "   %s embed_server", check(h.EmbedServer))
	return b.String()
}

func styleErr(err error) string {
	line := " " + Fail.Render(Glyph(GlyphErr)) + " " + oneLine(err.Error())
	if isUnreachable(err) {
		line += "\n   " + Meta.Render("start the services with `blk up`")
	}
	return line
}

func promptEcho(q string) string {
	label := Prompt.Render(Glyph(GlyphPrompt))
	lines := strings.Split(q, "\n")
	var b strings.Builder
	fmt.Fprintf(&b, " %s %s", label, Body.Render(lines[0]))
	for _, l := range lines[1:] {
		fmt.Fprintf(&b, "\n   %s", Body.Render(l))
	}
	return b.String()
}

func welcomeBanner() string {
	return " " + H1.Render("blk") + " " +
		Meta.Render("· ask the knowledge base — Enter to ask, /help for commands, ctrl+d to quit")
}

func helpBlock() string {
	rows := []usageRow{
		{"<question>", "ask the knowledge base (the default)"},
		{"/ask <q>", "ask explicitly"},
		{"/search <q>", "find ranked source chunks (also: s <q>)"},
		{"/open <N|path>", "open source N from the last answer/search, or a path"},
		{"/hermes <prompt>", "run a Hermes agent turn"},
		{"/health", "API + dependency status"},
		{"/doctor", "diagnose the whole stack"},
		{"/logs [name]", "tail a service log (api, embed_server)"},
		{"/copy", "copy the last answer to the clipboard"},
		{"/help", "this help"},
		{"/quit", "leave (also ctrl+d)"},
	}
	width := 0
	for _, r := range rows {
		if len(r.name) > width {
			width = len(r.name)
		}
	}
	var b strings.Builder
	b.WriteString(" " + H2.Render("COMMANDS") + "\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "   %s  %s\n", Key.Render(pad(r.name, width)), Body.Render(r.desc))
	}
	b.WriteString("   " + Meta.Render("Enter submits · ctrl+j newline · ↑/↓ history · ? toggles keys"))
	return b.String()
}

// --- small helpers ---

func workingVerbLabel(verb string) string {
	switch verb {
	case "search":
		return "searching" + ellipsis()
	case "health":
		return "checking" + ellipsis()
	default:
		return "thinking" + ellipsis()
	}
}

func ellipsis() string {
	if useUnicode {
		return "…"
	}
	return "..."
}

func citationPaths(cits []client.Citation) []string {
	paths := make([]string, len(cits))
	for i, c := range cits {
		paths[i] = c.Path
	}
	return paths
}

func resultPaths(results []client.SearchResult) []string {
	paths := make([]string, len(results))
	for i, r := range results {
		paths[i] = r.Payload.Path
	}
	return paths
}

func isUnreachable(err error) bool {
	var un *client.UnreachableError
	return errors.As(err, &un)
}

func oneLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

var placeholders = []string{
	"Ask the knowledge base  (Enter to ask, ctrl+j newline, /help)",
	"What do you want to know?  (/search to find chunks, /help)",
	"Type a question, or /help for commands",
}

func randomPlaceholder() string {
	return placeholders[rand.Intn(len(placeholders))]
}
