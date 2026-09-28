package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
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
//
// The model holds a *tea.Program so the RAG streaming callback can push tokens
// back into the event loop with prog.Send(chunkMsg). Because tea.NewProgram
// takes the model by value, "p := tea.NewProgram(m); m.prog = p" would set the
// field on a copy the program never sees. Instead we build the model, hand the
// program its ADDRESS, then set prog on that same value before Run — the value
// (with prog set) is copied into every subsequent model returned from Update.
func runTUI() error {
	m := initialModel()
	p := tea.NewProgram(&m)
	m.prog = p
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

// chunkMsg is one streamed token slice from the RAG synthesizer, pushed into
// the event loop by the StreamRAG callback via prog.Send.
type chunkMsg string

// streamDoneMsg is the terminal message of a stream: the full answer, the
// citations derived from the retrieved chunks (RAG only), and any error. agent
// marks an agent-mode turn, which renders without a SOURCES block.
type streamDoneMsg struct {
	full      string
	citations []client.Citation
	err       error
	agent     bool
}

// Agent-mode streaming messages (V2-BRIEF.md T3), pushed into the event loop by
// the StreamAgent/StreamAgentSubprocess callback via prog.Send. Answer deltas
// reuse chunkMsg; these carry the non-answer signals.
type agentToolMsg struct{ verb, tool string } // muted "· running <tool>…" line
type agentNoteMsg string                      // muted commentary / fallback note line
type agentModelMsg string                     // model id for the status line
type agentSessionMsg string                   // gateway session id to cache
type agentXportMsg string                     // "gateway" | "subprocess" for this turn
type agentHealthMsg struct {                  // startup/mode-switch agent health
	gwOK  bool
	binOK bool
	model string
}

// --- model ---

type model struct {
	client *client.Client
	prog   *tea.Program // set in runTUI so the stream callback can Send messages

	ta   textarea.Model
	sp   spinner.Model
	help help.Model
	keys keyMap

	width int

	working     bool
	workingVerb string
	turnStart   time.Time
	cancel      context.CancelFunc
	live        string // in-progress streamed answer, committed to scrollback on done

	history   []string
	histIdx   int
	histDraft string

	lastAnswer  string
	openTargets []string // paths for /open N (from the last answer or search)

	apiOK      bool
	apiChecked bool

	// Agent mode (V2-BRIEF.md T3). mode is "rag" (default) or "agent"; the agent
	// fields track the gateway session handle and the health/transport shown in
	// the status line.
	mode         string
	agentSession string // cached hermes gateway session id (conversation handle)
	agentModel   string // display model id, discovered from events / model options
	agentXport   string // last-used transport: "gateway" | "subprocess"
	agentGwOK    bool   // gateway /health reachable+authorized
	agentBinOK   bool   // hermes CLI on PATH (subprocess fallback possible)
	agentChecked bool
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
	sp.Style = lipgloss.NewStyle().Foreground(Muted)

	hist := loadHistory()

	return model{
		client:  client.NewClient(),
		ta:      ta,
		sp:      sp,
		help:    help.New(),
		keys:    defaultKeys(),
		history: hist,
		histIdx: len(hist),
		mode:    "rag",
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
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		m.lastAnswer = msg.resp.Answer
		m.openTargets = citationPaths(msg.resp.Citations)
		m.apiOK, m.apiChecked = true, true
		return m, tea.Println(formatAnswer(msg.resp, msg.elapsed, m.renderWidth()))

	case chunkMsg:
		if !m.working {
			return m, nil // stray token after cancel/done
		}
		m.live += string(msg)
		m.workingVerb = "answering" + ellipsis()
		return m, nil

	case streamDoneMsg:
		m.working = false
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		live := strings.TrimRight(m.live, "\n")
		m.live = ""
		m.workingVerb = ""
		elapsed := time.Since(m.turnStart)
		full := msg.full
		if strings.TrimSpace(full) == "" {
			full = live
		}
		if msg.agent {
			if msg.err != nil && errors.Is(msg.err, context.Canceled) {
				return m, tea.Println("   " + Meta.Render("canceled"))
			}
			m.lastAnswer = full
			m.openTargets = nil
			if msg.err != nil {
				var b strings.Builder
				if strings.TrimSpace(full) != "" {
					b.WriteString(formatAgentAnswer(full, elapsed, m.renderWidth()))
					b.WriteByte('\n')
				}
				b.WriteString(styleErr(fmt.Errorf("agent turn ended early: %w", msg.err)))
				return m, tea.Println(b.String())
			}
			if strings.TrimSpace(full) == "" {
				return m, tea.Println("   " + Meta.Render("(agent returned no output)"))
			}
			return m, tea.Println(formatAgentAnswer(full, elapsed, m.renderWidth()))
		}
		if msg.err != nil {
			if errors.Is(msg.err, context.Canceled) {
				return m, tea.Println("   " + Meta.Render("canceled"))
			}
			// Errored after streaming partial output (an immediate failure is
			// handled inside streamCmd by falling back to /answer). Commit what
			// streamed, then note the early end.
			m.apiChecked = true
			var b strings.Builder
			if strings.TrimSpace(full) != "" {
				resp := &client.AnswerResponse{Answer: full, Citations: msg.citations}
				b.WriteString(formatAnswer(resp, elapsed, m.renderWidth()))
				b.WriteByte('\n')
			}
			b.WriteString(styleErr(fmt.Errorf("stream ended early: %w", msg.err)))
			return m, tea.Println(b.String())
		}
		m.lastAnswer = full
		m.openTargets = citationPaths(msg.citations)
		m.apiOK, m.apiChecked = true, true
		resp := &client.AnswerResponse{Answer: full, Citations: msg.citations}
		return m, tea.Println(formatAnswer(resp, elapsed, m.renderWidth()))

	case searchMsg:
		m.working = false
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		m.openTargets = resultPaths(msg.results)
		m.apiOK, m.apiChecked = true, true
		return m, tea.Println(strings.TrimRight(formatResults(msg.query, msg.results, msg.elapsed), "\n"))

	case healthReportMsg:
		m.working = false
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		m.apiChecked = true
		m.apiOK = msg.err == nil && msg.h != nil && msg.h.Status == "ok"
		return m, tea.Println(formatHealth(msg.h, msg.err, m.client.BaseURL))

	case errMsg:
		m.working = false
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		if isUnreachable(msg.err) {
			m.apiOK, m.apiChecked = false, true
		}
		return m, tea.Println(styleErr(msg.err))

	case canceledMsg:
		m.working = false
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
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

	case agentToolMsg:
		if !m.working {
			return m, nil
		}
		line := " " + Meta.Render(Glyph(GlyphBullet)+" "+msg.verb+" "+msg.tool)
		if msg.verb == "running" {
			line += Meta.Render(ellipsis())
		}
		return m, tea.Println(line)

	case agentNoteMsg:
		if strings.TrimSpace(string(msg)) == "" {
			return m, nil
		}
		return m, tea.Println("   " + Meta.Render(oneLine(string(msg))))

	case agentModelMsg:
		if s := strings.TrimSpace(string(msg)); s != "" {
			m.agentModel = s
		}
		return m, nil

	case agentSessionMsg:
		m.agentSession = string(msg)
		return m, nil

	case agentXportMsg:
		m.agentXport = string(msg)
		m.agentChecked = true
		return m, nil

	case agentHealthMsg:
		m.agentGwOK = msg.gwOK
		m.agentBinOK = msg.binOK
		m.agentChecked = true
		if msg.model != "" {
			m.agentModel = msg.model
		}
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
	case "mode":
		if m.mode == "agent" {
			m.mode = "rag"
		} else {
			m.mode = "agent"
		}
		return m, tea.Batch(tea.Sequence(tea.Println(echo), tea.Println(modeNote(m.mode))), m.modeSwitchCmd())
	case "agent":
		m.mode = "agent"
		return m, tea.Batch(tea.Sequence(tea.Println(echo), tea.Println(modeNote(m.mode))), m.modeSwitchCmd())
	case "rag":
		m.mode = "rag"
		return m, tea.Batch(tea.Sequence(tea.Println(echo), tea.Println(modeNote(m.mode))), m.modeSwitchCmd())
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
	case "up", "down", "status":
		return m, tea.Sequence(tea.Println(echo), execFuncCmd(func() error { return runStack(verb) }))
	case "search", "ask", "health":
		if (verb == "search" || verb == "ask") && strings.TrimSpace(arg) == "" {
			return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(fmt.Errorf("%s: give me something to %s", verb, verb))))
		}
		m.working = true
		m.workingVerb = workingVerbLabel(verb)
		m.live = ""
		m.turnStart = time.Now()
		// Match the client's own timeout so the context doesn't fire before the
		// HTTP call does (ask can be slow; see client.requestTimeout).
		ctx, cancel := context.WithTimeout(context.Background(), m.client.HTTPClient.Timeout)
		m.cancel = cancel
		// AGENT mode: an ask runs a full agentic turn via the hermes gateway (or
		// the subprocess fallback), streaming into the same live buffer.
		if verb == "ask" && m.mode == "agent" {
			return m, tea.Batch(tea.Println(echo), m.sp.Tick, m.agentStreamCmd(ctx, arg))
		}
		// RAG mode: stream the synthesis directly from oMLX when OMLX_API_KEY is
		// set; otherwise fall back to the non-streaming /answer path so ask
		// always works (V2-BRIEF.md fallback).
		if verb == "ask" && streamingEnabled() {
			return m, tea.Batch(tea.Println(echo), m.sp.Tick, m.streamCmd(ctx, arg, m.turnStart))
		}
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
		if lr := m.liveRegion(); lr != "" {
			b.WriteByte('\n')
			b.WriteString(lr)
		}
	} else {
		b.WriteString(m.ta.View())
	}
	b.WriteByte('\n')
	b.WriteString(m.help.View(m.keys))
	return b.String()
}

// liveRegion renders the in-progress streamed answer under a Muted left "│"
// bar. It shows raw tokens (glamour-rendered only once the turn completes, in
// the streamDoneMsg handler). Empty when nothing has streamed yet.
func (m model) liveRegion() string {
	if strings.TrimSpace(m.live) == "" {
		return ""
	}
	bar := Meta.Render(Glyph(GlyphBar))
	wrapped := lipgloss.NewStyle().Width(m.renderWidth()).Render(strings.TrimRight(m.live, "\n"))
	lines := strings.Split(wrapped, "\n")
	var b strings.Builder
	for i, ln := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(" " + bar + " " + Body.Render(ln))
	}
	return b.String()
}

// --- async dispatch ---

// dispatchCmd runs the network call for search/ask/health in a goroutine and
// selects it against ctx, so a Ctrl+C (which calls cancel) surfaces a
// canceledMsg immediately even though the underlying HTTP call keeps running
// until the client's own timeout. A deadline exceeded is reported as a
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
				return errMsg{errors.New("request timed out (raise BLKCHAIN_TIMEOUT_SECONDS)")}
			}
			return canceledMsg{}
		case msg := <-ch:
			return msg
		}
	}
}

// streamCmd runs StreamRAG in a goroutine (tea.Cmd), pushing each token back
// as a chunkMsg via the stored *tea.Program. If the stream fails before any
// token arrives, it falls back to the non-streaming /answer path so ask always
// works (V2-BRIEF.md); a cancel returns a canceledMsg.
func (m model) streamCmd(ctx context.Context, question string, start time.Time) tea.Cmd {
	prog := m.prog
	c := m.client
	return func() tea.Msg {
		streamed := false
		full, cits, err := StreamRAG(ctx, c, question, func(b []byte) {
			streamed = true
			if prog != nil {
				prog.Send(chunkMsg(string(b)))
			}
		})
		if err != nil && !streamed {
			if errors.Is(err, context.Canceled) {
				return canceledMsg{}
			}
			// Immediate stream failure (no tokens): fall back to /answer.
			resp, aerr := c.Answer(question)
			if aerr != nil {
				return errMsg{aerr}
			}
			return answerMsg{resp: resp, elapsed: time.Since(start)}
		}
		return streamDoneMsg{full: full, citations: cits, err: err}
	}
}

func healthCmd(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		h, err := c.Health()
		return healthMsg{ok: err == nil && h != nil && h.Status == "ok"}
	}
}

// agentStreamCmd runs one AGENT-mode turn in a goroutine (tea.Cmd). It decides
// the transport once per turn: prefer the hermes gateway when reachable, else
// the `hermes chat` subprocess. Answer deltas become chunkMsg (the shared live
// buffer); tool activity and commentary become muted scrollback lines; the
// terminal event yields a streamDoneMsg (agent). Ctrl-C (ctx cancel) aborts the
// gateway request or kills the subprocess.
func (m model) agentStreamCmd(ctx context.Context, message string) tea.Cmd {
	prog := m.prog
	sessID := m.agentSession
	return func() tea.Msg {
		var full strings.Builder
		onEvent := func(ev agentEvent) {
			switch ev.kind {
			case agentText:
				full.WriteString(ev.text)
				if prog != nil {
					prog.Send(chunkMsg(ev.text))
				}
			case agentCommentary:
				if prog != nil {
					prog.Send(agentNoteMsg(ev.text))
				}
			case agentToolActivity:
				if prog != nil {
					prog.Send(agentToolMsg{verb: ev.text, tool: ev.tool})
				}
			case agentModelInfo:
				if prog != nil {
					prog.Send(agentModelMsg(ev.text))
				}
			case agentTerminal:
				// Use the terminal final text only when nothing streamed (a
				// non-streaming run); otherwise the deltas already hold the answer.
				if ev.text != "" && full.Len() == 0 {
					full.WriteString(ev.text)
				}
			}
		}

		if hermesAvailable(ctx) {
			id := sessID
			var err error
			if id == "" {
				id, err = ensureSession(ctx)
			}
			if err == nil {
				if prog != nil {
					if id != sessID {
						prog.Send(agentSessionMsg(id))
					}
					prog.Send(agentXportMsg("gateway"))
				}
				serr := StreamAgent(ctx, id, message, onEvent)
				if errors.Is(serr, context.Canceled) {
					return canceledMsg{}
				}
				return streamDoneMsg{full: full.String(), agent: true, err: serr}
			}
			// Gateway reachable but session setup failed: fall back with a note.
			if prog != nil {
				prog.Send(agentNoteMsg("gateway session failed, using hermes subprocess"))
			}
		}

		// Subprocess fallback: gateway unreachable, or session setup failed.
		if prog != nil {
			prog.Send(agentXportMsg("subprocess"))
		}
		serr := StreamAgentSubprocess(ctx, message, onEvent)
		if errors.Is(serr, context.Canceled) {
			return canceledMsg{}
		}
		if serr != nil && full.Len() == 0 {
			if errors.Is(serr, errHermesMissing) {
				return errMsg{errors.New("agent mode unavailable: run `hermes gateway`, or install the hermes CLI")}
			}
			return errMsg{fmt.Errorf("agent turn failed: %w", serr)}
		}
		return streamDoneMsg{full: full.String(), agent: true, err: serr}
	}
}

// modeSwitchCmd refreshes the status-line health after a mode change: the agent
// gateway/binary for agent mode, the blkChain API for rag mode.
func (m model) modeSwitchCmd() tea.Cmd {
	if m.mode == "agent" {
		return agentHealthCmd()
	}
	return healthCmd(m.client)
}

// agentHealthCmd probes the hermes gateway and the hermes binary so the status
// line can show the transport before the first agent turn.
func agentHealthCmd() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), agentSessionTimeout)
		defer cancel()
		gwOK := hermesAvailable(ctx)
		model := ""
		if gwOK {
			model = currentAgentModel(ctx)
		}
		return agentHealthMsg{gwOK: gwOK, binOK: hermesBinAvailable(), model: model}
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

// statusLine shows the active mode, the model, and an api-health dot on one
// muted line (V2-BRIEF.md T3). In rag mode the dot reflects the blkChain API; in
// agent mode it reflects the hermes gateway (or "subprocess" on fallback).
func (m model) statusLine() string {
	if m.mode == "agent" {
		return m.agentStatusLine()
	}
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
	return " " + style.Render(dot) + " " + Meta.Render("rag") + "  " +
		Meta.Render(ragModelLabel()) + "  " + Meta.Render(label)
}

// agentStatusLine renders the agent-mode status line: dot + "agent" + model +
// transport. The transport is the one used on the last turn, or the health-probe
// result before the first turn.
func (m model) agentStatusLine() string {
	dot := Glyph(GlyphDot)
	xport := m.agentXport
	if xport == "" {
		switch {
		case !m.agentChecked:
			xport = "checking"
		case m.agentGwOK:
			xport = "gateway"
		case m.agentBinOK:
			xport = "subprocess"
		default:
			xport = "unavailable"
		}
	}
	style := Caut
	switch xport {
	case "gateway":
		style = OK
	case "unavailable":
		style = Fail
	}
	model := m.agentModel
	if model == "" {
		model = "unknown"
	}
	return " " + style.Render(dot) + " " + Meta.Render("agent") + "  " +
		Meta.Render(model) + "  " + Meta.Render(xport)
}

// ragModelLabel is the oMLX model shown in rag-mode status, without a network
// call: OMLX_MODEL when set, else the built-in default.
func ragModelLabel() string {
	if v := strings.TrimSpace(os.Getenv("OMLX_MODEL")); v != "" {
		return v
	}
	return defaultOMLXModel
}

// modeNote is the one-line confirmation printed when the mode changes.
func modeNote(mode string) string {
	if mode == "agent" {
		return "   " + Meta.Render("mode: agent (full hermes agent with tools, web, memory)")
	}
	return "   " + Meta.Render("mode: rag (retrieve then stream a cited answer)")
}

// formatAgentAnswer glamour-renders an agent turn's answer with a muted timing
// header and no SOURCES block (agent turns carry no citation list).
func formatAgentAnswer(full string, elapsed time.Duration, width int) string {
	var b strings.Builder
	fmt.Fprintf(&b, " %s %s\n", OK.Render(Glyph(GlyphOK)),
		Meta.Render("Agent answered in "+elapsed.Round(100*time.Millisecond).String()))
	b.WriteString(strings.TrimRight(glowRender(full, width), "\n"))
	return strings.TrimRight(b.String(), "\n")
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
		Meta.Render("· ask the knowledge base — Enter to ask, /mode for agent, /help for commands, ctrl+d to quit")
}

func helpBlock() string {
	rows := []usageRow{
		{"<question>", "ask (rag mode streams a cited answer; agent mode runs hermes)"},
		{"/ask <q>", "ask explicitly"},
		{"/mode", "toggle rag / agent mode (also /agent, /rag)"},
		{"/search <q>", "find ranked source chunks (also: s <q>)"},
		{"/open <N|path>", "open source N from the last answer/search, or a path"},
		{"/hermes <prompt>", "run a Hermes agent turn"},
		{"/health", "API + dependency status"},
		{"/doctor", "diagnose the whole stack"},
		{"/logs [name]", "tail a service log (api, embed_server)"},
		{"/up | /down | /status", "manage the local services"},
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
