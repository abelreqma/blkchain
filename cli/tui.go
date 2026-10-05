package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"blkchain/cli/internal/askuser"
	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/histstore"
	"blkchain/cli/internal/modeleval"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/secgate"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// tui.go is the interactive Bubble Tea REPL. Its
// architecture is deliberately constrained:
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
// program its ADDRESS, then set prog on that same value before Run. The value
// (with prog set) is copied into every subsequent model returned from Update.
func runTUI() error {
	m := initialModel()
	p := tea.NewProgram(&m)
	m.prog = p
	// Wire the operator arm gate so a REPL engagement's at-exploit arm prompt
	// (runExploitPhase -> ArmRequester) reads over a released terminal, like the
	// confirm, so the keypress is reliable in any terminal during an engagement.
	SetReplArmRequester(releaseArmRequester{prog: p})
	llmWarn = func(line string) { p.Send(tea.Println(line)()) }
	_, err := p.Run()
	if m.rc != nil {
		m.rc.Close()
	}
	return err
}

// --- keys + help ---

type keyMap struct {
	Submit, Newline, HistPrev, HistNext, Cancel, Quit, Help, PickModel key.Binding
	ReverseSearch, Editor, ClearQueue                                  key.Binding
	Esc, Attach, CancelTurn, QueueSubmit                               key.Binding
}

func defaultKeys() keyMap {
	return keyMap{
		Submit:        key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "ask")),
		Newline:       key.NewBinding(key.WithKeys("ctrl+j"), key.WithHelp("ctrl+j", "newline")),
		HistPrev:      key.NewBinding(key.WithKeys("up"), key.WithHelp(Glyph(GlyphUp), "prev")),
		HistNext:      key.NewBinding(key.WithKeys("down"), key.WithHelp(Glyph(GlyphDown), "next")),
		Cancel:        key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c", "cancel/clear/quit")),
		Quit:          key.NewBinding(key.WithKeys("ctrl+d"), key.WithHelp("ctrl+d", "quit")),
		Help:          key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "keys")),
		PickModel:     key.NewBinding(key.WithKeys("ctrl+p"), key.WithHelp("ctrl+p", "model (idle only, shadows line up)")),
		ReverseSearch: key.NewBinding(key.WithKeys("ctrl+r"), key.WithHelp("ctrl+r", "search")),
		Editor:        key.NewBinding(key.WithKeys("ctrl+g"), key.WithHelp("ctrl+g", "editor")),
		ClearQueue:    key.NewBinding(key.WithKeys("ctrl+u"), key.WithHelp("ctrl+u", "clear queue (only while queued, shadows delete to line start)")),
		Esc:           key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "cancel turn/close")),
		Attach:        key.NewBinding(key.WithKeys("@"), key.WithHelp("@", "attach file")),
		CancelTurn:    key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c", "cancel")),
		QueueSubmit:   key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "queue")),
	}
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Submit, k.Newline, k.Help, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Submit, k.Newline, k.HistPrev, k.HistNext},
		{k.ReverseSearch, k.Editor, k.PickModel, k.ClearQueue, k.Attach},
		{k.Help, k.Esc, k.Cancel, k.Quit},
	}
}

// footerKeyMap is the state-dependent key list the footer renders. drop is the
// order in which hints leave a line too narrow for all of them, as indexes
// into short; nil drops from the end with the way out last (see exitHint).
type footerKeyMap struct {
	short []key.Binding
	drop  []int
}

// confirmDrop is the drop order of a confirm footer (confirm, quit, cancel):
// quit goes first, then cancel, and the confirm key stays longest.
var confirmDrop = []int{1, 2, 0}

// hint builds a footer-only binding from a key label and its description.
func hint(k, desc string) key.Binding {
	return key.NewBinding(key.WithKeys(k), key.WithHelp(k, desc))
}

// footerKeys picks the footer hints for the current state, innermost first: an
// open overlay, reverse search, the slash palette, a running turn, then idle.
func (m model) footerKeys() footerKeyMap {
	closeKey := hint("esc/ctrl+c", "close")
	switch {
	case m.overlay != nil:
		switch ov := m.overlay.(type) {
		case historyPicker:
			if ov.confirm {
				return footerKeyMap{short: []key.Binding{hint("y", "confirm delete"), hint("ctrl+d", "quit"), hint("any other key", "cancel")}, drop: confirmDrop}
			}
			return footerKeyMap{short: []key.Binding{hint("1-9", "open"), hint("up/down", "move"), hint("enter", "open"), hint("d then y", "delete"), closeKey}}
		case modelPicker:
			return footerKeyMap{short: []key.Binding{hint("up/down", "choose"), hint("tab/left/right", "switch column"), hint("enter", "apply"), closeKey}}
		case clarifyPicker:
			if ov.typing {
				return footerKeyMap{short: []key.Binding{hint("enter", "submit"), hint("esc", "back")}}
			}
			return footerKeyMap{short: []key.Binding{hint("up/down", "move"), hint("enter", "choose"), hint("esc", "cancel")}}
		case confirmPicker:
			if ov.editing {
				return footerKeyMap{short: []key.Binding{hint("enter", "re-check & run"), hint("esc", "cancel edit")}}
			}
			return footerKeyMap{short: []key.Binding{hint("y", "allow"), hint("e", "edit"), hint("n", "deny"), hint("esc", "deny & stop")}}
		case armPicker:
			return footerKeyMap{short: []key.Binding{hint("y", "arm & continue"), hint("n", "skip"), hint("esc", "stop")}}
		case filePicker:
			return footerKeyMap{short: []key.Binding{hint("type", "filter"), hint("up/down", "move"), hint("enter", "open/select"), hint("backspace", "erase/up"), closeKey}}
		case modelsPanel:
			if ov.armed != "" {
				return footerKeyMap{short: ov.hints(closeKey), drop: confirmDrop}
			}
			return footerKeyMap{short: ov.hints(closeKey)}
		}
		return footerKeyMap{short: []key.Binding{closeKey}}
	case m.rsearch.open:
		return footerKeyMap{short: []key.Binding{hint("type", "search"), hint("ctrl+r", "next"), hint("enter", "accept"), hint("esc/ctrl+c", "cancel")}}
	case m.pal.open:
		return footerKeyMap{short: []key.Binding{hint("up/down", "move"), hint("tab", "complete"), hint("enter", "run"), closeKey}}
	case m.working:
		short := []key.Binding{m.keys.QueueSubmit, m.keys.CancelTurn}
		if len(m.queue) > 0 {
			short = append(short, m.keys.ClearQueue)
		}
		return footerKeyMap{short: append(short, m.keys.Quit)}
	case m.keyPanel:
		short := []key.Binding{hint("?/esc", "close")}
		if w, _ := m.termSize(); len(keyPanelLines(m.keys, w)) > m.keyPanelRows() {
			short = append(short, hint(m.keys.HistPrev.Help().Key+"/"+m.keys.HistNext.Help().Key, "scroll"))
		}
		return footerKeyMap{short: short}
	}
	// Idle: ctrl+j newline goes first, then enter ask, then ? keys, which
	// opens the full key list, and ctrl+d quit last.
	return footerKeyMap{short: m.keys.ShortHelp(), drop: []int{1, 0, 2, 3}}
}

// footer renders the one-line help footer. The full key list is the key panel
// (keyPanelView), not a footer, so this line is always one row. When the hints
// do not fit, they are dropped in the footer's drop order, and the last one in
// that order always stays. A line that still does not fit is cut to the width.
func (m model) footer() string {
	w, _ := m.termSize()
	h := m.help
	h.Width = 0 // render every hint given; the fitting happens here
	fk := m.footerKeys()
	order := fk.drop
	if order == nil {
		order = defaultDrop(fk.short)
	}
	gone := map[int]bool{}
	line := h.ShortHelpView(fk.short)
	for _, i := range order[:max(len(order)-1, 0)] {
		if lipgloss.Width(line) <= w {
			break
		}
		gone[i] = true
		var kept []key.Binding
		for j, k := range fk.short {
			if !gone[j] {
				kept = append(kept, k)
			}
		}
		line = h.ShortHelpView(kept)
	}
	return lipgloss.NewStyle().MaxWidth(w).Render(line)
}

// defaultDrop drops hints from the end, the way out (see exitHint) last.
func defaultDrop(keys []key.Binding) []int {
	exit := exitHint(keys)
	var order []int
	for i := len(keys) - 1; i >= 0; i-- {
		if i != exit {
			order = append(order, i)
		}
	}
	if exit >= 0 {
		order = append(order, exit)
	}
	return order
}

// exitHint is the index of the footer hint that leaves the current state: the
// first close or quit hint, else the first cancel hint, else -1.
func exitHint(keys []key.Binding) int {
	for _, desc := range []string{"close", "quit", "cancel"} {
		for i, k := range keys {
			if k.Help().Desc == desc {
				return i
			}
		}
	}
	return -1
}

// inputCharLimit bounds the draft to 64 KiB of UTF-8 text.
const inputCharLimit = 65536

// limitNotice is the one-line warning shown while the draft sits at the cap,
// since the textarea drops further input silently. Empty otherwise.
func (m model) limitNotice() string {
	if m.draftTruncated && m.ta.LineCount() >= maxDraftLines {
		return " " + Caut.Render(Glyph(GlyphWarn)+" input truncated at 10,000 lines")
	}
	if m.draftTruncated || len(m.ta.Value()) >= inputCharLimit {
		return " " + Caut.Render(Glyph(GlyphWarn)+" input truncated at 64 KiB")
	}
	return ""
}

// reduceMotion reports whether BLK_REDUCE_MOTION asks for a static working line
// instead of the animated spinner (any non-empty value except 0 or false).
func reduceMotion() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("BLK_REDUCE_MOTION")))
	return v != "" && v != "0" && v != "false"
}

// secondTickMsg refreshes the static working line once per second in
// reduced-motion mode. gen ties it to the turn that started the chain, so a
// stale chain from an earlier turn dies instead of doubling the tick rate.
type secondTickMsg struct{ gen int }

// vizTickMsg polls the engagement revision once per second while a turn runs.
// gen ties it to the turn that started the chain, like secondTickMsg.
type vizTickMsg struct{ gen int }

// vizTick schedules the next revision poll for the current turn.
func (m model) vizTick() tea.Cmd {
	gen := m.tickGen
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return vizTickMsg{gen: gen} })
}

// startVizPoll begins the poll chain for a turn, only when an engagement is
// wired. It returns nil otherwise so plain turns start no ticker.
func (m model) startVizPoll() tea.Cmd {
	if m.engagement == nil {
		return nil
	}
	return m.vizTick()
}

// vizBlockMsg carries a rendered task-graph block to commit to scrollback.
type vizBlockMsg struct{ block string }

// vizCommitCmd polls the engagement revision off the UI goroutine and emits a
// vizBlockMsg only when the revision advanced. It returns nil when viz is off
// or no engagement is wired.
func (m *model) vizCommitCmd() tea.Cmd {
	if !m.prefs.Viz || m.engagement == nil || m.viz == nil {
		return nil
	}
	eng, vz := m.engagement, m.viz
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		block, changed, err := vz.Block(ctx, eng)
		if err != nil || !changed {
			return nil
		}
		return vizBlockMsg{block: block}
	}
}

// workTick starts the redraw ticker for a turn: the spinner animation normally,
// a once-per-second tick in reduced-motion mode.
func (m model) workTick() tea.Cmd {
	if !m.reduceMotion {
		return m.sp.Tick
	}
	gen := m.tickGen
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return secondTickMsg{gen: gen} })
}

// ctrlCWindow is how long after a Ctrl-C a second Ctrl-C is treated as "quit".
const ctrlCWindow = time.Second

// --- messages ---

type searchMsg struct {
	query   string
	results []retrieval.Result
	elapsed time.Duration
	web     bool
	json    bool
}
type webAnswerMsg struct {
	query   string
	results []retrieval.Result
	ctx     context.Context
}
type healthReportMsg struct{ h *serviceHealth }
type healthMsg struct { // status-dot check: qdrant, embed_server, llm
	h       *serviceHealth
	rerank  bool      // embed_server's /health says the reranker loaded
	started time.Time // when the probe began, to tell a stale result from a current one
}

// stageMsg is the AnswerLoop phase name ("retrieving", "grading", ...), pushed
// through prog.Send by the Stage callback and shown as the working verb.
// personaMsg carries the chosen domain-expert key for the current rag turn,
// sent once before the answer streams.
type personaMsg string

var personaSymbols = map[string]string{
	"":         "\U0001f9ed",
	"cve":      "\U0001f52c",
	"web":      "\U0001f310",
	"api":      "\U0001f50c",
	"ad":       "\U0001faaa",
	"cloud":    "\u2601\ufe0f",
	"supply":   "\U0001f517",
	"k8s":      "\u2638\ufe0f",
	"linux":    "\U0001f427",
	"windows":  "\U0001fa9f",
	"wireless": "\U0001f4e1",
	"binexp":   "\U0001f41b",
	"network":  "\U0001f578\ufe0f",
	"mobile":   "\U0001f4f1",
	"recon":    "\U0001f50e",
	"ai":       "\U0001f916",
}

func tuiPersonaCue(domain string, tier plTier) string {
	const prefix = "answering as "
	if tier == plASCII {
		return prefix + personaLabel(domain)
	}
	symbol, ok := personaSymbols[domain]
	if !ok {
		symbol = personaSymbols[""]
	}
	return prefix + symbol + " " + personaLabel(domain)
}

type stageMsg string

// noResultsMsg ends a turn when AnswerLoop found nothing to answer from. It is
// a warning with next steps, not an answer.
type noResultsMsg struct{}
type errMsg struct{ err error }
type canceledMsg struct{}
type execDoneMsg struct{ err error }

// chunkMsg is one streamed token slice from the RAG synthesizer, pushed into
// the event loop by the AnswerLoop stream callback via prog.Send.
type chunkMsg string

// streamDoneMsg is the terminal message of a stream: the full answer, the
// citations derived from the retrieved chunks (RAG only), and any error. agent
// marks an agent-mode turn, which renders without a SOURCES block. usedWeb is
// RAG-only (AnswerLoop's web-search fallback); agent turns leave it false.
type streamDoneMsg struct {
	full            string
	citations       []citation
	usedWeb         bool
	rerankOff       bool // the reranker was turned off for this answer
	err             error
	agent           bool
	results         []retrieval.Result
	tokens          int // completion tokens when the transport exposed usage, else 0
	llmCalls        []llmCallStats
	llmCallsPartial bool
}

// dequeueMsg drives the queue-while-busy auto-submit: after a turn completes with
// items queued, the completion handler schedules this so the next queued prompt
// runs.
type dequeueMsg struct{}

// Agent-mode streaming messages, pushed into the event loop by
// the StreamAgent/StreamAgentSubprocess callback via prog.Send. Answer deltas
// reuse chunkMsg; these carry the non-answer signals.
type agentToolMsg struct{ verb, tool string } // muted "- running <tool>..." line
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
	prog *tea.Program // set in runTUI so the stream callback can Send messages

	ta   textarea.Model
	sp   spinner.Model
	help help.Model
	keys keyMap

	width, height int

	working     bool
	workingVerb string
	turnStart   time.Time
	cancel      context.CancelFunc
	live        string // in-progress streamed answer, committed to scrollback on done

	liveTokens int       // streamed tokens counted this turn (for the live readout)
	firstTokAt time.Time // first streamed token this turn

	history        []string
	histIdx        int
	histDraft      string
	draftTruncated bool
	draftTop       int
	draftGoal      int
	draftVertical  bool
	draftLayout    draftLayout

	// Input UX. pal is the slash-command autocomplete palette;
	// queue is the FIFO of prompts typed while a turn runs; lastCtrlC times the
	// Ctrl-C double-press; rsearch is the Ctrl-R reverse history search;
	// attachments are @file contents to inject into the next prompt; ambient is the
	// /init .blk/context.md context; lastCost is the last turn's usage for /cost.
	pal          palette
	queue        []string
	lastCtrlC    time.Time
	quitArmed    string // "turn" or "draft" after one ctrl+d, awaiting the confirming press
	reduceMotion bool   // BLK_REDUCE_MOTION: static working line, no animated spinner
	tickGen      int    // generation of the current turn's once-per-second ticker
	rsearch      reverseSearch
	attachments  []attachment
	ambient      string
	lastCost     turnCost
	lastCostSet  bool

	// Session persistence. sess is the current transcript
	// handle (nil if persistence is unavailable); sessTitle mirrors its title for
	// the status line. pendingQ holds the in-flight question so a completed turn
	// can record both the operator message and the answer.
	sess      *session
	sessTitle string
	pendingQ  string

	// hist is the persistent langchaingo/sqlite3 conversation memory (nil when it
	// could not be opened). Every recorded turn is mirrored here keyed by the
	// session id, and /history lists and reopens sessions from it.
	hist *histstore.Store

	// overlay is the open picker (/resume, /model) or nil. While set it captures
	// keys; the base Update passes through only quit.
	overlay overlayModel

	// engageIntake holds the active /engage guided-intake flow (domain, target,
	// interactive) while its clarify overlays run at idle; nil when no intake is
	// in progress.
	engageIntake *engageIntakeFlow

	// Model/reasoning selection from the /model picker. ragModel overrides the
	// oMLX model in rag mode ("" = default); reasoning is the reasoning-effort
	// level shown in the status line and sent to the agent gateway.
	ragModel  string
	reasoning string

	// resolvedModel is the model a rag turn uses when none is picked, resolved
	// once per session when the model list first loads; "" until then.
	resolvedModel string

	// prefs is the saved /models settings: hidden chat models and the reranker
	// and web switches. Changes are kept here at once and saved in a command.
	prefs modelPrefs

	// engagement feeds the live progress bar and viz renders the task graph.
	// Both stay nil until the viz wiring lands; a nil engagement keeps the
	// plain spinner line.
	engagement EngagementView
	viz        *vizRenderer
	// noticedCandidates is the set of exploit/post-ex candidate task ids already
	// announced inline this engagement, so each detection is noticed once. Reset
	// when a new /engage turn starts.
	noticedCandidates map[string]bool

	lastAnswer  string
	openTargets []openTarget // files for /open N (from the last answer or search)

	// lastQuery and lastResults hold the most recent /search so /generate can
	// synthesize an answer from exactly those retrieved chunks (no re-retrieval).
	lastQuery   string
	lastResults []retrieval.Result

	// cfg is the RAG config, read once when the session starts. rc is the
	// session's one retrieval client, closed when the session ends; rcErr is why
	// it could not be made.
	cfg   ragconfig.Config
	rc    *retrieval.Client
	rcErr error

	// forceRag makes the next rag-mode turn ground unconditionally (the
	// /rag <question> form). It is a one-shot: consumed and cleared per turn.
	forceRag bool

	// liveCache holds live's incremental wrap, so a frame never re-wraps the
	// whole stream. nil works too, rendering from scratch.
	liveCache *liveCache

	// servicesOK is whether qdrant, embed_server, and the LLM all answered;
	// servicesChecked is whether anything has said so either way yet.
	servicesOK      bool
	servicesChecked bool
	health          *serviceHealth // last qdrant/embed_server/llm probe; names what is down
	rerankUp        bool           // the last probe found the reranker loaded
	llmDownAt       time.Time      // when a turn last found the LLM refusing connections
	probeSeen       bool           // the first health probe has arrived, so the down-service hint is spent

	// keyPanel is the "?" key reference, drawn above the input; keyScroll is how
	// many of its rows are scrolled off the top on a short terminal.
	keyPanel  bool
	keyScroll int

	// Agent mode. mode is "rag" (default) or "agent"; the agent
	// fields track the gateway session handle and the health/transport shown in
	// the status line.
	mode string
	// persona is the domain key of the expert that answered the current/last rag
	// turn (e.g. "ad"), set from a personaMsg; "" for the generic persona. The
	// status ribbon shows it; it is cleared at the start of each new rag turn.
	persona string
	// engageMode is the session autonomy mode (secgate.Safe default, or Auto) that a
	// gate-governed REPL engagement (replengage.go runReplEngage) feeds into
	// buildEngageGate; engageOverride is the auto-scope override (/auto override). The
	// /safe//auto commands set these; the ribbon and the /engage dispatch read them.
	engageMode     secgate.Mode
	engageOverride bool
	// engageHITL is true when /auto for the current directory would fall back to
	// per-command confirmation because the unattended allowed_binaries bound is
	// empty (unattendedBoundEmpty at /auto time). The ribbon shows it as the
	// "auto (hitl)" marker. It is set by /auto and cleared by /safe.
	engageHITL   bool
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
	ta.CharLimit = inputCharLimit
	ta.MaxHeight = 0
	ta.MaxWidth = 0
	ta.ShowLineNumbers = false
	ta.SetHeight(1)
	ta.FocusedStyle.Prompt = lipgloss.NewStyle().Foreground(Accent).Bold(true)
	ta.FocusedStyle.Placeholder = lipgloss.NewStyle().Foreground(Muted)
	ta.BlurredStyle.Placeholder = lipgloss.NewStyle().Foreground(Muted)
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle()
	ta.KeyMap.InsertNewline = key.NewBinding(key.WithKeys("ctrl+j"), key.WithHelp("ctrl+j", "newline"))
	ta.Focus()

	sp := spinner.New()
	sp.Spinner = spinner.Spinner{Frames: SpinnerFrames(), FPS: time.Second / 10}
	sp.Style = lipgloss.NewStyle().Foreground(Muted)

	hist := loadHistory()
	histDB := histstore.OpenDefault()
	cfg := loadConfig()
	rc, rcErr := newRetrievalClient(cfg)

	// Create a fresh session for this run. The transcript file is written lazily
	// on the first turn (session.go), so an unused launch leaves nothing on disk.
	sess, _ := newSession()
	title := "untitled"
	if sess != nil {
		title = "new session"
	}

	// /init: load ./.blk/context.md as ambient session context if present. The
	// muted "loaded" note is printed from Init.
	ambient, _ := loadInitContext()

	// The bubbles help defaults use dim grays and a unicode bullet and
	// ellipsis; route them through the theme.
	hp := help.New()
	hp.ShortSeparator = " " + Glyph(GlyphSep) + " "
	hp.Ellipsis = ellipsis()
	hp.Styles.ShortKey, hp.Styles.ShortDesc, hp.Styles.ShortSeparator = Meta, Meta, Meta
	hp.Styles.FullKey, hp.Styles.FullDesc, hp.Styles.FullSeparator = Meta, Meta, Meta
	hp.Styles.Ellipsis = Meta

	return model{
		ta:         ta,
		sp:         sp,
		help:       hp,
		keys:       defaultKeys(),
		history:    hist,
		histIdx:    len(hist),
		mode:       "rag",
		engageMode: secgate.Safe, // explicit: Safe is the zero value, but spell out the security default
		sess:       sess,
		hist:       histDB,
		sessTitle:  title,
		reasoning:  "medium",
		ambient:    ambient,
		prefs:      loadPrefs(),
		cfg:        cfg,
		rc:         rc,
		liveCache:  &liveCache{},
		rcErr:      rcErr,
		viz:        newVizRenderer(newMmdfluxRunner()),

		reduceMotion: reduceMotion(),
	}
}

func (m model) Init() tea.Cmd {
	w, _ := m.termSize()
	// The banner, the context note, and the first probe run in order, so the
	// down-service hint the probe can trigger prints under the banner.
	start := []tea.Cmd{tea.Println(welcomeBanner(w))}
	if strings.TrimSpace(m.ambient) != "" {
		start = append(start, tea.Println("   "+Meta.Render("loaded .blk/context.md")))
	}
	start = append(start, m.healthCmd())
	return tea.Batch(textarea.Blink, tea.Sequence(start...), resolveModelCmd)
}

// modelResolvedMsg carries the model a rag turn uses when none is picked.
type modelResolvedMsg string

// resolveModel records id as the model a rag turn uses when none is picked.
// The first resolution holds for the session, and an open /models panel
// follows it. An empty id changes nothing.
func (m model) resolveModel(id string) model {
	if m.resolvedModel != "" || id == "" {
		return m
	}
	m.resolvedModel = id
	if p, ok := m.overlay.(modelsPanel); ok && m.mode == "rag" {
		p.active = m.activeModel()
		m.overlay = p
	}
	return m
}

// resolveModelCmd lists the LLM server's models to learn the model a turn will
// use (see listedModel). It reports nothing when the list does not load.
func resolveModelCmd() tea.Msg {
	if id := listedModel(); id != "" {
		return modelResolvedMsg(id)
	}
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ta.SetWidth(max(msg.Width, 1))
		m.draftVertical = false
		m.resizeDraft()
		m.help.Width = max(msg.Width, 1)
		return m, nil

	case tea.KeyMsg:
		// One mode-capture at a time: an open overlay (picker /
		// @file) first, then Ctrl-R reverse search, then the slash palette. Each
		// leaves the others closed.
		//
		// An open overlay captures every key except quit. Esc is
		// handled inside the overlay (it cancels). The draft in the textarea is
		// left untouched, so it survives the overlay.
		// Any key other than ctrl+d disarms a pending quit confirmation.
		if !key.Matches(msg, m.keys.Quit) {
			m.quitArmed = ""
		}
		if m.overlay != nil {
			if key.Matches(msg, m.keys.Quit) {
				return m.handleQuit()
			}
			// Ctrl-C closes an overlay the same way Esc does.
			if key.Matches(msg, m.keys.Cancel) {
				msg = tea.KeyMsg{Type: tea.KeyEsc}
			}
			var cmd tea.Cmd
			m.overlay, cmd = m.overlay.Update(msg)
			return m, cmd
		}
		// Ctrl-R reverse-search captures every key while open.
		if m.rsearch.open {
			if key.Matches(msg, m.keys.Quit) {
				return m.handleQuit()
			}
			return m.reverseSearchKey(msg)
		}

		// Ctrl-C closes the slash palette the same way Esc does, leaving the draft
		// and any running turn alone.
		if m.pal.open && key.Matches(msg, m.keys.Cancel) {
			if nm, cmd, handled := m.paletteKey(tea.KeyMsg{Type: tea.KeyEsc}); handled {
				return nm, cmd
			}
		}

		// The key panel closes on "?" or esc and scrolls on up and down. Any other
		// key closes it and then does its normal job.
		if m.keyPanel {
			switch msg.String() {
			case "?", "esc":
				m.keyPanel, m.keyScroll = false, 0
				return m, nil
			case "up", "down", "pgup", "pgdown":
				return m.scrollKeyPanel(msg.String()), nil
			}
			m.keyPanel, m.keyScroll = false, 0
		}

		// Global keys that always apply, even while a turn runs.
		switch {
		case key.Matches(msg, m.keys.Cancel):
			return m.handleCancel()
		case key.Matches(msg, m.keys.Quit):
			return m.handleQuit()
		}

		// The palette intercepts navigation/complete/run keys while open, so up/down and
		// Enter drive it instead of history/submit.
		if m.pal.open {
			if nm, cmd, handled := m.paletteKey(msg); handled {
				return nm, cmd
			}
		}

		switch {
		case key.Matches(msg, m.keys.Esc):
			// Esc cancels a running turn like ctrl+c, but never arms the ctrl+c
			// double-press quit.
			if m.working {
				if m.cancel != nil {
					m.cancel()
				}
				return m, nil
			}
		case key.Matches(msg, m.keys.ReverseSearch):
			return m.openReverseSearch()
		case key.Matches(msg, m.keys.Editor):
			if !m.working {
				return m, m.editorCmd()
			}
		case key.Matches(msg, m.keys.ClearQueue):
			if len(m.queue) > 0 {
				return m.clearQueue()
			}
		case key.Matches(msg, m.keys.PickModel):
			// Ctrl-P opens the model picker without touching the input draft.
			if !m.working {
				return m, m.openModelPickerCmd()
			}
		case key.Matches(msg, m.keys.Help):
			// Only open the key panel when the input is empty, so "?" can be
			// typed inside a question. The panel handles the closing "?" itself.
			if !m.working && strings.TrimSpace(m.ta.Value()) == "" {
				m.keyPanel, m.keyScroll = true, 0
				return m, nil
			}
		case key.Matches(msg, m.keys.Submit):
			return m.submit()
		case key.Matches(msg, m.keys.HistPrev):
			if m.working || m.ta.LineCount() > 1 || len(m.draftRows()) > 1 {
				break // wrapped drafts use cursor navigation
			}
			return m.recallPrev(), nil
		case key.Matches(msg, m.keys.HistNext):
			if m.working || m.ta.LineCount() > 1 || len(m.draftRows()) > 1 {
				break
			}
			return m.recallNext(), nil
		}

		// @ at an empty draft opens the file picker. The "@" is not
		// inserted; the picker replaces it.
		if msg.String() == "@" && strings.TrimSpace(m.ta.Value()) == "" {
			return m.openFilePicker()
		}

		// Editing stays live even while a turn runs, so a prompt can be typed and
		// queued (queue-while-busy). Editing refreshes the command palette.
		return m.updateDraft(msg)

	case draftPasteMsg:
		return m.pasteDraft(msg)

	case spinner.TickMsg:
		if m.working {
			var cmd tea.Cmd
			m.sp, cmd = m.sp.Update(msg)
			return m, cmd
		}
		return m, nil

	case secondTickMsg:
		if !m.working || !m.reduceMotion || msg.gen != m.tickGen {
			return m, nil
		}
		return m, m.workTick()

	case vizTickMsg:
		if !m.working || m.engagement == nil || msg.gen != m.tickGen {
			return m, nil
		}
		return m, tea.Batch(m.vizCommitCmd(), m.candidateScanCmd(), m.vizTick())

	case vizBlockMsg:
		if msg.block == "" {
			return m, nil
		}
		return m, tea.Println(msg.block)

	case candidateScanMsg:
		// Announce each newly-seen exploit/post-ex candidate once. The diff and the
		// noticed-set mutation happen here (not in the scan command).
		if m.noticedCandidates == nil {
			m.noticedCandidates = map[string]bool{}
		}
		var cmds []tea.Cmd
		for _, t := range unnoticedCandidates(m.noticedCandidates, msg.cands) {
			m.noticedCandidates[t.ID] = true
			cmds = append(cmds, tea.Println(candidateNotice(t)))
		}
		if len(cmds) == 0 {
			return m, nil
		}
		return m, tea.Sequence(cmds...)

	case chunkMsg:
		if !m.working {
			return m, nil // stray token after cancel/done
		}
		m.appendLive(string(msg))
		m.workingVerb = "answering" + ellipsis()
		if m.firstTokAt.IsZero() {
			m.firstTokAt = time.Now()
		}
		m.liveTokens++
		return m, nil

	case personaMsg:
		if !m.working {
			return m, nil // stray persona cue after cancel/done
		}
		m.persona = string(msg)
		// Print the cue above the streaming answer; set the status token too.
		return m, tea.Println(Meta.Render(tuiPersonaCue(string(msg), plCurrentTier())))

	case stageMsg:
		if !m.working {
			return m, nil // stray stage after cancel/done
		}
		m.workingVerb = string(msg) + ellipsis()
		return m, nil

	case noResultsMsg:
		m.working = false
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		m.live = ""
		m.workingVerb = ""
		m.openTargets = nil
		return m, m.finish(tea.Println(formatNoResults()))

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
		cost := turnCost{completionTokens: msg.tokens, elapsed: elapsed, calls: msg.llmCalls, partial: msg.llmCallsPartial}
		if msg.agent {
			if msg.err != nil && errors.Is(msg.err, context.Canceled) {
				return m, tea.Println(canceledOutput(full, m.renderWidth()))
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
				return m, m.finish(tea.Println("   " + Meta.Render("(agent returned no output)")))
			}
			m.recordTurn(full)
			m.lastCost, m.lastCostSet = cost, true
			out := formatAgentAnswer(full, elapsed, m.renderWidth()) + "\n" + costFooter(cost)
			return m, m.finish(tea.Println(out))
		}
		if msg.err != nil {
			if errors.Is(msg.err, context.Canceled) {
				return m, tea.Println(canceledOutput(full, m.renderWidth()))
			}
			// Errored after streaming partial output. Commit what streamed, then
			// note the early end.
			m.servicesChecked = true
			var b strings.Builder
			if strings.TrimSpace(full) != "" {
				resp := &answerResponse{Answer: full, Citations: msg.citations, UsedWeb: msg.usedWeb}
				b.WriteString(formatAnswer(resp, elapsed, m.renderWidth(), msg.rerankOff))
				b.WriteByte('\n')
			}
			b.WriteString(styleErr(fmt.Errorf("stream ended early: %w", timeoutOrErr(msg.err))))
			return m, tea.Println(b.String())
		}
		m.lastAnswer = full
		m.openTargets = citationTargets(msg.citations)
		if msg.results != nil {
			m.lastQuery, m.lastResults = m.pendingQ, msg.results
		}
		m.servicesOK, m.servicesChecked = true, true
		m.recordTurn(full)
		m.lastCost, m.lastCostSet = cost, true
		resp := &answerResponse{Answer: full, Citations: msg.citations, UsedWeb: msg.usedWeb}
		out := formatAnswer(resp, elapsed, m.renderWidth(), msg.rerankOff) + "\n" + costFooter(cost)
		return m, m.finish(tea.Println(out))

	case webFindingMsg:
		return m, tea.Println(msg.Data)

	case webDoneMsg:
		m.working = false
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		m.live = ""
		m.workingVerb = ""
		if msg.Err != nil {
			return m, m.finish(tea.Println(styleErr(msg.Err)))
		}
		return m, m.finish(tea.Println(msg.Output))

	case engageDoneMsg:
		m.working = false
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		m.live = ""
		m.workingVerb = ""
		elapsed := time.Since(m.turnStart)
		if msg.err != nil {
			if errors.Is(msg.err, context.Canceled) {
				return m, m.finish(tea.Println("   " + Meta.Render("engagement stopped") + "\n" + msg.final))
			}
			if msg.paused {
				return m, m.finish(tea.Println(formatEngagePaused(msg.err.Error()+"\n\n"+msg.final, elapsed, m.renderWidth())))
			}
			return m, m.finish(tea.Println(formatEngageError(msg.final, fmt.Errorf("engage: %w", timeoutOrErr(msg.err)), m.renderWidth())))
		}
		if msg.paused {
			return m, m.finish(tea.Println(formatEngagePaused(msg.final, elapsed, m.renderWidth())))
		}
		return m, m.finish(tea.Println(formatEngageDone(msg.final, elapsed, m.renderWidth())))

	case webAnswerMsg:
		m.lastQuery, m.lastResults, m.pendingQ = msg.query, msg.results, msg.query
		m.workingVerb = stageAnswering
		return m, m.generateCmd(msg.ctx, msg.query, msg.results, m.turnStart)
	case searchMsg:
		m.working = false
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		m.openTargets = resultTargets(msg.results)
		// Retain this search so /generate can synthesize from exactly these chunks.
		m.lastQuery, m.lastResults = msg.query, msg.results
		if !msg.web {
			m.markRetrievalOK()
		}
		output := formatResults(msg.query, msg.results, msg.elapsed, m.renderWidth())
		if msg.json {
			encoded, err := formatWebJSON(searchResponse{Results: msg.results})
			if err != nil {
				return m, m.finish(tea.Println(styleErr(err)))
			}
			output = encoded
		}
		return m, m.finish(tea.Println(strings.TrimRight(output, "\n")))

	case healthReportMsg:
		m.working = false
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		m.servicesChecked = true
		m.servicesOK = msg.h.ok()
		m.health = msg.h
		return m, m.finish(tea.Println(formatHealth(msg.h, m.cfg)))

	case errMsg:
		m.working = false
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		if isUnreachable(msg.err) {
			m.servicesOK, m.servicesChecked = false, true
			m.health = nil // the last probe is stale, so do not name a service from it
		}
		var llmErr *llmUnreachableError
		if errors.As(msg.err, &llmErr) && llmErr.refused() {
			m.markLLMDown()
		}
		return m, tea.Println(styleErr(timeoutOrErr(msg.err)))

	case canceledMsg:
		m.working = false
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		partial := strings.TrimRight(m.live, "\n")
		m.live = ""
		m.workingVerb = ""
		return m, tea.Println(canceledOutput(partial, m.renderWidth()))

	case execDoneMsg:
		if msg.err != nil {
			return m, tea.Println(styleErr(msg.err))
		}
		return m, nil

	case healthMsg:
		h := msg.h
		if h != nil && h.LLM && msg.started.Before(m.llmDownAt) {
			// The probe began before a turn found the LLM refusing connections, so
			// its LLM-up result is stale. Keep the rest of what it found.
			c := *h
			c.LLM = false
			h = &c
		}
		m.servicesOK = h != nil && h.ok()
		m.servicesChecked = true
		m.health = h
		m.rerankUp = msg.rerank
		// Only the first probe of a session says what is down and how to fix it,
		// so a service that stays down does not repeat the line on every probe.
		first := !m.probeSeen
		m.probeSeen = true
		if first && h != nil && len(downServices(h)) > 0 {
			w, _ := m.termSize()
			return m, tea.Println(downHint(h, w))
		}
		return m, nil

	case agentToolMsg:
		if !m.working {
			return m, nil
		}
		line := " " + Meta.Render(Glyph(GlyphBullet)+" "+sanitizeTerminal(msg.verb+" "+msg.tool))
		if msg.verb == "running" {
			line += Meta.Render(ellipsis())
		}
		return m, tea.Println(line)

	case agentNoteMsg:
		if strings.TrimSpace(string(msg)) == "" {
			return m, nil
		}
		return m, tea.Println("   " + Meta.Render(oneLine(sanitizeTerminal(string(msg)))))

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

	case openModelPickerMsg:
		// A /resume or other overlay (or reverse-search/palette) may have opened
		// while this async discovery was in flight; don't clobber it.
		if m.overlay != nil || m.rsearch.open || m.pal.open {
			return m, nil
		}
		p := newModelPicker(msg.models, msg.current, msg.reasoning, m.width)
		switch {
		case msg.listErr != nil:
			p.hint = msg.listErr.Error()
		case msg.allHidden:
			p.hint = "every other model is hidden; run /models to show them"
		}
		m.overlay = p
		return m, nil

	case modelResolvedMsg:
		return m.resolveModel(string(msg)), nil

	case modelsDataMsg:
		// A list that loads before the model was resolved resolves it now, so
		// the panel marks and protects the model a turn uses.
		m = m.resolveModel(msg.listed)
		if p, ok := m.overlay.(modelsPanel); ok {
			var cmd tea.Cmd
			m.overlay, cmd = p.Update(msg)
			return m, cmd
		}
		return m, nil

	case modelActionDoneMsg:
		if p, ok := m.overlay.(modelsPanel); ok {
			var cmd tea.Cmd
			m.overlay, cmd = p.Update(msg)
			return m, cmd
		}
		// The panel closed while the load or unload ran: print the result.
		if msg.err != nil {
			return m, tea.Println(styleErr(fmt.Errorf("%s %s: %w", msg.action, msg.id, msg.err)))
		}
		return m, tea.Println("   " + Meta.Render(sanitizeTerminal(modelActionNote(msg.id, msg.action, msg.id == m.activeModel()))))

	case prefsChangedMsg:
		m.prefs = msg.prefs
		return m, savePrefsCmd(msg.prefs)

	case prefsSavedMsg:
		if msg.err == nil {
			return m, nil
		}
		err := fmt.Errorf("saving the model settings: %w", msg.err)
		if p, ok := m.overlay.(modelsPanel); ok {
			m.overlay = p.setNote(err.Error(), true)
			return m, nil
		}
		return m, tea.Println(styleErr(err))

	case modelsArgsDoneMsg:
		if msg.err != nil {
			return m, tea.Println(styleErr(msg.err))
		}
		if msg.sw == nil {
			return m, tea.Println("   " + Meta.Render(oneLine(sanitizeTerminal(msg.note))))
		}
		// Apply the switch to the settings as they are now, which may hold a
		// panel change made while the command ran, and keep an open panel in step.
		sw := msg.sw
		np, note, err := setModelSwitch(m.prefs, sw.kind, sw.id, sw.on, m.activeModel(), sw.webSet)
		if err != nil {
			return m, tea.Println(styleErr(err))
		}
		m.prefs = np
		if p, ok := m.overlay.(modelsPanel); ok {
			p.prefs = np
			m.overlay = p
		}
		return m, tea.Batch(tea.Println("   "+Meta.Render(oneLine(sanitizeTerminal(note)))), savePrefsCmd(np))

	case overlayCloseMsg:
		m.overlay = nil
		return m, textarea.Blink

	case clarifyMsg:
		// A clarify overlay already open is displaced: answer it as canceled so
		// its requester is not left blocked on the reply channel.
		var cancel tea.Cmd
		if old, ok := m.overlay.(clarifyPicker); ok && old.reply != nil {
			reply := old.reply
			cancel = func() tea.Msg {
				reply <- ClarifyResult{Canceled: true}
				return nil
			}
		}
		m.overlay = newClarifyPicker(msg.c, m.width, msg.reply)
		return m, cancel

	case clarifyResolvedMsg:
		// An intake overlay (pre-dispatch /engage) is driven by the model, not a
		// goroutine reply channel: advance the sequence instead of answering it.
		if m.engageIntake != nil && msg.reply == m.engageIntake.reply {
			return m.advanceEngageIntake(msg.res)
		}
		m.overlay = nil
		reply, res := msg.reply, msg.res
		// The send runs in a command so a slow receiver never blocks the loop.
		return m, tea.Batch(textarea.Blink, func() tea.Msg {
			if reply != nil {
				reply <- res
			}
			return nil
		})

	case confirmMsg:
		// A confirm overlay already open is displaced: deny it so its requester is
		// not left blocked on the reply channel.
		var cancel tea.Cmd
		if old, ok := m.overlay.(confirmPicker); ok && old.reply != nil {
			reply := old.reply
			cancel = func() tea.Msg {
				reply <- confirmResult{}
				return nil
			}
		}
		m.overlay = newConfirmPicker(msg.cmd, m.width, msg.reply)
		return m, cancel

	case confirmResolvedMsg:
		m.overlay = nil
		reply, res := msg.reply, msg.res
		// esc stops the engagement: cancel the running turn so the orchestrator
		// winds down after this denied command.
		if res.stop && m.cancel != nil {
			m.cancel()
		}
		// The send runs in a command so a slow receiver never blocks the loop.
		return m, tea.Batch(textarea.Blink, func() tea.Msg {
			if reply != nil {
				reply <- res
			}
			return nil
		})

	case armMsg:
		// A displaced arm request (new before the old is answered) fails safe: the
		// old request is answered ArmSkip so its executor is not left blocked.
		var cancel tea.Cmd
		if old, ok := m.overlay.(armPicker); ok && old.reply != nil {
			reply := old.reply
			cancel = func() tea.Msg {
				reply <- ArmSkip
				return nil
			}
		}
		m.overlay = newArmPicker(msg.task, msg.reply)
		return m, cancel

	case armResolvedMsg:
		m.overlay = nil
		reply, res := msg.reply, msg.res
		// ArmStop halts the engagement: cancel the running turn.
		if res == ArmStop && m.cancel != nil {
			m.cancel()
		}
		return m, tea.Batch(textarea.Blink, func() tea.Msg {
			if reply != nil {
				reply <- res
			}
			return nil
		})

	case historySelectedMsg:
		m.overlay = nil
		return m.openHistorySessionInto(msg.id)

	case modelSelectedMsg:
		m.overlay = nil
		return m.applyModel(msg.model, msg.reasoning)

	case fileSelectedMsg:
		m.overlay = nil
		content, err := readAttachment(msg.path)
		if err != nil {
			return m, tea.Println(styleErr(fmt.Errorf("attach: %w", err)))
		}
		m.attachments = append(m.attachments, attachment{path: msg.path, content: content})
		chip := " " + OK.Render(Glyph(GlyphOK)) + " " + Meta.Render("attached "+sanitizeTerminal(filepath.Base(msg.path)))
		return m, tea.Println(chip)

	case editorDoneMsg:
		return m.applyEditorResult(msg)

	case dequeueMsg:
		if m.working || len(m.queue) == 0 {
			return m, nil
		}
		next := m.queue[0]
		m.queue = m.queue[1:]
		return m.dispatchInput(next)
	}

	if m.overlay != nil {
		var cmd tea.Cmd
		m.overlay, cmd = m.overlay.Update(msg)
		return m, cmd
	}
	return m.updateDraft(msg)
}

// markRetrievalOK records a successful retrieval: qdrant and embed_server
// answered. It never touches the LLM field, so a known-down LLM keeps the dot
// down. With no probe result yet there is nothing to keep, and the dot is ok.
func (m *model) markRetrievalOK() {
	m.servicesChecked = true
	if m.health == nil {
		m.servicesOK = true
		return
	}
	h := *m.health
	h.Qdrant, h.EmbedServer = true, true
	m.health = &h
	m.servicesOK = h.ok()
}

// markLLMDown records that a turn found the LLM server refusing connections, so
// the status dot and label update without waiting for the next probe. Reaching
// the LLM stage means retrieval worked, so an unknown probe result starts from
// qdrant and embed_server up.
func (m *model) markLLMDown() {
	h := serviceHealth{Qdrant: true, EmbedServer: true}
	if m.health != nil {
		h = *m.health
	}
	h.LLM = false
	m.health = &h
	m.servicesOK, m.servicesChecked = false, true
	m.llmDownAt = time.Now()
}

// finish wraps a turn-completion command: when prompts are queued, it schedules
// the next one to auto-submit after the completion output is printed
// (queue-while-busy). A turn that ends by cancel or error returns its output
// without finish, so a Ctrl-C or a failed turn never auto-submits the next
// queued prompt; the queue is left intact either way.
func (m model) finish(cmd tea.Cmd) tea.Cmd {
	if len(m.queue) == 0 {
		return cmd
	}
	return tea.Batch(cmd, func() tea.Msg { return dequeueMsg{} })
}

// clearQueue drops all queued prompts with a muted note (Ctrl-U).
func (m model) clearQueue() (tea.Model, tea.Cmd) {
	n := len(m.queue)
	m.queue = nil
	return m, tea.Println("   " + Meta.Render(fmt.Sprintf("cleared %d queued", n)))
}

// handleCancel implements Ctrl-C: cancel a running turn, or clear a non-empty
// idle draft, with a second press within ctrlCWindow quitting. An empty idle
// draft gets the hint on the first press.
func (m model) handleCancel() (tea.Model, tea.Cmd) {
	now := time.Now()
	action := decideCtrlC(now, m.lastCtrlC, m.working, strings.TrimSpace(m.ta.Value()) == "")
	m.lastCtrlC = now
	switch action {
	case ccQuit:
		return m, tea.Quit
	case ccCancel:
		if m.cancel != nil {
			m.cancel()
		}
		return m, nil
	default: // ccClear, ccHint
		if action == ccClear {
			m.ta.Reset()
			m.draftTruncated, m.draftTop, m.draftVertical = false, 0, false
			m.ta.SetHeight(1)
			m.pal = palette{}
		}
		return m, tea.Println("   " + Meta.Render("(ctrl+c again to quit)"))
	}
}

// handleQuit implements Ctrl-D. With an empty draft and no running turn it quits
// at once. Otherwise the first press prints a hint and arms the quit for that
// state; a second press in the same state quits, and any other key disarms it.
func (m model) handleQuit() (tea.Model, tea.Cmd) {
	state := ""
	switch {
	case m.working:
		state = "turn"
	case strings.TrimSpace(m.ta.Value()) != "":
		state = "draft"
	}
	if state == "" || m.quitArmed == state {
		return m, tea.Quit
	}
	m.quitArmed = state
	return m, tea.Println("   " + Meta.Render("press ctrl+d again to quit"))
}

// canceledOutput is the scrollback text for a canceled turn: the partial answer,
// if any, through the same sanitizing markdown path a finished answer uses,
// then a muted canceled tag.
func canceledOutput(partial string, width int) string {
	tag := "   " + Meta.Render("canceled")
	if strings.TrimSpace(partial) == "" {
		return tag
	}
	return strings.TrimRight(glowRender(partial, width), "\n") + "\n" + tag
}

// ctrlCAction is the decision handleCancel makes for one Ctrl-C press.
type ctrlCAction int

const (
	ccCancel ctrlCAction = iota
	ccClear
	ccHint
	ccQuit
)

// decideCtrlC is the pure Ctrl-C decision: a press within ctrlCWindow of the last
// quits; otherwise a running turn is cancelled, a non-empty idle draft is cleared,
// and an empty idle draft prints the quit hint.
func decideCtrlC(now, last time.Time, working, draftEmpty bool) ctrlCAction {
	if !last.IsZero() && now.Sub(last) < ctrlCWindow {
		return ccQuit
	}
	if working {
		return ccCancel
	}
	if !draftEmpty {
		return ccClear
	}
	return ccHint
}

// activeModel is the model a turn really uses. In rag mode that is the model
// picked with /model, else the one resolved when the model list first loaded,
// and "" until one of those is known, so nothing is marked or protected as
// active by guesswork. In agent mode it is the agent's model.
func (m model) activeModel() string {
	if m.mode == "agent" {
		if m.agentModel != "" {
			return m.agentModel
		}
		return "unknown"
	}
	return m.ragTurnModel()
}

// ragTurnModel is the model a grounded turn uses, independent of mode:
// streamCmd serves forced grounded turns even in agent mode, so it must not
// use the agent model. "" until a model is known, so streamCmd's resolve
// fallback applies.
func (m model) ragTurnModel() string {
	if s := strings.TrimSpace(m.ragModel); s != "" {
		return s
	}
	return m.resolvedModel
}

// currentModel is the model id shown and recorded for the active mode: the
// active model, or the configured default until the model list has loaded.
func (m model) currentModel() string {
	if id := m.activeModel(); id != "" {
		return id
	}
	return m.cfg.DefaultModel
}

// startEngageIntake opens the guided /engage intake: it seeds the flow with any
// typed goal and opens the first clarify overlay (domain). Subsequent steps and
// dispatch are driven by advanceEngageIntake from the clarifyResolvedMsg handler.
func (m model) startEngageIntake(goal, echo string) (tea.Model, tea.Cmd) {
	f := &engageIntakeFlow{answers: engageIntakeAnswers{GoalPrefill: goal}, reply: make(chan ClarifyResult, 1)}
	m.engageIntake = f
	c, _ := f.clarification()
	m.overlay = newClarifyPicker(c, m.width, f.reply)
	return m, tea.Println(echo)
}

// advanceEngageIntake records one intake answer and either opens the next
// question or, when the sequence is complete, assembles the goal and dispatches
// the engagement. A canceled answer aborts the intake.
func (m model) advanceEngageIntake(res ClarifyResult) (tea.Model, tea.Cmd) {
	f := m.engageIntake
	if res.Canceled {
		m.engageIntake = nil
		m.overlay = nil
		return m, tea.Println("   " + Meta.Render("engage canceled"))
	}
	f.record(res)
	if c, ok := f.clarification(); ok {
		m.overlay = newClarifyPicker(c, m.width, f.reply)
		return m, nil
	}
	goal := f.goal()
	m.engageIntake = nil
	m.overlay = nil
	return m.dispatchEngage(goal)
}

// dispatchEngage builds the engage dependencies and starts the gated
// orchestrator for goal. HITL confirmation reads over a released terminal
// (reliable line input) rather than a Bubble Tea overlay, whose key events are
// unreliable in some terminals during a long engagement; stop cancels the turn.
func (m model) dispatchEngage(goal string) (tea.Model, tea.Cmd) {
	return m.dispatchEngageAt(goal, "", "")
}

func (m model) dispatchEngageAt(goal, wsDir, projectDir string) (tea.Model, tea.Cmd) {
	run, err := m.buildReplEngageRun(goal)
	if err != nil {
		return m, tea.Println(styleErr(err))
	}
	if wsDir != "" {
		run.wsDir = wsDir
		run.cwd = projectDir
	}
	m.working = true
	m.tickGen++
	m.workingVerb = workingVerbLabel("engage")
	m.live = ""
	m.turnStart = time.Now()
	m.liveTokens = 0
	m.firstTokAt = time.Time{}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	run.ctx = ctx
	run.confirm = releaseConfirmer{prog: m.prog, stop: cancel}
	stub := newStubEngagement("engagement")
	m.engagement = stub
	m.noticedCandidates = map[string]bool{}
	run.stub = stub
	if m.engageMode == secgate.Safe {
		// Mid-run clarifications read over a released terminal, like the confirm,
		// so follow-up questions work in any terminal during a long engagement.
		run.asker = releaseAsker{prog: m.prog}
	} else {
		run.asker = askuser.AutoAsker{}
	}
	return m, tea.Batch(m.workTick(), m.startVizPoll(), engageCmd(run))
}

// conversationHistory returns the full prior conversation for the current
// session, read from the persistent history store, so a rag turn can carry it
// back as memory. It is called before the current turn is recorded, so it holds
// only completed prior turns. The shared answer path compresses it to the budget
// when needed. Returns nil when there is no store or no session.
func (m model) conversationHistory() []priorTurn {
	if m.hist == nil || m.sess == nil {
		return nil
	}
	turns, err := m.hist.Messages(context.Background(), m.sess.id)
	if err != nil || len(turns) == 0 {
		return nil
	}
	pt := make([]priorTurn, len(turns))
	for i, t := range turns {
		pt[i] = priorTurn{Role: t.Role, Content: t.Content}
	}
	return pt
}

// recordTurn appends the completed user question and answer to the current
// session transcript. It is best-effort: a nil session or an IO error just skips
// persistence (an errSessionFull is surfaced as a muted note by the caller path).
func (m *model) recordTurn(answer string) {
	if m.sess == nil || strings.TrimSpace(m.pendingQ) == "" {
		return
	}
	model := m.currentModel()
	_ = m.sess.appendTurn(turnRecord{Role: roleUser, Content: m.pendingQ, Model: model, Mode: m.mode})
	_ = m.sess.appendTurn(turnRecord{Role: roleAssistant, Content: answer, Model: model, Mode: m.mode})
	if m.hist != nil {
		// Mirror the exchange into the persistent langchaingo memory, keyed by the
		// same session id. Best-effort: a write error just skips persistence.
		ctx := context.Background()
		_ = m.hist.AppendUser(ctx, m.sess.id, m.pendingQ)
		_ = m.hist.AppendAI(ctx, m.sess.id, answer)
	}
	if m.sess.title != "" {
		m.sessTitle = m.sess.title
	}
	m.pendingQ = ""
}

// applyModel applies a model-picker selection to subsequent turns and refreshes
// the status-line health for the active mode.
func (m model) applyModel(modelID, reasoning string) (tea.Model, tea.Cmd) {
	if strings.TrimSpace(reasoning) != "" {
		m.reasoning = reasoning
	}
	if m.mode == "agent" {
		if strings.TrimSpace(modelID) != "" {
			m.agentModel = modelID
		}
	} else {
		m.ragModel = strings.TrimSpace(modelID)
	}
	note := "   " + Meta.Render(joinSep("model: "+sanitizeTerminal(m.currentModel()), "reasoning: "+m.reasoning))
	return m, tea.Batch(tea.Println(note), m.modeSwitchCmd())
}

// openSessionInto loads a saved session's transcript, replays it into scrollback
// (styled like live turns), and makes it the current session.
func (m model) openSessionInto(id string) (tea.Model, tea.Cmd) {
	recs, err := loadMessages(id)
	if err != nil {
		return m, tea.Println(styleErr(fmt.Errorf("resume: %w", err)))
	}
	s, err := openSession(id)
	if err != nil {
		return m, tea.Println(styleErr(fmt.Errorf("resume: %w", err)))
	}
	m.sess = s
	m.sessTitle = s.title
	if m.sessTitle == "" {
		m.sessTitle = s.id
	}

	cmds := []tea.Cmd{tea.Println(" " + Meta.Render("resumed session: "+sanitizeTerminal(m.sessTitle)))}
	for _, r := range recs {
		switch r.Role {
		case roleUser:
			cmds = append(cmds, tea.Println(promptEcho(r.Content)))
		case roleAssistant:
			cmds = append(cmds, tea.Println(formatReplayAnswer(r.Content, m.renderWidth())))
		}
	}
	return m, tea.Sequence(cmds...)
}

// openHistorySessionInto reopens a session chosen in the /history picker and
// makes it current so the conversation can continue. It prefers the JSONL
// transcript (rich replay that honors /undo) via openSessionInto, and falls back
// to the langchaingo memory for a session that never wrote JSONL, such as an
// ingested engage run.
func (m model) openHistorySessionInto(id string) (tea.Model, tea.Cmd) {
	if sessionExists(id) {
		return m.openSessionInto(id)
	}
	if m.hist == nil {
		return m, tea.Println(styleErr(fmt.Errorf("history: persistent memory is unavailable")))
	}
	msgs, err := m.hist.Messages(context.Background(), id)
	if err != nil {
		return m, tea.Println(styleErr(fmt.Errorf("history: %w", err)))
	}
	s, err := attachSession(id)
	if err != nil {
		return m, tea.Println(styleErr(fmt.Errorf("history: %w", err)))
	}
	m.sess = s
	m.sessTitle = s.title
	if m.sessTitle == "" {
		m.sessTitle = s.id
	}

	cmds := []tea.Cmd{tea.Println(" " + Meta.Render("opened from history: "+sanitizeTerminal(m.sessTitle)))}
	for _, r := range msgs {
		switch r.Role {
		case histstore.RoleUser:
			cmds = append(cmds, tea.Println(promptEcho(r.Content)))
		case histstore.RoleAI:
			cmds = append(cmds, tea.Println(formatReplayAnswer(r.Content, m.renderWidth())))
		}
	}
	return m, tea.Sequence(cmds...)
}

// historyClear handles "/history clear" (erase every stored session) and
// "/history clear [n]" (erase the nth session, newest first, matching the
// picker's 1-9 numbering). It erases from both the langchaingo store and the
// JSONL transcripts. Erasing all is immediate and irreversible.
func (m model) historyClear(echo string, args []string) (tea.Model, tea.Cmd) {
	ctx := context.Background()
	hs, err := m.hist.Sessions(ctx)
	if err != nil {
		return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(fmt.Errorf("history: %w", err))))
	}
	if len(args) == 0 {
		purgeAllHistory(m.hist)
		return m, tea.Sequence(tea.Println(echo), tea.Println("   "+Meta.Render(fmt.Sprintf("cleared all history (%d sessions)", len(hs)))))
	}
	idx, err := strconv.Atoi(args[0])
	if err != nil || idx < 1 {
		return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(fmt.Errorf("history: clear takes a session number, got %q", args[0]))))
	}
	if idx > len(hs) {
		return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(fmt.Errorf("history: no session %d (have %d)", idx, len(hs)))))
	}
	purgeHistorySession(m.hist, hs[idx-1].ID)
	return m, tea.Sequence(tea.Println(echo), tea.Println("   "+Meta.Render(fmt.Sprintf("cleared session %d", idx))))
}

// submit handles the Enter key: consume the draft, record history, then either
// queue it (while a turn runs) or dispatch it immediately.
func (m model) submit() (tea.Model, tea.Cmd) {
	q := strings.TrimSpace(m.ta.Value())
	if q == "" {
		return m, nil
	}
	m.ta.Reset()
	m.draftTruncated, m.draftTop, m.draftVertical = false, 0, false
	m.ta.SetHeight(1)
	m.pal = palette{}
	_ = appendHistory(q)
	m.history = append(m.history, q)
	if len(m.history) > historyMaxEntries {
		m.history = m.history[len(m.history)-historyMaxEntries:]
	}
	m.histIdx = len(m.history)
	m.histDraft = ""

	// Queue-while-busy: while a turn runs, a plain question (or a
	// turn-starting slash command) is queued FIFO instead of erroring; other slash
	// commands run immediately (mode switch, pickers, /help, /clear, ...).
	verb, arg := parseInput(q)
	turn := isTurnVerb(verb)
	if verb == "web" {
		c, err := parseWebCommand(strings.Fields(arg))
		turn = err == nil && c.action == "search"
	}
	if m.working && turn {
		m.queue = append(m.queue, q)
		note := "   " + Meta.Render(fmt.Sprintf("%s queued (%d in queue)", Glyph(GlyphBullet), len(m.queue)))
		return m, tea.Println(note)
	}
	return m.dispatchInput(q)
}

// isTurnVerb reports whether a verb starts a network turn (and so must queue
// rather than run concurrently while another turn is in flight).
func isTurnVerb(v string) bool {
	return v == "ask" || v == "search" || v == "health" || v == "generate"
}

// vizNext applies a /viz argument to the current setting. ok is false for an
// argument that is not on, off, toggle, or empty.
func vizNext(cur bool, arg string) (on, ok bool) {
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "on":
		return true, true
	case "off":
		return false, true
	case "", "toggle":
		return !cur, true
	}
	return cur, false
}

// vizNote is the confirmation line printed after /viz.
func vizNote(on bool) string {
	if on {
		return "viz: on"
	}
	return "viz: off (diagram and bar hidden)"
}

// dispatchInput parses one input line, echoes it to scrollback, and runs the
// matching command. It never touches the draft/history/queue (submit and the
// dequeue handler own those).
func (m model) dispatchInput(q string) (tea.Model, tea.Cmd) {
	verb, arg := parseInput(q)
	echo := promptEcho(q)
	groundSearch := verb == "search"
	if groundSearch {
		verb = "ask"
	}
	webOnly := false
	if verb == "ask" {
		if first, rest := splitFirst(arg); first == "--web" {
			webOnly, arg = true, rest
		}
	}
	switch verb {
	case "quit":
		return m, tea.Quit
	case "help":
		w, _ := m.termSize()
		return m, tea.Sequence(tea.Println(echo), tea.Println(helpResponse(arg, w)))
	case "mode":
		if m.mode == "agent" {
			m.mode = "rag"
		} else {
			m.mode = "agent"
		}
		return m, tea.Batch(tea.Sequence(tea.Println(echo), tea.Println(modeNote(m.mode))), m.modeSwitchCmd())
	case "safe":
		m.engageMode = secgate.Safe
		m.engageOverride = false
		m.engageHITL = false
		return m, tea.Sequence(tea.Println(echo), tea.Println("   "+Meta.Render("safe: every command is confirmed before it runs")))
	case "auto":
		m.engageMode = secgate.Auto
		m.engageOverride = strings.EqualFold(strings.TrimSpace(arg), "override")
		cwd, _ := os.Getwd()
		m.engageHITL = unattendedBoundEmpty(cwd)
		return m, tea.Sequence(tea.Println(echo), tea.Println("   "+Meta.Render(autoModeNote(m.engageOverride, scopeDetected(cwd)))))
	case "agent":
		m.mode = "agent"
		return m, tea.Batch(tea.Sequence(tea.Println(echo), tea.Println(modeNote(m.mode))), m.modeSwitchCmd())
	case "rag":
		toggle, on, question := ragArg(arg)
		switch {
		case toggle:
			m.prefs.Rag = on
			_ = savePrefs(m.prefs)
			return m, tea.Sequence(tea.Println(echo), tea.Println("   "+Meta.Render("rag "+boolOnOff(on))))
		case question != "":
			// A force-ground question is a turn: while one runs, queue the raw
			// input (dequeueMsg replays it through dispatchInput). Otherwise set
			// the one-shot and run it as an ask.
			if m.working {
				m.queue = append(m.queue, q)
				return m, tea.Println("   " + Meta.Render(fmt.Sprintf("%s queued (%d in queue)", Glyph(GlyphBullet), len(m.queue))))
			}
			m.forceRag = true
			return m.dispatchInput("/ask " + question)
		default:
			m.mode = "rag"
			return m, tea.Batch(tea.Sequence(tea.Println(echo), tea.Println(modeNote(m.mode))), m.modeSwitchCmd())
		}
	case "candidates":
		return m, tea.Sequence(tea.Println(echo), tea.Println(candidatesBlock(m.engagement)))
	case "evidence":
		return m, tea.Sequence(tea.Println(echo), tea.Println(evidenceBlock(m.engagement)))
	case "kg":
		return m, tea.Sequence(tea.Println(echo), tea.Println(kgBlock(arg)))
	case "copy":
		return m, tea.Sequence(tea.Println(echo), tea.Println(m.doCopy()))
	case "history":
		if m.hist == nil {
			return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(fmt.Errorf("history: persistent memory is unavailable"))))
		}
		if fields := strings.Fields(arg); len(fields) > 0 {
			if fields[0] == "clear" {
				return m.historyClear(echo, fields[1:])
			}
			return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(fmt.Errorf("history: unknown option %q; use /history or /history clear [n]", arg))))
		}
		hs, err := m.hist.Sessions(context.Background())
		if err != nil {
			return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(fmt.Errorf("history: %w", err))))
		}
		titles := map[string]string{}
		if metas, err := listSessions(); err == nil {
			for _, meta := range metas {
				titles[meta.ID] = meta.Title
			}
		}
		hp := newHistoryPicker(mergeHistoryMetas(hs, titles), m.sessID(), m.width)
		hp.store = m.hist
		hp.titles = titles
		m.overlay = hp
		return m, tea.Println(echo)
	case "model":
		return m, tea.Batch(tea.Println(echo), m.openModelPickerCmd())
	case "models":
		if strings.TrimSpace(arg) == "" {
			m.overlay = newModelsPanel(m.prefs, m.activeModel())
			return m, tea.Batch(tea.Println(echo), fetchModelsCmd)
		}
		verb, name, err := parseModelsArgs(arg)
		if err != nil {
			return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(err)))
		}
		cmds := []tea.Cmd{tea.Println(echo)}
		if verb == "load" {
			cmds = append(cmds, tea.Println("   "+Meta.Render("loading can take a few minutes; the result prints here")))
		}
		return m, tea.Sequence(append(cmds, modelsArgsCmd(verb, name, m.activeModel()))...)
	case "viz":
		on, ok := vizNext(m.prefs.Viz, arg)
		if !ok {
			return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(fmt.Errorf("viz: use on or off"))))
		}
		m.prefs.Viz = on
		_ = savePrefs(m.prefs)
		return m, tea.Sequence(tea.Println(echo), tea.Println("   "+Meta.Render(vizNote(on))))
	case "attach":
		return m.openFilePickerEcho(echo)
	case "editor":
		return m, tea.Sequence(tea.Println(echo), m.editorCmd())
	case "init":
		return m.reloadInit(echo)
	case "cost":
		return m, tea.Sequence(tea.Println(echo), tea.Println(m.costLine()))
	case "undo":
		return m.undo(echo)
	case "clear":
		return m.clearScrollback(echo)
	case "title":
		return m.retitle(echo, arg)
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
	case "web":
		args, err := webArguments(arg)
		if err != nil {
			return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(err)))
		}
		c, err := parseWebCommand(args)
		if err != nil {
			return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(err)))
		}
		if c.action != "search" {
			p, note, err := applyWebCommand(loadPrefs(), c)
			if err != nil {
				return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(err)))
			}
			m.prefs = p
			if panel, ok := m.overlay.(modelsPanel); ok {
				panel.prefs = p
				m.overlay = panel
			}
			if c.json {
				output, err := formatWebJSON(webReport(p))
				if err != nil {
					return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(err)))
				}
				return m, tea.Sequence(tea.Println(echo), tea.Println(output))
			}
			return m, tea.Sequence(tea.Println(echo), tea.Println("   "+Meta.Render(note)))
		}
		m.working, m.workingVerb = true, stageWeb
		m.tickGen++
		m.turnStart = time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), m.cfg.RequestTimeout())
		m.cancel = cancel
		return m, tea.Batch(tea.Println(echo), m.workTick(), func() tea.Msg {
			results, err := webSearchResults(ctx, c)
			if err != nil {
				if ctx.Err() == context.Canceled {
					return canceledMsg{}
				}
				return errMsg{err}
			}
			if c.json {
				return searchMsg{query: c.value, results: results, elapsed: time.Since(m.turnStart), web: true, json: true}
			}
			return webAnswerMsg{query: c.value, results: results, ctx: ctx}
		})
	case "search", "ask", "health":
		if (verb == "search" || verb == "ask") && strings.TrimSpace(arg) == "" {
			return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(fmt.Errorf("%s: give me something to %s", verb, verb))))
		}
		m.working = true
		m.tickGen++
		m.workingVerb = workingVerbLabel(verb)
		m.live = ""
		m.turnStart = time.Now()
		m.liveTokens = 0
		m.firstTokAt = time.Time{}
		var ctx context.Context
		var cancel context.CancelFunc
		if verb == "ask" && m.mode == "agent" && !m.forceRag && !groundSearch && !webOnly {
			// Agent turns can run for a long time (multi-step tool use) and
			// StreamAgent assumes a long-lived ctx; only Ctrl-C should end one,
			// not the RAG client's HTTP timeout.
			ctx, cancel = context.WithCancel(context.Background())
		} else {
			// ask can be slow on a large local model, so bound the turn by the
			// configured request timeout (BLKCHAIN_TIMEOUT_SECONDS).
			ctx, cancel = context.WithTimeout(context.Background(), m.cfg.RequestTimeout())
		}
		m.cancel = cancel
		if verb == "ask" {
			// @file attachments + /init ambient context ride along with this turn.
			preface := m.buildContextPreface()
			m.attachments = nil // one-shot: consumed by this turn
			m.pendingQ = arg    // the operator's question, recorded to the session
			// AGENT mode: a full agentic turn via the gateway (or subprocess
			// fallback), streaming into the same live buffer.
			if m.mode == "agent" && !m.forceRag && !groundSearch && !webOnly {
				message := arg
				if preface != "" {
					message = preface + "\n\n" + arg
				}
				return m, tea.Batch(tea.Println(echo), m.workTick(), m.startVizPoll(), m.agentStreamCmd(ctx, message))
			}
			// RAG mode: route through the adaptive router (skip/ground/web).
			force := m.forceRag || groundSearch
			m.forceRag = false
			m.persona = "" // cleared for the new turn; set when its persona cue arrives
			return m, tea.Batch(tea.Println(echo), m.workTick(), m.startVizPoll(), m.streamCmd(ctx, arg, preface, m.turnStart, force, webOnly))
		}
		return m, tea.Batch(tea.Println(echo), m.workTick(), m.startVizPoll(), m.dispatchCmd(ctx, verb, arg, m.turnStart))
	case "generate":
		// Synthesize an answer from the LAST /search results, with no re-retrieval.
		if len(m.lastResults) == 0 {
			return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(errors.New("generate: nothing retrieved yet; run /search first"))))
		}
		question := generateQuestion(arg, m.lastQuery)
		results := m.lastResults
		m.working = true
		m.tickGen++
		m.workingVerb = workingVerbLabel("generate")
		m.persona = ""
		m.live = ""
		m.turnStart = time.Now()
		m.liveTokens = 0
		m.firstTokAt = time.Time{}
		ctx, cancel := context.WithTimeout(context.Background(), m.cfg.RequestTimeout())
		m.cancel = cancel
		m.pendingQ = question
		return m, tea.Batch(tea.Println(echo), m.workTick(), m.startVizPoll(), m.generateCmd(ctx, question, results, m.turnStart))
	case "engage":
		parts := strings.Fields(arg)
		if len(parts) > 0 && parts[0] == "web" {
			return m.dispatchWeb(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(arg), "web")), echo)
		}
		if strings.TrimSpace(arg) == "resume" || strings.HasPrefix(strings.TrimSpace(arg), "resume ") {
			workspace := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(arg), "resume"))
			if workspace == "" {
				var err error
				workspace, err = latestEngagementDir()
				if err != nil {
					return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(err)))
				}
			}
			checkpoint, err := loadEngageCheckpoint(workspace)
			if err != nil {
				return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(err)))
			}
			m.engageMode = secgate.Safe
			if checkpoint.Auto {
				m.engageMode = secgate.Auto
			}
			m.engageOverride = checkpoint.AutoOverride
			nm, cmd := m.dispatchEngageAt(checkpoint.Goal, workspace, checkpoint.ProjectDir)
			return nm, tea.Batch(tea.Println(echo), cmd)
		}
		// A goal that already names a target is clear enough to dispatch; otherwise
		// run the guided intake (domain, target, interactivity) at idle, where key
		// input is reliable, to shape the goal before any run.
		goal := strings.TrimSpace(arg)
		if goalHasTarget(goal) {
			nm, cmd := m.dispatchEngage(goal)
			return nm, tea.Batch(tea.Println(echo), cmd)
		}
		return m.startEngageIntake(goal, echo)
	}
	// Unknown /verb.
	return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(fmt.Errorf("unknown command /%s, try /help", verb))))
}

// openFilePickerEcho echoes the /attach command then opens the file picker.
func (m model) openFilePickerEcho(echo string) (tea.Model, tea.Cmd) {
	nm, _ := m.openFilePicker()
	return nm, tea.Println(echo)
}

// reloadInit re-runs /init: reload ./.blk/context.md into the ambient context.
func (m model) reloadInit(echo string) (tea.Model, tea.Cmd) {
	ctx, ok := loadInitContext()
	if !ok {
		return m, tea.Sequence(tea.Println(echo), tea.Println("   "+Meta.Render("no .blk/context.md in this directory")))
	}
	m.ambient = ctx
	return m, tea.Sequence(tea.Println(echo), tea.Println("   "+Meta.Render("loaded .blk/context.md")))
}

// costLine renders the /cost command output: the last turn's footer, or a note
// when no turn has completed yet.
func (m model) costLine() string {
	if !m.lastCostSet {
		return "   " + Meta.Render("no turn yet")
	}
	return costDetails(m.lastCost)
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
	m.setDraft(m.history[m.histIdx])
	m.ta.CursorEnd()
	return m
}

func (m model) recallNext() model {
	if m.histIdx >= len(m.history) {
		return m
	}
	m.histIdx++
	if m.histIdx == len(m.history) {
		m.setDraft(m.histDraft)
	} else {
		m.setDraft(m.history[m.histIdx])
	}
	m.ta.CursorEnd()
	return m
}

func (m model) View() string {
	w, h := m.termSize()
	// The status line collapses once, but a long model or health label can still
	// overshoot a narrow terminal, so cut it to the width.
	status := lipgloss.NewStyle().MaxWidth(w).Render(m.statusLine())
	footer := m.footer()
	var b strings.Builder
	b.WriteString(status)
	b.WriteByte('\n')
	if m.overlay != nil {
		b.WriteString(m.overlay.View(w, h))
	} else {
		// One row budget: the terminal height minus the status line, the spinner
		// line while a turn runs, and the footer. The input area (a multi-line
		// draft or the palette) takes its share of it first; the live region
		// above the input gets the rest, and is omitted when nothing is left.
		spin := ""
		if m.working {
			if spin = m.vizBar(); spin == "" {
				spin = m.spinnerLine()
			}
		}
		budget := h - lipgloss.Height(status) - lipgloss.Height(footer)
		if spin != "" {
			budget -= lipgloss.Height(spin)
		}
		input := m.inputView(w, budget)
		// While a turn runs, show the spinner + live region ABOVE the input, so a
		// prompt can still be typed and queued (queue-while-busy).
		// A long stream never pushes the status line and spinner off screen.
		if m.working {
			b.WriteString(spin)
			if rows := budget - lipgloss.Height(input); rows > 0 {
				if lr := m.liveRegion(rows); lr != "" {
					b.WriteByte('\n')
					b.WriteString(lr)
				}
			}
			b.WriteByte('\n')
		}
		b.WriteString(input)
	}
	b.WriteByte('\n')
	b.WriteString(footer)
	return b.String()
}

// inputView renders the input area within budget rows: the reverse-search
// prompt, or the draft with the palette above it, or the draft with the input
// limit notice. The draft is cut to the rows the budget allows (at least one)
// and gets them first; the palette is clamped to what the draft leaves, and the
// notice is dropped when there is no row for it.
func (m model) inputView(w, budget int) string {
	if m.rsearch.open {
		return m.reverseSearchView()
	}
	want := m.ta.Height()
	rows := clamp(want, 1, max(budget, 1))
	if rows != want {
		m.ta.SetHeight(rows)
		defer m.ta.SetHeight(want)
	}
	draft := m.draftView()
	left := budget - rows
	if m.pal.open {
		if pv := m.paletteView(w, left); pv != "" {
			return pv + "\n" + draft
		}
		return draft
	}
	if m.keyPanelShown() {
		if kv := m.keyPanelView(w, left); kv != "" {
			return kv + "\n" + draft
		}
		return draft
	}
	if n := m.limitNotice(); n != "" && left >= 1 {
		return draft + "\n" + n
	}
	return draft
}

// liveRegion renders the in-progress streamed answer under a Muted left "|"
// bar. It shows raw tokens (glamour-rendered only once the turn completes, in
// the streamDoneMsg handler). Empty when nothing has streamed yet.
//
// maxRows caps the region (0 means no cap). When the text is taller, the tail
// is shown, where new tokens arrive, under a one-row indicator counting the
// hidden earlier lines; a cap of 1 shows the newest line alone.
func (m model) liveRegion(maxRows int) string {
	if strings.TrimSpace(m.live) == "" {
		return ""
	}
	termW, _ := m.termSize()
	bar := Meta.Render(Glyph(GlyphBar))
	// The text is wrapped at the width left after the " | " prefix, hard-breaking
	// any token longer than that; only the visible tail is styled.
	wrapW := clamp(termW-3, 1, 100)
	c := m.liveCache
	if c == nil {
		c = &liveCache{}
	}
	done, tail := c.wrapped(m.live, wrapW)
	total := len(done) + len(tail)
	line := func(i int) string {
		if i < len(done) {
			return done[i]
		}
		return tail[i-len(done)]
	}
	first, hidden := 0, 0
	if maxRows > 0 && total > maxRows {
		if maxRows == 1 {
			first = total - 1
		} else {
			hidden = total - (maxRows - 1)
			first = hidden
		}
	}
	var b strings.Builder
	if hidden > 0 {
		noun := "lines"
		if hidden == 1 {
			noun = "line"
		}
		note := ellipsize(fmt.Sprintf("... %d earlier %s hidden", hidden, noun), wrapW)
		b.WriteString(" " + bar + " " + Meta.Render(note))
	}
	for i := first; i < total; i++ {
		if i > first || hidden > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(" " + bar + " " + Body.Render(strings.TrimRight(line(i), " ")))
	}
	// Guard for terminals narrower than the prefix itself.
	if termW < 4 {
		return lipgloss.NewStyle().MaxWidth(termW).Render(b.String())
	}
	return b.String()
}

// liveCache is the streamed answer's incremental state, shared by the copies
// of one session's model. Update appends each chunk to raw, so the stream
// grows without copying (m.live is raw.String()). The live region sanitizes
// and wraps only what arrived since the last frame: complete lines are wrapped
// once and kept, and only the unfinished last line is wrapped per frame.
type liveCache struct {
	raw strings.Builder

	src   string     // the prefix of the stream consumed so far
	ts    termStream // sanitizes across chunks, holding back a split sequence
	clean []byte     // the sanitized text consumed so far
	width int        // the wrap width of lines
	lines []string   // the wrapped lines of clean[:done]
	done  int        // clean[:done] ends at a line break
	blank int        // how many of lines' last source lines were empty
}

// appendLive adds a streamed chunk to m.live.
func (m *model) appendLive(chunk string) {
	c := m.liveCache
	if c == nil {
		m.live += chunk
		return
	}
	// The builder follows m.live unless something else set m.live.
	if c.raw.Len() != len(m.live) || c.raw.String() != m.live {
		c.raw.Reset()
		c.raw.WriteString(m.live)
	}
	c.raw.WriteString(chunk)
	m.live = c.raw.String()
}

// wrapped returns live sanitized and wrapped at width: the lines of the text up
// to its last line break, then the lines of the rest. Trailing empty lines are
// left out, as they carry nothing to show yet. A live that does not extend the
// last one starts over, and a new width re-wraps the kept text.
func (c *liveCache) wrapped(live string, width int) (done, tail []string) {
	if !strings.HasPrefix(live, c.src) {
		*c = liveCache{}
	}
	if width != c.width {
		c.width, c.lines, c.done, c.blank = width, nil, 0, 0
	}
	c.clean = append(c.clean, c.ts.Write(live[len(c.src):])...)
	c.src = live

	if end := bytes.LastIndexByte(c.clean, '\n'); end >= c.done {
		for _, src := range strings.Split(string(c.clean[c.done:end]), "\n") {
			if src == "" {
				c.blank++
				c.lines = append(c.lines, "")
				continue
			}
			c.blank = 0
			c.lines = append(c.lines, wrapLive(src, width)...)
		}
		c.done = end + 1
	}
	if rest := string(c.clean[c.done:]); rest != "" {
		return c.lines, wrapLive(rest, width)
	}
	return c.lines[:len(c.lines)-c.blank], nil
}

// wrapLive wraps one line of text at width, hard-breaking a longer token.
func wrapLive(s string, width int) []string {
	return strings.Split(lipgloss.NewStyle().Width(width).Render(s), "\n")
}

// --- async dispatch ---

// dispatchCmd runs the network call for search/health in a goroutine and
// selects it against ctx, so a Ctrl+C (which calls cancel) surfaces a
// canceledMsg immediately even though the underlying search or native health
// probe keeps running until its own timeout. A deadline exceeded is reported as a
// one-line timeout error. ask is handled separately by streamCmd (always the
// full AnswerLoop, never this dispatcher).
func (m model) dispatchCmd(ctx context.Context, verb, arg string, start time.Time) tea.Cmd {
	return func() tea.Msg {
		ch := make(chan tea.Msg, 1)
		go func() {
			switch verb {
			case "search":
				rc, err := m.retrievalClient()
				if err != nil {
					ch <- errMsg{err}
					return
				}
				results, err := rc.Search(ctx, arg, 0, nil)
				if err != nil {
					ch <- errMsg{err}
					return
				}
				ch <- searchMsg{query: arg, results: results, elapsed: time.Since(start)}
			case "health":
				ch <- healthReportMsg{h: nativeHealth(m.cfg, m.rc)}
			}
		}()
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				return errMsg{errRequestTimeout}
			}
			return canceledMsg{}
		case msg := <-ch:
			return msg
		}
	}
}

// streamCmd runs the adaptive answer in a goroutine (tea.Cmd), pushing each
// token back as a chunkMsg via the stored *tea.Program. The router picks skip,
// ground, or web; force grounds unconditionally. The grounded path is the full
// bounded AnswerLoop (grade, optional web fallback or rewrite, then synthesis);
// a cancel returns a canceledMsg.
func (m model) streamCmd(ctx context.Context, question, preface string, start time.Time, force bool, explicitWeb ...bool) tea.Cmd {
	webOnly := len(explicitWeb) > 0 && explicitWeb[0]
	prog := m.prog
	turnModel := m.ragTurnModel()
	return func() tea.Msg {
		ctx, metrics := withCallMetrics(ctx)
		if turnModel == "" {
			// The list has not loaded yet: resolve the model here, and keep it
			// for the session.
			if turnModel = listedModel(); turnModel != "" && prog != nil {
				prog.Send(modelResolvedMsg(turnModel))
			}
		}
		var rc *retrieval.Client
		var err error
		if !webOnly {
			rc, err = m.retrievalClient()
			if err != nil {
				return errMsg{err}
			}
		}
		cfg := m.cfg
		streamed := false
		p := loadPrefs()
		full, cits, usedWeb, results, tokens, _, err := adaptiveAnswerFn(ctx, rc, cfg, question, askRoutes(p), force, AnswerOpts{
			Model:   turnModel,
			Preface: preface,
			NoWeb:   !p.Web,
			WebOnly: webOnly,
			History: m.conversationHistory(),
			Persona: func(domain string) {
				if prog != nil {
					prog.Send(personaMsg(domain))
				}
			},
			Stream: func(b []byte) {
				streamed = true
				if prog != nil {
					prog.Send(chunkMsg(string(b)))
				}
			},
			Stage: func(stage string) {
				if prog != nil {
					prog.Send(stageMsg(stage))
				}
			},
		})
		if errors.Is(err, ErrNoResults) {
			return noResultsMsg{}
		}
		if err != nil && !streamed {
			if errors.Is(err, context.Canceled) {
				return canceledMsg{}
			}
			return errMsg{timeoutOrErr(err)}
		}
		calls, partial := metrics.snapshot()
		return streamDoneMsg{full: full, citations: cits, usedWeb: usedWeb, results: results, rerankOff: rc != nil && rc.SkipRerank, err: err, tokens: tokens, llmCalls: calls, llmCallsPartial: partial}
	}
}

// synthFromResultsFn allows tests to substitute result synthesis.
var synthFromResultsFn = SynthesizeFromResults

// generateCmd synthesizes an answer from the given retrieved results (the last
// /search), streaming each token back as a chunkMsg like streamCmd. It does no
// retrieval or grading; grounding is exactly the results passed in. A cancel
// returns a canceledMsg; ErrNoResults becomes a noResultsMsg.
func (m model) generateCmd(ctx context.Context, question string, results []retrieval.Result, start time.Time) tea.Cmd {
	prog := m.prog
	turnModel := m.ragTurnModel()
	cfg := m.cfg
	return func() tea.Msg {
		ctx, metrics := withCallMetrics(ctx)
		if turnModel == "" {
			if turnModel = listedModel(); turnModel != "" && prog != nil {
				prog.Send(modelResolvedMsg(turnModel))
			}
		}
		streamed := false
		full, cits, tokens, err := synthFromResultsFn(ctx, cfg, question, results, AnswerOpts{
			Model: turnModel,
			Persona: func(domain string) {
				if prog != nil {
					prog.Send(personaMsg(domain))
				}
			},
			Stream: func(b []byte) {
				streamed = true
				if prog != nil {
					prog.Send(chunkMsg(string(b)))
				}
			},
			Stage: func(stage string) {
				if prog != nil {
					prog.Send(stageMsg(stage))
				}
			},
		})
		if errors.Is(err, ErrNoResults) {
			return noResultsMsg{}
		}
		if err != nil && !streamed {
			if errors.Is(err, context.Canceled) {
				return canceledMsg{}
			}
			return errMsg{timeoutOrErr(err)}
		}
		usedWeb := false
		for _, result := range results {
			if result.Payload.Source == webSource {
				usedWeb = true
				break
			}
		}
		calls, partial := metrics.snapshot()
		return streamDoneMsg{full: full, citations: cits, results: results, usedWeb: usedWeb, tokens: tokens, llmCalls: calls, llmCallsPartial: partial}
	}
}

// retrievalClient returns the session's retrieval client with the saved
// /models switches applied. It reads the settings file, so it runs in a
// command, never in Update.
func (m model) retrievalClient() (*retrieval.Client, error) {
	if m.rcErr != nil {
		return nil, m.rcErr
	}
	return followPrefs(m.rc, loadPrefs()), nil
}

// healthCmd runs the status-line probe: the three services, and alongside
// them embed_server's /health for whether the reranker loaded.
func (m model) healthCmd() tea.Cmd {
	rc, cfg := m.rc, m.cfg
	return func() tea.Msg {
		started := time.Now()
		rerank := make(chan bool, 1)
		go func() {
			eh, ok := probeEmbedHealth(cfg)
			rerank <- ok && eh.Reranker
		}()
		h := nativeHealth(cfg, rc)
		return healthMsg{h: h, rerank: <-rerank, started: started}
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
	agentModel := m.agentModel
	reasoning := m.reasoning
	return func() tea.Msg {
		var full strings.Builder
		var tokens int
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
				if ev.tokens > 0 {
					tokens = ev.tokens
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
				serr := StreamAgent(ctx, id, message, agentModel, reasoning, onEvent)
				if errors.Is(serr, context.Canceled) {
					return canceledMsg{}
				}
				return streamDoneMsg{full: full.String(), agent: true, err: serr, tokens: tokens}
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
		return streamDoneMsg{full: full.String(), agent: true, err: serr, tokens: tokens}
	}
}

// modeSwitchCmd refreshes the status-line health after a mode change: the agent
// gateway/binary for agent mode, qdrant + embed_server for rag mode.
func (m model) modeSwitchCmd() tea.Cmd {
	if m.mode == "agent" {
		return agentHealthCmd()
	}
	return m.healthCmd()
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

// sessID returns the current session id, or "" when persistence is unavailable.
func (m model) sessID() string {
	if m.sess != nil {
		return m.sess.id
	}
	return ""
}

// openModelPickerCmd discovers the available models for the active mode in a
// command (network IO) and opens the model picker on completion, so the event
// loop stays responsive and the input draft is preserved. When
// discovery fails it still opens with the current model plus the reasoning
// levels, so the picker always works.
//
// In rag mode the models hidden in /models are left out. When that leaves only
// the active model, the picker says so and points to /models.
func (m model) openModelPickerCmd() tea.Cmd {
	mode := m.mode
	current := m.currentModel()
	reasoning := m.reasoning
	prefs := m.prefs
	return func() tea.Msg {
		var models []string
		var listErr error
		allHidden := false
		if mode == "agent" {
			ctx, cancel := context.WithTimeout(context.Background(), agentSessionTimeout)
			defer cancel()
			models, _ = modelOptions(ctx)
		} else {
			all, err := llmModels()
			if errors.Is(err, errLLMRedirect) {
				listErr = errLLMRedirect
			}
			models = slices.DeleteFunc(slices.Clone(all), prefs.isHidden)
			allHidden = len(models) < len(all) && len(ensureFirst(models, current)) <= 1
		}
		return openModelPickerMsg{models: ensureFirst(models, current), current: current, reasoning: reasoning, allHidden: allHidden, listErr: listErr}
	}
}

// ensureFirst returns models with current de-duplicated to the front (dropping a
// "unknown"/empty current), so the picker always lists the active model.
func ensureFirst(models []string, current string) []string {
	current = strings.TrimSpace(current)
	seen := map[string]bool{}
	var out []string
	if current != "" && current != "unknown" {
		out = append(out, current)
		seen[current] = true
	}
	for _, id := range models {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// undo appends a tombstone to the session (so replay skips the last exchange) and
// notes that already-committed scrollback lines can't be unprinted.
func (m model) undo(echo string) (tea.Model, tea.Cmd) {
	if m.sess == nil {
		return m, tea.Sequence(tea.Println(echo), tea.Println("   "+Meta.Render("undo: no active session")))
	}
	if err := m.sess.appendTurn(turnRecord{Role: roleTombstone, Mode: m.mode}); err != nil {
		return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(fmt.Errorf("undo: %w", err))))
	}
	m.lastAnswer = ""
	m.openTargets = nil
	note := "   " + Meta.Render(Glyph(GlyphArrow)+" undid the last turn (dropped from this session; printed lines remain in scrollback)")
	return m, tea.Sequence(tea.Println(echo), tea.Println(note))
}

// clearScrollback resets the model's notion of the transcript and prints a
// separator + muted note. It can't unprint committed tea.Println lines (they are
// real terminal scrollback); this is the documented limitation.
func (m model) clearScrollback(echo string) (tea.Model, tea.Cmd) {
	m.lastAnswer = ""
	m.openTargets = nil
	sep := " " + RuleS.Render(strings.Repeat(barRune(), clamp(m.renderWidth(), 20, 60)))
	note := "   " + Meta.Render("cleared (lines above stay in the terminal's own scrollback)")
	return m, tea.Sequence(tea.Println(echo), tea.Println(sep), tea.Println(note))
}

// retitle renames the current session (persisted to the index once it exists).
func (m model) retitle(echo, arg string) (tea.Model, tea.Cmd) {
	name := strings.TrimSpace(arg)
	if name == "" {
		return m, tea.Sequence(tea.Println(echo), tea.Println(styleErr(errors.New("title: give a name, e.g. /title vector tuning notes"))))
	}
	if m.sess == nil {
		return m, tea.Sequence(tea.Println(echo), tea.Println("   "+Meta.Render("title: no active session")))
	}
	m.sess.title = name // seeds the title even before the first turn is written
	m.sessTitle = name
	_ = renameSession(m.sess.id, name) // no-op error when the session isn't on disk yet
	return m, tea.Sequence(tea.Println(echo), tea.Println("   "+Meta.Render("renamed session to: "+name)))
}

// barRune is the horizontal separator glyph, unicode or ascii.
func barRune() string {
	if useUnicode {
		return "─"
	}
	return "-"
}

// formatReplayAnswer renders a resumed session's answer turn: a muted "blk"
// header plus the glamour-rendered body, mirroring a live answer without timing.
func formatReplayAnswer(full string, width int) string {
	head := " " + Meta.Render(Glyph(GlyphOK)+" blk")
	body := strings.TrimRight(glowRender(full, width), "\n")
	return head + "\n" + body
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
	path, section, done := m.openAction(arg)
	if done != nil {
		return done
	}
	return execFuncCmd(func() error { return openFile(path, section, false) })
}

// openAction resolves a /open argument to the file and cited section to open.
// A non-nil cmd means there is nothing to open: it prints the error or the web
// notice instead. A literal path has no section.
func (m model) openAction(arg string) (path, section string, done tea.Cmd) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", "", tea.Println(styleErr(errors.New("open: give a number (e.g. /open 2) or a path")))
	}
	if n, err := strconv.Atoi(arg); err == nil {
		if n < 1 || n > len(m.openTargets) {
			return "", "", tea.Println(styleErr(fmt.Errorf("open: no item %d (have %d)", n, len(m.openTargets))))
		}
		t := m.openTargets[n-1]
		if t.Path == "" {
			return "", "", tea.Println(styleErr(fmt.Errorf("open: item %d has no file path", n)))
		}
		if isWebURL(t.Path) {
			return "", "", tea.Println(openWebNotice(t.Path))
		}
		return t.Path, t.Section, nil
	}
	if isWebURL(arg) {
		return "", "", tea.Println(openWebNotice(arg))
	}
	return arg, "", nil
}

// isWebURL reports whether a source path is an http(s) URL (a web citation or an
// indexed page), which /open never launches or fetches.
func isWebURL(p string) bool {
	p = strings.ToLower(strings.TrimSpace(p))
	return strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://")
}

// openWebNotice is the one-line answer to /open on a web result: it says why
// nothing opened and prints the sanitized URL so the operator can copy it.
func openWebNotice(url string) string {
	return " " + Caut.Render(Glyph(GlyphWarn)) + " " +
		Meta.Render("open: web results are not opened automatically; copy the URL: ") +
		oneLine(sanitizeTerminal(strings.TrimSpace(url)))
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
		// The text is untrusted LLM output the operator may paste into a terminal.
		c.Stdin = strings.NewReader(sanitizeTerminal(text))
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
// command; bare "s" is a search shorthand; other natural input is an ask
// (the headline verb for a Q&A KB).
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
	case "s":
		return "search", rest
	case "search":
		return "ask", line
	case "web":
		return "web", rest
	}
	return "ask", line
}

// --- rendering helpers (all return strings for tea.Println) ---

func statusMark(tone lipgloss.TerminalColor) string {
	if plCurrentTier() != plNerd {
		return Glyph(GlyphDot)
	}
	switch tone {
	case Success:
		return "\U0001f7e2"
	case Err:
		return "\U0001f534"
	default:
		return "\U0001f7e1"
	}
}

// statusLine shows the active mode, the model, and services health. In rag mode
// the status mark reflects qdrant, embed_server, and the LLM; in
// agent mode it reflects the hermes gateway (or "subprocess" on fallback). Rag
// mode also shows the embedder and reranker once the probe has run, and the
// reranker switch.
func (m model) statusLine() string {
	if m.mode == "agent" {
		return m.agentStatusLine()
	}
	style := Caut
	var tone lipgloss.TerminalColor = Warn
	label := "checking services"
	if m.servicesChecked {
		if m.servicesOK {
			style, tone, label = OK, Success, "services ok"
		} else {
			style, tone, label = Fail, Err, "services down"
			if m.health != nil {
				if down := downServices(m.health); len(down) > 0 {
					label = strings.Join(down, ", ") + " down"
				}
			}
		}
	}
	var retrieval []string
	// rag is the KB-grounding switch (adaptive-RAG). On is the default and is
	// already implied by being in rag mode, so only the off state is surfaced,
	// where it changes behavior (the answer path stops querying the local KB).
	// This keeps the common case uncluttered and preserves the width budget.
	if !m.prefs.Rag {
		retrieval = append(retrieval, "rag off")
	}
	if m.health != nil {
		embed := "embed down"
		if m.health.EmbedServer {
			embed = "embed ok"
		}
		retrieval = append(retrieval, embed)
	}
	switch {
	case !m.prefs.Rerank:
		retrieval = append(retrieval, "rerank off")
	case m.health != nil && m.health.EmbedServer && m.rerankUp:
		retrieval = append(retrieval, "rerank ok")
	case m.health != nil:
		retrieval = append(retrieval, "rerank down")
	}
	// web is off by default (offline-by-default), so it follows the rag switch's
	// discipline: the segment is shown only when web search is actually in use,
	// naming the active provider, and nothing is added in the common off case.
	if seg, ok := webStatusSegment(activeWebProvider(), m.prefs.Web); ok {
		retrieval = append(retrieval, seg)
	}
	// The domain-expert persona for this turn, shown only when one was chosen
	// (generic adds nothing). It is a low-priority retrieval segment, so it drops
	// with the others when the ribbon is narrow.
	if m.persona != "" {
		retrieval = append(retrieval, "persona "+m.persona)
	}
	return m.composeStatus(style.Render(statusMark(tone)), tone, "rag", m.currentModel(), label, retrieval)
}

// webStatusSegment is the optional web entry in the rag status ribbon. It is
// shown only when web search is actually in use: a provider is available
// (activeWebProvider is not "off") and the web switch is on. provider is the
// activeWebProvider label; the segment names it ("web tavily", or "web ddg" for
// the DuckDuckGo fallback). When web is off or unconfigured it returns ok=false
// so the common case adds no segment and the width budget is preserved.
func webStatusSegment(provider string, on bool) (string, bool) {
	if !on || provider == webProviderNone {
		return "", false
	}
	if provider == webProviderDuckDuckGo {
		return "web ddg", true
	}
	return "web " + provider, true
}

// modelPriorityCols is how much of the model name the status line keeps
// visible before it drops the other segments to make room.
const modelPriorityCols = 24

// statusLayout is which optional segments a status line carries: the session
// title, the reasoning, the retrieval models, and the long health label
// ("services ok" rather than "ok").
type statusLayout struct{ title, reasoning, retrieval, longHealth bool }

// composeStatus renders the status line as a powerline ribbon of labeled
// fields. The left cluster is mode, model, and reasoning on the surface fill.
// The right cluster is the retrieval models, health (filled with tone), and the
// viz switch. The session title and the queue count trail as muted text. The
// model name has priority. While the line overflows and fewer than
// modelPriorityCols of the name would show, the session title goes first, then
// the reasoning (and viz), then the word "services" in the health label. Past
// that the line collapses to mode, model, and health, and the model is cut as
// the last resort (with an ASCII "..."). A narrow rich tier puts retrieval
// labels on a second line.
func (m model) composeStatus(dot string, tone lipgloss.TerminalColor, mode, modelID, health string, retrieval []string) string {
	modelID = sanitizeTerminal(modelID)
	title := ""
	if t := strings.TrimSpace(m.sessTitle); t != "" {
		title = oneLine(sanitizeTerminal(t))
	}
	shortHealth := strings.TrimSpace(strings.Replace(health, "services", "", 1))
	queued := m.queuedIndicator()
	build := func(model string, l statusLayout) string {
		// The autonomy (engage-mode) segment is a SAFETY indicator: it is always
		// shown, right after the mode, so the operator can never lose sight of
		// whether an engagement would run commands without confirming. Safe is sage
		// text on the neutral fill; Auto is a tan fill (active/caution).
		engSeg := plSegment{Text: engageModeSeg(m.engageMode, m.engageOverride, m.engageHITL), FG: wSageFg, BG: wSegBg}
		if m.engageMode == secgate.Auto {
			engSeg.FG, engSeg.BG = wTanFg, wTanBg
		}
		left := []plSegment{
			{Text: mode, FG: wSageFg, BG: wSageBg, Icon: iconDatabase},
			engSeg,
			{Text: "model " + model, FG: wHeadFg, BG: wSegBg, Icon: iconCPU},
		}
		if l.reasoning {
			left = append(left, plSegment{Text: "reasoning " + m.reasoning, FG: wMutedFg, BG: wSegBg2, Icon: iconBolt})
		}
		var right []plSegment
		if l.retrieval {
			for _, r := range retrieval {
				right = append(right, plSegment{Text: r, FG: wMutedFg, BG: wSegBg2})
			}
		}
		h := shortHealth
		if l.longHealth {
			h = health
		}
		hFG, hBG := wSageFg, wSageBg
		if tone == Err {
			hFG, hBG = wRoseFg, wRoseBg
		}
		right = append(right, plSegment{Text: h, FG: hFG, BG: hBG, Icon: iconHealth})
		if l.reasoning && mode == "rag" {
			if m.prefs.Viz {
				right = append(right, plSegment{Text: "viz", FG: wTanFg, BG: wTanBg, Icon: iconChart})
			} else {
				right = append(right, plSegment{Text: "viz off", FG: wMutedFg, BG: wSegBg2, Icon: iconChart})
			}
		}
		line := " " + dot + " " + plRenderRibbon(left, right, plCurrentTier(), 0)
		var extra []string
		if l.title && title != "" {
			extra = append(extra, title)
		}
		if queued != "" {
			extra = append(extra, queued)
		}
		if len(extra) > 0 {
			line += "  " + Meta.Render(joinSep(extra...))
		}
		return line
	}
	w, _ := m.termSize()
	if w < 45 {
		state := "checking"
		if tone == Success {
			state = "ok"
		} else if tone == Err {
			state = "down"
		}
		first := fmt.Sprintf(" %s %s %s", dot, mode, state)
		second := " " + engageModeSeg(m.engageMode, m.engageOverride, m.engageHITL)
		if room := w - lipgloss.Width(second) - 2; room >= 4 && modelID != "" {
			second += " " + ellipsize(modelID, room)
		}
		clip := lipgloss.NewStyle().MaxWidth(w)
		return clip.Render(first) + "\n" + clip.Render(second)
	}
	for _, l := range []statusLayout{
		{title: true, reasoning: true, retrieval: true, longHealth: true},
		{reasoning: true, retrieval: true, longHealth: true},
		{retrieval: true, longHealth: true},
		{retrieval: true},
	} {
		line := build(modelID, l)
		over := lipgloss.Width(line) - w
		if over <= 0 {
			return line
		}
		// ellipsize keeps keep-3 columns of the name plus "...".
		if keep := lipgloss.Width(modelID) - over; keep-3 >= modelPriorityCols {
			return build(ellipsize(modelID, keep), l)
		}
	}
	collapsed := statusLayout{}
	base := build(modelID, collapsed)
	if over := lipgloss.Width(base) - w; over > 0 {
		base = build(ellipsize(modelID, max(lipgloss.Width(modelID)-over, 4)), collapsed)
	}
	if len(retrieval) > 0 && plCurrentTier() == plNerd {
		info := "  " + Meta.Render(strings.Join(retrieval, " "+Glyph(GlyphSep)+" "))
		return base + "\n" + lipgloss.NewStyle().MaxWidth(w).Render(info)
	}
	return base
}

// queuedIndicator is the muted "N queued" status marker, empty when the queue is
// empty.
func (m model) queuedIndicator() string {
	n := len(m.queue)
	if n == 0 {
		return ""
	}
	if plCurrentTier() != plASCII {
		return fmt.Sprintf("\U0001f4e5 %d queued", n)
	}
	return fmt.Sprintf("(%d queued)", n)
}

// agentStatusLine renders the agent-mode status line: dot + "agent" + model +
// transport. The transport is the one used on the last turn, or the health-probe
// result before the first turn.
func (m model) agentStatusLine() string {
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
	var tone lipgloss.TerminalColor = Warn
	label := xport
	switch xport {
	case "gateway":
		style, tone, label = OK, Success, "via gateway"
	case "subprocess":
		label = "via subprocess"
	case "unavailable":
		style, tone, label = Fail, Err, "gateway unavailable"
	case "checking":
		label = "checking gateway"
	}
	return m.composeStatus(style.Render(statusMark(tone)), tone, "agent", m.currentModel(), label, nil)
}

// ragModelLabel is the oMLX model the plain REPL's /models marks active,
// without a network call: the config's default_model, which OMLX_MODEL
// overrides. The TUI keeps its config and reads m.cfg.DefaultModel instead.
func ragModelLabel() string {
	return loadConfig().DefaultModel
}

// modeNote is the one-line confirmation printed when the mode changes.
func modeNote(mode string) string {
	if mode == "agent" {
		return "   " + Meta.Render("mode: agent (full hermes agent with tools, web, memory)")
	}
	return "   " + Meta.Render("mode: rag (retrieve then stream a cited answer)")
}

// engageModeSeg is the autonomy-mode label for the status ribbon: "safe" (every
// command confirmed), or "auto" with an "(hitl)" marker when the unattended bound
// is empty (so every command still confirms) and an "override" marker when the
// scope override is on. It is a safety indicator; override and hitl apply only in
// Auto.
func engageModeSeg(mode secgate.Mode, override, hitl bool) string {
	if mode != secgate.Auto {
		return "safe"
	}
	label := "auto"
	if hitl {
		label = "auto (hitl)"
	}
	if override {
		label += " override"
	}
	return label
}

// autoModeNote is the one-line confirmation printed after /auto: it warns when
// bounded autonomy has no scope and no override, and notes when the scope
// override is on. LOCAL unattended actions need both RoE and binary allowlists.
func autoModeNote(override, scopeDetected bool) string {
	switch {
	case override:
		return "auto: no-scope override logged; LOCAL needs an RoE rule and binary allowlist"
	case !scopeDetected:
		return "auto: no scope detected - add ROE.md or use /auto override before engaging"
	default:
		return "auto: scoped; LOCAL needs an RoE rule and binary allowlist or confirmation"
	}
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
	lead := m.sp.View()
	if m.reduceMotion {
		// Static marker and whole elapsed seconds, redrawn once per second.
		lead = Meta.Render(Glyph(GlyphBullet))
		el = " " + Meta.Render(fmt.Sprintf("(%ds)", int(time.Since(m.turnStart).Seconds())))
	}
	readout := ""
	if !m.firstTokAt.IsZero() {
		readout = "  " + liveReadout(m.liveTokens, time.Since(m.firstTokAt), useUnicode)
	}
	// Fit the line to the terminal: drop the live readout first, then the elapsed
	// time, then cut the verb.
	w, _ := m.termSize()
	head := " " + lead + " "
	for _, tail := range []string{el + readout, el, ""} {
		if line := head + Meta.Render(m.workingVerb) + tail; lipgloss.Width(line) <= w {
			return line
		}
	}
	line := head + Meta.Render(ellipsize(m.workingVerb, w-lipgloss.Width(head)))
	return lipgloss.NewStyle().MaxWidth(w).Render(line)
}

// vizBar renders stage progress, or task progress when the stage has no total.
// It returns "" when viz is off or no progress denominator exists.
func (m model) vizBar() string {
	if !m.prefs.Viz || m.engagement == nil {
		return ""
	}
	e, err := m.engagement.Snapshot(context.Background())
	if err != nil {
		return ""
	}
	step, total := e.Stage.Step, e.Stage.Total
	taskProgress := false
	if total <= 0 {
		total = len(e.Tasks)
		if total == 0 {
			return ""
		}
		step = 0
		for _, task := range e.Tasks {
			if task.Status == eng.StatusDone || task.Status == eng.StatusNA {
				step++
			}
		}
		taskProgress = true
	}
	frac := float64(step) / float64(total)
	count := fmt.Sprintf("%d/%d", step, total)
	if taskProgress {
		count += " tasks"
	}
	// Each piece carries the bar background itself: an inner style's reset would
	// otherwise cut the outer background short.
	on := func(fg lipgloss.Color) lipgloss.Style { return lipgloss.NewStyle().Foreground(fg).Background(wBarBg) }
	gap := on(wBarBg).Render(" ")
	// The rich tier uses the play and loader icons.
	tier := plCurrentTier()
	lead, spin := "\u258e", "\u283f"
	switch tier {
	case plNerd:
		lead, spin = iconPlay, iconLoader
	case plASCII:
		lead, spin = "|", "/"
	}
	accent := on(wMeterOn).Render(lead)
	spinner := on(wMeterOn).Render(spin)
	rate := !m.firstTokAt.IsZero() && m.liveTokens > 0
	var rateText string
	if rate {
		tps := modeleval.TokensPerSec(m.liveTokens, time.Since(m.firstTokAt))
		bolt := ""
		if tier == plNerd {
			bolt = on(wMeterOn).Render(iconBolt) + gap
		}
		// The chunk count can under-report tokens, so the rate is approximate.
		rateText = on(wMutedFg).Render(" "+glyphFor(GlyphBar, tier != plASCII)+" ") + bolt + on(wMutedFg).Render("~") + on(wTanFg).Render(fmt.Sprintf("%.0f", tps)) + on(wMutedFg).Render(" t/s")
	}
	render := func(label, tool string, cells int, showRate bool) string {
		line := accent + gap + spinner + gap + on(wOffWhite).Render(label) + gap + gap + plMeter(frac, cells, tier) + gap + gap + on(wMutedFg).Render(count)
		if tool != "" {
			line += on(wMutedFg).Render(" " + tool)
		}
		if showRate {
			line += rateText
		}
		return line
	}
	w, _ := m.termSize()
	if rate && lipgloss.Width(render("....", "", 12, true)) > w {
		rate = false
	}
	cells := 12
	for cells > 1 && lipgloss.Width(render("", "", cells, rate)) > w {
		cells--
	}
	label := oneLine(sanitizeTerminal(e.Stage.Label))
	room := w - lipgloss.Width(render("", "", cells, rate))
	shortLabel := ellipsize(label, room)
	tool := oneLine(sanitizeTerminal(e.Stage.Tool))
	if shortLabel != label || lipgloss.Width(render(shortLabel, tool, cells, rate)) > w {
		tool = ""
	}
	line := render(shortLabel, tool, cells, rate)
	return lipgloss.NewStyle().Background(wBarBg).MaxWidth(w).Render(line)
}

func liveReadout(tokens int, since time.Duration, unicode bool) string {
	sep := " " + glyphFor(GlyphBullet, unicode) + " "
	parts := []string{modeleval.FormatElapsed(since)}
	if tokens > 0 {
		tps := modeleval.TokensPerSec(tokens, since)
		parts = []string{
			fmt.Sprintf("%d tok", tokens),
			fmt.Sprintf("%.0f tok/s", tps),
			modeleval.FormatElapsed(since),
		}
	}
	return Meta.Render(strings.Join(parts, sep))
}

// termSize is the terminal size the layout fits: the model's width and height
// from the last tea.WindowSizeMsg, falling back to the detected terminal width
// (80 off a TTY) and 24 rows before the first size message arrives, so both
// are always at least 1.
func (m model) termSize() (int, int) {
	w, h := m.width, m.height
	if w <= 0 {
		w = terminalWidth()
	}
	if h <= 0 {
		h = 24
	}
	return w, h
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

// formatAnswer renders a finished RAG answer with its SOURCES block. rerankOff
// adds the note that the reranker was off for it.
func formatAnswer(resp *answerResponse, elapsed time.Duration, width int, rerankOff bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, " %s %s\n", OK.Render(Glyph(GlyphOK)),
		Meta.Render("Answered in "+elapsed.Round(100*time.Millisecond).String()))
	b.WriteString(strings.TrimRight(glowRender(resp.Answer, width), "\n"))
	b.WriteString("\n\n " + H2.Render("SOURCES") + "\n")
	if len(resp.Citations) == 0 {
		b.WriteString("   " + Meta.Render("(none)") + "\n")
	}
	for i, cit := range resp.Citations {
		b.WriteString(citationLine("   ", i, cit) + "\n")
	}
	if resp.UsedWeb {
		b.WriteString("   " + Meta.Render("(this answer used a web search)") + "\n")
	}
	if rerankOff {
		b.WriteString("   " + Meta.Render(rerankOffNote) + "\n")
	}
	if len(resp.Citations) > 0 {
		b.WriteString("   " + Meta.Render("open a source with /open N") + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// formatNoResults is the warning shown when AnswerLoop found nothing to answer
// from. It is not a success: no check mark, no timing, no SOURCES block.
func formatNoResults() string {
	return renderNoResults(func(s lipgloss.Style, text string) string { return s.Render(text) },
		Glyph(GlyphWarn), Glyph(GlyphBullet))
}

// formatNoResultsErr is formatNoResults for stderr: styled and glyphed by
// stderr's capabilities, not stdout's.
func formatNoResultsErr() string {
	return renderNoResults(errStyle, glyphFor(GlyphWarn, useErrUnicode), glyphFor(GlyphBullet, useErrUnicode))
}

// renderNoResults builds the no-results warning with the given style function
// and glyphs, so stdout and stderr callers share one text.
func renderNoResults(style func(lipgloss.Style, string) string, warn, bullet string) string {
	var b strings.Builder
	fmt.Fprintf(&b, " %s %s\n", style(Caut, warn), style(Meta, "No relevant sources were found, so there is no answer."))
	b.WriteString("   " + style(Meta, "Try one of these:") + "\n")
	b.WriteString("   " + style(Meta, bullet+" rephrase the question with different keywords") + "\n")
	b.WriteString("   " + style(Meta, bullet+" run `blk status` to check that the services are up") + "\n")
	b.WriteString("   " + style(Meta, bullet+" run `blk add <path or url>` to index more content"))
	return b.String()
}

func formatHealth(h *serviceHealth, cfg ragconfig.Config) string {
	llmBase := redactedURL(omlxBaseURL())
	status := "degraded"
	if h.ok() {
		status = "ok"
	}
	var b strings.Builder
	fmt.Fprintf(&b, " %s blkChain services: %s\n", check(h.ok()), status)
	fmt.Fprintf(&b, "   %s qdrant        %s\n", check(h.Qdrant), Meta.Render("("+cfg.QdrantGRPCURL+")"))
	fmt.Fprintf(&b, "   %s embed_server  %s\n", check(h.EmbedServer), Meta.Render("("+cfg.EmbedServerURL+")"))
	fmt.Fprintf(&b, "   %s llm           %s", check(h.LLM), Meta.Render("("+llmBase+")"))
	if !h.Qdrant || !h.EmbedServer {
		b.WriteString("\n   " + Meta.Render("start the services with `blk up`"))
	}
	if !h.LLM {
		b.WriteString("\n   " + Meta.Render(llmDownHint(h, llmBase)))
	}
	return b.String()
}

func styleErr(err error) string {
	// retrieval.ErrUnreachable already carries the `blk up` hint.
	return " " + Fail.Render(Glyph(GlyphErr)) + " " + oneLine(sanitizeTerminal(err.Error()))
}

func promptEcho(q string) string {
	q = sanitizeTerminal(q) // replayed sessions come from disk
	label := Prompt.Render(Glyph(GlyphPrompt))
	lines := strings.Split(q, "\n")
	var b strings.Builder
	fmt.Fprintf(&b, " %s %s", label, Body.Render(lines[0]))
	for _, l := range lines[1:] {
		fmt.Fprintf(&b, "\n   %s", Body.Render(l))
	}
	return b.String()
}

// bannerTagline is the one-line framework descriptor shown inside the welcome box.
const bannerTagline = "Autonomous Offensive Security Framework"

// welcomeBanner shows the tool name and tagline inside a rounded box.
// Terminals without Unicode get two plain lines.
func welcomeBanner(width int) string {
	if width < 1 {
		width = 1
	}
	title := "blkchain"
	tagStyle := lipgloss.NewStyle().Foreground(wTanFg)

	if !useUnicode {
		head := " " + H1.Render(title)
		tag := " " + tagStyle.Render(ellipsize(bannerTagline, max(width-1, 1)))
		return lipgloss.NewStyle().MaxWidth(width).Render(head) + "\n" +
			lipgloss.NewStyle().MaxWidth(width).Render(tag)
	}

	border := lipgloss.NewStyle().Foreground(Muted)
	titleStyle := lipgloss.NewStyle().Foreground(wHeadFg).Bold(true)
	iconStyle := lipgloss.NewStyle().Foreground(wSageFg)
	if width < 16 {
		return lipgloss.NewStyle().MaxWidth(width).Render(titleStyle.Render(title))
	}
	inner := width - 2
	top := border.Render("╭" + strings.Repeat("─", inner) + "╮")
	name := iconStyle.Render(iconRadar) + " " + titleStyle.Render(title)
	namePad := inner - 2 - lipgloss.Width(name)
	nameLine := border.Render("│  ") + name + strings.Repeat(" ", namePad) + border.Render("│")
	tag := bannerTagline
	if lipgloss.Width(tag) > inner-4 {
		tag = ellipsize(tag, inner-4)
	}
	tagPad := inner - 4 - lipgloss.Width(tag)
	tagLine := border.Render("│    ") + tagStyle.Render(tag) + strings.Repeat(" ", tagPad) + border.Render("│")
	bottom := border.Render("╰" + strings.Repeat("─", inner) + "╯")
	return top + "\n" + nameLine + "\n" + tagLine + "\n" + bottom
}

// helpResponse renders the REPL /help output: the full command list when arg is
// empty, one command's help (the same renderer as `blk help <command>`) when arg
// names a known command, or an unknown-command error otherwise. Only the first
// token of arg names the command.
func helpResponse(arg string, width int) string {
	name := ""
	if f := strings.Fields(arg); len(f) > 0 {
		name = f[0]
	}
	if name == "" {
		return helpBlock(width)
	}
	if c, ok := lookupCommand(name); ok {
		return strings.TrimRight(renderCommandHelp(c, width), "\n")
	}
	return styleErr(unknownCommand(name))
}

// helpBlock is the /help text: one section per command group, every description
// in one column (wrapped to width), and a pointer to the key panel. Descriptions
// come from the command registry, so they match the palette and the command line.
func helpBlock(width int) string {
	groups := commandGroups()
	sections := make([][]helpRow, len(groups))
	nameW := 0
	for gi, g := range groups {
		if gi == 0 {
			sections[gi] = append(sections[gi], helpRow{"<question>", "type a question and press enter (same as /ask)"})
		}
		for _, c := range g.cmds {
			n := "/" + c.name
			if c.args != "" {
				n += " " + c.args
			}
			sections[gi] = append(sections[gi], helpRow{n, c.desc})
			if c.name == "search" {
				sections[gi] = append(sections[gi], helpRow{"s <q>", "short for /search"})
			}
		}
		for _, r := range sections[gi] {
			nameW = max(nameW, len(r.name))
		}
	}
	descW := max(width-3-nameW-2, 1)
	var b strings.Builder
	for gi, g := range groups {
		if gi > 0 {
			b.WriteString("\n")
		}
		b.WriteString(" " + H2.Render(strings.ToUpper(g.title)) + "\n")
		for _, r := range sections[gi] {
			for i, ln := range strings.Split(wrapIndent(r.desc, 0, descW), "\n") {
				name := strings.Repeat(" ", nameW)
				if i == 0 {
					name = Key.Render(padCols(r.name, nameW))
				}
				b.WriteString("   " + name + "  " + Body.Render(ln) + "\n")
			}
		}
	}
	b.WriteString("\n   " + Meta.Render("Press ? for keyboard shortcuts."))
	return b.String()
}

// padCols right-pads s with spaces to width display columns.
func padCols(s string, width int) string {
	if n := width - lipgloss.Width(s); n > 0 {
		return s + strings.Repeat(" ", n)
	}
	return s
}

// --- key panel ---

// keyRow is one line of the key panel: the key label and what it does.
type keyRow struct{ keys, desc string }

// keyGroup is a titled block of key rows.
type keyGroup struct {
	title string
	rows  []keyRow
}

// panelGroups is the full key reference, grouped. Key labels come from the
// bindings, so the panel shows the keys the model listens for. Every binding in
// the key map has a row; the two bindings that shadow a textarea key say when
// they apply.
func (k keyMap) panelGroups() []keyGroup {
	label := func(bs ...key.Binding) string {
		parts := make([]string, len(bs))
		for i, b := range bs {
			parts[i] = b.Help().Key
		}
		return strings.Join(parts, "/")
	}
	return []keyGroup{
		{"MOVE AND EDIT", []keyRow{
			{label(k.Newline), "new line in the draft"},
			{label(k.HistPrev, k.HistNext), "recall earlier questions; moves the cursor in a wrapped or multi-line draft"},
			{label(k.Editor), "compose in $EDITOR (only while idle)"},
			{"home/ctrl+a", "line start"},
			{"end/ctrl+e", "line end"},
			{"alt+b/f", "word left/right"},
			{"ctrl+w", "delete previous word"},
			{"ctrl+k", "delete to line end"},
			{"ctrl+v", "paste clipboard"},
			{"backspace/del", "delete character"},
		}},
		{"ASK", []keyRow{
			{label(k.Submit), "ask; while a turn runs, queue it"},
			{label(k.ClearQueue), "clear queued questions (only while some are queued; else deletes to line start)"},
			{label(k.Esc), "cancel the turn; close pickers"},
			{label(k.Cancel), "cancel the turn or clear the draft; press twice to quit"},
		}},
		{"OVERLAYS", []keyRow{
			{label(k.Help), "show or hide this list"},
			{"/", "open the command list"},
			{label(k.Attach), "attach a file to your next question"},
			{label(k.ReverseSearch), "search earlier questions"},
			{label(k.PickModel), "pick the model and reasoning level (only while idle; replaces cursor up)"},
		}},
		{"SESSION", []keyRow{
			{label(k.Quit), "quit; press twice if a draft or turn is active"},
		}},
	}
}

// keyPanelLines renders the whole key reference for a terminal width w: one
// column below 70 columns, two above, each line at most w wide. Callers show a
// window of the result when the terminal is short.
func keyPanelLines(k keyMap, w int) []string {
	groups := k.panelGroups()
	keyW := 0
	for _, g := range groups {
		for _, r := range g.rows {
			keyW = max(keyW, lipgloss.Width(r.keys))
		}
	}
	cols, colW := 1, max(w-1, 1)
	if w >= 70 {
		cols, colW = 2, (w-1-3)/2
	}
	descW := max(colW-2-keyW-2, 1)
	blocks := make([][]string, len(groups))
	for i, g := range groups {
		blocks[i] = []string{H2.Render(g.title)}
		for _, r := range g.rows {
			for j, ln := range strings.Split(wrapIndent(r.desc, 0, descW), "\n") {
				keys := strings.Repeat(" ", keyW)
				if j == 0 {
					keys = Key.Render(padCols(r.keys, keyW))
				}
				blocks[i] = append(blocks[i], "  "+keys+"  "+Body.Render(ln))
			}
		}
	}
	// stack joins blocks into one column, a blank row between them.
	stack := func(bs [][]string) []string {
		var out []string
		for i, blk := range bs {
			if i > 0 {
				out = append(out, "")
			}
			out = append(out, blk...)
		}
		return out
	}
	var lines []string
	if cols == 1 {
		for _, ln := range stack(blocks) {
			lines = append(lines, strings.TrimRight(" "+ln, " "))
		}
	} else {
		// Split the groups, in order, where the taller column is shortest.
		split, best := 1, -1
		for s := 1; s < len(blocks); s++ {
			h := max(len(stack(blocks[:s])), len(stack(blocks[s:])))
			if best < 0 || h < best {
				split, best = s, h
			}
		}
		left, right := stack(blocks[:split]), stack(blocks[split:])
		for i := 0; i < max(len(left), len(right)); i++ {
			l, r := "", ""
			if i < len(left) {
				l = left[i]
			}
			if i < len(right) {
				r = right[i]
			}
			lines = append(lines, strings.TrimRight(" "+padCols(l, colW)+"   "+r, " "))
		}
	}
	for i, ln := range lines {
		lines[i] = lipgloss.NewStyle().MaxWidth(max(w, 1)).Render(ln)
	}
	return lines
}

// keyPanelShown reports whether the key panel is drawn: it only belongs on an
// idle input, never over a turn, an overlay, reverse search, or the palette.
func (m model) keyPanelShown() bool {
	return m.keyPanel && !m.working && m.overlay == nil && !m.rsearch.open && !m.pal.open
}

// keyPanelRows is how many rows the key panel is offered: the terminal minus the
// status line, the one-row draft, and the footer.
func (m model) keyPanelRows() int {
	_, h := m.termSize()
	return max(h-3, 0)
}

// scrollKeyPanel moves the key panel window for an up, down, pgup, or pgdown key,
// keeping it inside the rows that exist.
func (m model) scrollKeyPanel(k string) model {
	w, _ := m.termSize()
	limit := max(len(keyPanelLines(m.keys, w))-max(m.keyPanelRows()-1, 0), 0)
	step := map[string]int{"up": -1, "down": 1, "pgup": -5, "pgdown": 5}[k]
	m.keyScroll = clamp(m.keyScroll+step, 0, limit)
	return m
}

// keyPanelView draws the key panel in at most rows rows. When the terminal is
// too short for the whole reference it shows a window of it, scrolled by
// keyScroll, and ends with a "+N more" row that says how to scroll.
func (m model) keyPanelView(w, rows int) string {
	if rows < 1 {
		return ""
	}
	lines := keyPanelLines(m.keys, w)
	if len(lines) <= rows {
		return strings.Join(lines, "\n")
	}
	shown := rows - 1
	off := clamp(m.keyScroll, 0, len(lines)-shown)
	note := fmt.Sprintf(" +%d more, %s/%s to scroll", len(lines)-shown, m.keys.HistPrev.Help().Key, m.keys.HistNext.Help().Key)
	out := append(append([]string{}, lines[off:off+shown]...), lipgloss.NewStyle().MaxWidth(max(w, 1)).Render(Meta.Render(note)))
	return strings.Join(out, "\n")
}

// downHint is the first-use note printed under the banner when the first health
// probe finds a service down: what is down and how to fix it, wrapped to width.
// The LLM server is started separately from /up, so it gets its own advice with
// the configured URL, credentials removed.
func downHint(h *serviceHealth, width int) string {
	var local []string
	for _, s := range downServices(h) {
		if s != "llm" {
			local = append(local, s)
		}
	}
	var parts []string
	switch n := len(local); {
	case n == 1:
		parts = append(parts, local[0]+" is down. Run /up to start it.")
	case n > 1:
		parts = append(parts, strings.Join(local[:n-1], ", ")+" and "+local[n-1]+" are down. Run /up to start them.")
	}
	if !h.LLM {
		parts = append(parts, "The LLM is down: start the LLM server at "+redactedURL(omlxBaseURL())+".")
	}
	lines := strings.Split(wrapIndent(oneLine(sanitizeTerminal(strings.Join(parts, " "))), 3, width), "\n")
	for i, ln := range lines {
		lines[i] = Meta.Render(ln)
	}
	return strings.Join(lines, "\n")
}

// --- small helpers ---

func workingVerbLabel(verb string) string {
	switch verb {
	case "search":
		return "searching" + ellipsis()
	case "health":
		return "checking" + ellipsis()
	case "generate":
		return "answering" + ellipsis()
	case "engage":
		return "engaging" + ellipsis()
	default:
		return "thinking" + ellipsis()
	}
}

// generateQuestion is the question /generate synthesizes against: the explicit
// argument when given, otherwise the last search query.
func generateQuestion(arg, lastQuery string) string {
	if a := strings.TrimSpace(arg); a != "" {
		return a
	}
	return lastQuery
}

func ellipsis() string {
	if useUnicode {
		return "…"
	}
	return "..."
}

// openTarget is a file /open N can open, with the cited section to jump to.
type openTarget struct {
	Path    string
	Section string
}

func citationTargets(cits []citation) []openTarget {
	targets := make([]openTarget, len(cits))
	for i, c := range cits {
		targets[i] = openTarget{Path: c.Path, Section: c.Section}
	}
	return targets
}

func resultTargets(results []retrieval.Result) []openTarget {
	targets := make([]openTarget, len(results))
	for i, r := range results {
		targets[i] = openTarget{Path: r.Payload.Path, Section: r.Payload.Section}
	}
	return targets
}

func isUnreachable(err error) bool {
	return errors.Is(err, retrieval.ErrUnreachable)
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
