package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"blkchain/cli/internal/histstore"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/secgate"

	"github.com/charmbracelet/bubbles/textarea"
)

var runPlainEngage func([]string) error

func invokePlainEngage(args []string) error {
	if runPlainEngage != nil {
		return runPlainEngage(args)
	}
	return runEngage(args)
}

// runREPL is the entry point for bare `blk` and `blk repl`/`chat`. On a real
// interactive terminal it runs the Bubble Tea TUI (tui.go); otherwise (piped
// stdin/stdout, or TERM=dumb) it falls back to the plain line loop so
// `echo q | blk` and `blk < file` still work and print clean text.
func runREPL() error {
	if isInteractive() {
		return runTUI()
	}
	return plainREPL()
}

// isInteractive reports whether both stdin and stdout are real terminals and
// TERM is not "dumb". Only then is the full TUI usable.
func isInteractive() bool {
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return isTerminalFile(os.Stdin) && isTerminalFile(os.Stdout)
}

// replBanner is the muted hint line printed when the plain REPL starts.
func replBanner() string {
	return joinSep("type a question", "/help for commands", "/quit or Ctrl-D to leave")
}

// replPrompt is the plain REPL prompt text.
func replPrompt() string {
	return "blk" + Glyph(GlyphPrompt) + " "
}

// plainREPL is the non-TTY fallback: a simple line loop that mirrors the TUI's
// command model so behavior is consistent across both. Bare input is an ask
// (the headline verb for a Q&A KB); a leading "/" (or the bare verb) switches
// modes. It keeps the last search results so `open N` can open the N-th hit.
func plainREPL() error {
	var last []retrieval.Result
	mode := "agent"
	pm := model{cfg: loadConfig(), mode: mode, hist: histstore.OpenDefault(), engageMode: secgate.Auto, engageTranscript: "important", ta: textarea.New()}
	pm.sess, _ = newSession()
	pm.ambient, _ = loadInitContext()
	if pm.hist != nil {
		defer pm.hist.Close()
	}
	draft := ""
	var rc replClient
	defer rc.close()
	// convo is the in-process conversation memory for this piped/non-TTY
	// session: prior user questions and model answers, carried back into each
	// rag ask so the model remembers the session (the TUI reads the same memory
	// from the history store). Agent-mode memory lives in the Hermes gateway.
	var convo []priorTurn
	recordConvo := func(q, ans string) {
		if rc.metrics != nil {
			calls, partial := rc.metrics.snapshot()
			cost := turnCost{elapsed: time.Since(rc.started), calls: calls, partial: partial}
			for _, call := range calls {
				if call.Stage == "synthesis" && call.UsageReported {
					cost.completionTokens = call.CompletionTokens
				}
			}
			pm.lastCost, pm.lastCostSet = cost, true
			rc.metrics = nil
		}
		if strings.TrimSpace(ans) == "" {
			return
		}
		convo = append(convo, priorTurn{Role: "human", Content: q}, priorTurn{Role: "ai", Content: ans})
		pm.mode, pm.pendingQ, pm.lastAnswer = mode, q, ans
		pm.recordTurn(ans)
		// The full conversation is carried; the shared answer path compresses it
		// to the budget when it grows large, so nothing is truncated here.
	}
	// eng stays nil until the plain REPL gets an engage mode; the final DAG
	// snapshot below is dormant until then.
	var eng EngagementView
	var vz *vizRenderer

	fmt.Printf("%s  %s\n", H1.Render("blkChain"), Meta.Render(replBanner()))

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), inputCharLimit+2)
	for {
		fmt.Print(Prompt.Render(replPrompt()))
		if !in.Scan() {
			fmt.Println()
			return in.Err()
		}
		line, cut := boundedDraftText(in.Text(), inputCharLimit)
		if cut {
			printErr(fmt.Errorf("input exceeds the draft limit; edit and retry"))
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" && draft != "" {
			line, draft = draft, ""
		}
		if line == "" {
			continue
		}
		cmd, rest := splitFirst(line)
		// Accept both "/cmd" and bare "cmd" forms, matching the TUI.
		switch strings.ToLower(strings.TrimPrefix(cmd, "/")) {
		case "quit", "exit", "q":
			return nil
		case "cost":
			fmt.Println(pm.costLine())
		case "help", "?":
			if strings.TrimSpace(rest) == "" {
				replHelp()
			} else {
				fmt.Println(helpResponse(rest, terminalWidth()))
			}
		case "health":
			printErr(runHealth(nil))
		case "up", "down", "status":
			printErr(runStack(strings.TrimPrefix(cmd, "/")))
		case "doctor":
			printErr(runDoctor(nil))
		case "logs":
			var largs []string
			if strings.TrimSpace(rest) != "" {
				largs = strings.Fields(rest)
			}
			printErr(runLogs(largs))
		case "models":
			printErr(replModels(rest))
		case "viz":
			p := loadPrefs()
			on, ok := vizNext(p.Viz, rest)
			if !ok {
				printErr(fmt.Errorf("viz: use on or off"))
				break
			}
			p.Viz = on
			_ = savePrefs(p)
			fmt.Println(Meta.Render(vizNote(on)))
		case "copy":
			if pm.lastAnswer == "" {
				printErr(fmt.Errorf("copy: no answer yet"))
			} else {
				printErr(copyToClipboard(pm.lastAnswer))
			}
		case "transcript":
			selected := strings.ToLower(strings.TrimSpace(rest))
			if !validTranscriptMode(selected) {
				printErr(fmt.Errorf("transcript: use off, important, or full"))
				break
			}
			pm.engageTranscript = selected
			fmt.Println(Meta.Render("transcript: " + selected))
		case "safe":
			pm.engageMode = secgate.Safe
			fmt.Println(Meta.Render("engagement mode: safe"))
		case "auto":
			pm.engageMode = secgate.Auto
			fmt.Println(Meta.Render("engagement mode: auto"))
		case "attach":
			if strings.TrimSpace(rest) == "" {
				printErr(fmt.Errorf("attach: provide a file path or HTTP(S) URL"))
			} else if err := pm.addPendingContext(rest); err != nil {
				printErr(err)
			} else {
				fmt.Println(pm.contextText())
			}
		case "context":
			text, err := pm.contextAction(rest)
			if err != nil {
				printErr(err)
			} else {
				fmt.Println(text)
			}
		case "queue":
			text, err := pm.queueAction(rest)
			if err != nil {
				printErr(err)
			} else {
				fmt.Println(text)
			}
		case "engage":
			parts := strings.Fields(rest)
			if len(parts) > 0 && parts[0] == "web" {
				printErr(replWeb(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), "web")), pm.engageMode, pm.engageTranscript))
				break
			}
			if strings.HasPrefix(rest, "resume /") || strings.HasPrefix(rest, "resume --workspace /") || strings.HasPrefix(rest, "resume \"") || strings.HasPrefix(rest, "resume --workspace \"") {
				path := strings.TrimSpace(strings.TrimPrefix(rest, "resume "))
				path = strings.TrimPrefix(path, "--workspace ")
				printErr(runEngage([]string{"resume", strings.Trim(path, `"`)}))
			} else {
				args := []string{"--transcript", pm.engageTranscript}
				if pm.engageMode == secgate.Safe {
					args = append(args, "--safe")
				}
				args = append(args, strings.Fields(rest)...)
				printErr(invokePlainEngage(args))
			}
		case "history":
			var err error
			convo, err = plainHistory(&pm, rest, convo)
			printErr(err)
		case "editor":
			var err error
			draft, err = plainEditor(draft)
			printErr(err)
		case "init":
			if ambient, ok := loadInitContext(); ok {
				pm.ambient = ambient
				fmt.Println(Meta.Render("loaded .blk/context.md"))
			} else {
				fmt.Println(Meta.Render("no .blk/context.md in this directory"))
			}
		case "clear":
			if err := pm.resetConversation(); err != nil {
				printErr(err)
			} else {
				draft, convo, last = "", nil, nil
				fmt.Println(Meta.Render("started a fresh session"))
			}
		case "undo":
			if err := pm.undoConversation(); err != nil {
				printErr(err)
			} else {
				if pm.hist != nil {
					convo = pm.conversationHistory()
				} else {
					convo = convo[:max(len(convo)-2, 0)]
				}
				last = nil
				fmt.Println(Meta.Render("undid the last question and answer"))
			}
		case "mode":
			if mode == "agent" {
				mode = "rag"
			} else {
				mode = "agent"
			}
			fmt.Println(Meta.Render("mode: " + mode))
		case "agent":
			if strings.TrimSpace(rest) == "" {
				fmt.Println(pm.answerAgentStatus())
			} else if err := pm.selectAnswerAgent(rest); err != nil {
				printErr(err)
			} else {
				mode = pm.mode
				rc.agent = pm.answerAgent
				fmt.Println(pm.answerAgentStatus())
			}
		case "rag":
			if toggle, on, q := ragArg(rest); toggle {
				p := loadPrefs()
				p.Rag = on
				_ = savePrefs(p)
				fmt.Println(Meta.Render("rag " + boolOnOff(on)))
			} else if q != "" {
				ans, err := plainAsk(mode, q, &rc, convo, pm.takeContextPreface(q), true)
				printErr(err)
				recordConvo(q, ans)
			} else {
				mode = "rag"
				fmt.Println(Meta.Render("mode: rag"))
			}
		case "web":
			last = replWebSearch(rest, last, rc.agent)
		case "search", "s":
			query := rest
			if !strings.HasPrefix(cmd, "/") && strings.EqualFold(cmd, "search") {
				ans, err := plainAsk(mode, line, &rc, convo, pm.takeContextPreface(line), false)
				printErr(err)
				recordConvo(line, ans)
				break
			}
			ans, results := replSearch(query, last, &rc, convo, pm.takeContextPreface(query))
			last = results
			recordConvo(query, ans)
		case "ask", "a":
			ans, err := plainAsk(mode, rest, &rc, convo, pm.takeContextPreface(rest), false)
			printErr(err)
			recordConvo(rest, ans)
		case "hermes":
			printErr(runHermes([]string{rest}))
		case "open", "o":
			printErr(replOpen(rest, last))
		default:
			if strings.HasPrefix(cmd, "/") {
				printErr(plainSlashError(cmd))
				break
			}
			// Bare input with no recognized verb is an ask (matches the TUI); in
			// agent mode it runs the hermes agent instead.
			ans, err := plainAsk(mode, line, &rc, convo, pm.takeContextPreface(line), false)
			printErr(err)
			recordConvo(line, ans)
		}
		// After a turn, print one final DAG block. There is no live bar off a TTY.
		if eng != nil && loadPrefs().Viz {
			if vz == nil {
				vz = newVizRenderer(newMmdfluxRunner())
			}
			plainVizSnapshot(os.Stdout, vz, eng)
		}
	}
}

// ragArg classifies a /rag argument. An empty argument is the mode select
// (handled by the caller). "on"/"off" (trimmed, case-folded) set the rag
// toggle. Any other argument is a question to force-ground.
func ragArg(arg string) (setToggle bool, on bool, question string) {
	a := strings.TrimSpace(arg)
	if a == "" {
		return false, false, ""
	}
	if strings.EqualFold(a, "on") {
		return true, true, ""
	}
	if strings.EqualFold(a, "off") {
		return true, false, ""
	}
	return false, false, a
}

func boolOnOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// plainVizSnapshot writes the current DAG block once, for output that has no
// live progress bar. It writes nothing when the block is empty or errors.
func plainVizSnapshot(w io.Writer, r *vizRenderer, v EngagementView) {
	block, _, err := r.Block(context.Background(), v)
	if err == nil && block != "" {
		fmt.Fprintln(w, block)
	}
}

// plainClarify asks a numbered question on a non-TTY. An empty line or EOF
// cancels, a number in range picks that option, and any other text is a custom
// instruction. The plain REPL is serial, so it needs no reply channel.
func plainClarify(in *bufio.Scanner, out io.Writer, c Clarification) ClarifyResult {
	fmt.Fprintln(out, H2.Render(c.Question))
	if c.Detail != "" {
		fmt.Fprintln(out, Meta.Render(c.Detail))
	}
	for i, o := range c.Options {
		fmt.Fprintf(out, "  %d) %s\n", i+1, o.Label)
	}
	fmt.Fprint(out, Prompt.Render("choose> "))
	if !in.Scan() {
		return ClarifyResult{Canceled: true}
	}
	line := strings.TrimSpace(in.Text())
	if line == "" {
		return ClarifyResult{Canceled: true}
	}
	if n, err := strconv.Atoi(line); err == nil && n >= 1 && n <= len(c.Options) {
		return ClarifyResult{Value: c.Options[n-1].Value}
	}
	return ClarifyResult{Custom: line}
}

// replClient is the plain REPL's one retrieval client, made on first use and
// closed when the loop ends.
type replClient struct {
	agent   string
	rc      *retrieval.Client
	metrics *callMetrics
	started time.Time
}

func (c *replClient) get() (*retrieval.Client, error) {
	if c.rc == nil {
		rc, err := newRetrievalClient(loadConfig())
		if err != nil {
			return nil, err
		}
		c.rc = rc
	}
	return c.rc, nil
}

func (c *replClient) close() {
	if c.rc != nil {
		c.rc.Close()
	}
}

// replSearch synthesizes an answer and retains its cited sources for open.
func replSearch(query string, prev []retrieval.Result, c *replClient, history []priorTurn, preface string) (string, []retrieval.Result) {
	query = strings.TrimSpace(query)
	if query == "" {
		return "", prev
	}
	c.metrics = &callMetrics{}
	c.started = time.Now()
	base, err := c.get()
	if err != nil {
		printErr(err)
		return "", prev
	}
	rc := followPrefs(base, loadPrefs())
	ctx, cancel := context.WithTimeout(context.Background(), loadConfig().RequestTimeout())
	defer cancel()
	ctx = context.WithValue(ctx, metricsKey{}, c.metrics)
	answer, citations, results, err := printGroundedText(ctx, rc, loadConfig(), query, AnswerOpts{Agent: c.agent, NoWeb: !loadPrefs().Web, History: history, Preface: preface}, rc.SkipRerank)
	if err != nil {
		printErr(err)
		return "", prev
	}
	cited := make([]retrieval.Result, 0, len(citations))
	for _, citation := range citations {
		for _, result := range results {
			if result.Payload.Source == citation.Source && result.Payload.Path == citation.Path && result.Payload.Section == citation.Section {
				cited = append(cited, result)
				break
			}
		}
	}
	return answer, cited
}

// replOpen opens the N-th result from the last search, or a literal path.
func replOpen(arg string, last []retrieval.Result) error {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return fmt.Errorf("open: give a result number (e.g. `open 2`) or a path")
	}
	if n, err := strconv.Atoi(arg); err == nil {
		if n < 1 || n > len(last) {
			return fmt.Errorf("open: no result %d (have %d)", n, len(last))
		}
		path := last[n-1].Payload.Path
		if path == "" {
			return fmt.Errorf("open: result %d has no file path", n)
		}
		return openFile(path, last[n-1].Payload.Section, false)
	}
	return openFile(arg, "", false)
}

// replSpecDesc is a command's shared one-line description.
func replSpecDesc(name string) string {
	c, _ := lookupCommand(name)
	return c.desc
}

// replSlashDesc is a command's description from the slash-command registry,
// for the lines the plain REPL shares with the TUI rather than the command
// line: /models (the TUI's /models, not the blk models report) and the modes.
func replSlashDesc(name string) string {
	c, _ := slashCommand(name)
	return c.desc
}

// replGroups lists the commands the plain REPL supports, in the same groups and
// with the same descriptions as the usage and the TUI. Lines that exist only in
// the REPL (bare text, /help, /quit) have their own wording.
// The REPL groups its slash commands by what the operator does in a session, so
// its titles are its own: the command line's ENGAGE/INTEGRATIONS split does not
// describe /safe, /auto or /undo.
const (
	replGroupAsk     = "ASK AND SEARCH"
	replGroupAgent   = "AGENT (HERMES)"
	replGroupSession = "SETUP"
)

func replGroups() []rowGroup {
	return []rowGroup{
		{replGroupAsk, []helpRow{
			{"<question>", "type a question with no command to ask it"},
			{"/ask <q>", replSpecDesc("ask")},
			{"/search <q>", replSpecDesc("search")},
			{"/web [action]", replSpecDesc("web")},
			{"/open <N|path>", replSpecDesc("open")},
		}},
		{groupModes, []helpRow{
			{"/agent [auto|name]", replSlashDesc("agent")},
		}},
		{hgServices, []helpRow{
			{"/up", replSpecDesc("up")},
			{"/down", replSpecDesc("down")},
			{"/status", replSpecDesc("status")},
			{"/health", replSpecDesc("health")},
			{"/doctor", replSpecDesc("doctor")},
			{"/logs [service]", replSpecDesc("logs")},
			{"/models [verb <name>]", replSlashDesc("models")},
		}},
		{replGroupAgent, []helpRow{
			{"/hermes <prompt>", replSpecDesc("hermes")},
			{"/engage [flags] <goal>", replSpecDesc("engage")},
			{"/engage web <action>", "assess web targets within an engagement"},
			{"/transcript <mode>", "show off, important, or full action output"},
			{"/safe", "approve engagement actions interactively"},
			{"/auto", "run within the active RoE without prompts"},
			{"/mode", replSlashDesc("mode")},
			{"/rag [on|off|question]", replSlashDesc("rag")},
		}},
		{replGroupSession, []helpRow{
			{"/attach <path|URL>", replSlashDesc("attach")},
			{"/context [action]", replSlashDesc("context")},
			{"/queue [action]", replSlashDesc("queue")},
			{"/undo", replSlashDesc("undo")},
			{"/cost", replSlashDesc("cost")},
			{"/history [n|clear [n]]", replSlashDesc("history")},
			{"/editor", replSlashDesc("editor")},
			{"/init", replSlashDesc("init")},
			{"/copy", replSlashDesc("copy")},
			{"/clear", replSlashDesc("clear")},
			{"/viz [on|off]", replSlashDesc("viz")},
			{"/help", "show this list"},
			{"/quit", "leave (also Ctrl-D)"},
		}},
	}
}

// replHelp prints the plain REPL's command reference: the usage's groups,
// limited to what the plain REPL supports, laid out to fit the terminal.
func replHelp() {
	total := helpWidth(terminalWidth())
	var b strings.Builder
	for gi, g := range replGroups() {
		if gi > 0 {
			b.WriteString("\n")
		}
		b.WriteString(H2.Render(g.title) + "\n")
		writeRows(&b, g.rows, 2, total, Key, Meta)
	}
	b.WriteString("\n")
	writePara(&b, "Press Ctrl-D or type /quit to leave.", 0, total, Meta)
	fmt.Print(b.String())
}

// splitFirst splits s into its first whitespace-delimited word and the rest.
func splitFirst(s string) (first, rest string) {
	s = strings.TrimSpace(s)
	if i := strings.IndexFunc(s, unicode.IsSpace); i >= 0 {
		return s[:i], strings.TrimSpace(s[i:])
	}
	return s, ""
}

// printErr prints a non-nil error in the REPL without aborting the loop.
func printErr(err error) {
	reportError(os.Stderr, err)
}
