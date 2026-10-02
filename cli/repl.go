package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"blkchain/cli/internal/retrieval"
)

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
	mode := "rag"
	var rc replClient
	defer rc.close()
	// convo is the in-process conversation memory for this piped/non-TTY
	// session: prior user questions and model answers, carried back into each
	// rag ask so the model remembers the session (the TUI reads the same memory
	// from the history store). Agent-mode memory lives in the Hermes gateway.
	var convo []priorTurn
	recordConvo := func(q, ans string) {
		if strings.TrimSpace(ans) == "" {
			return
		}
		convo = append(convo, priorTurn{Role: "human", Content: q}, priorTurn{Role: "ai", Content: ans})
		// The full conversation is carried; the shared answer path compresses it
		// to the budget when it grows large, so nothing is truncated here.
	}
	// eng stays nil until the plain REPL gets an engage mode; the final DAG
	// snapshot below is dormant until then.
	var eng EngagementView
	var vz *vizRenderer

	fmt.Printf("%s  %s\n", H1.Render("blkChain"), Meta.Render(replBanner()))

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for {
		fmt.Print(Prompt.Render(replPrompt()))
		if !in.Scan() {
			fmt.Println()
			return in.Err()
		}
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		cmd, rest := splitFirst(line)
		// Accept both "/cmd" and bare "cmd" forms, matching the TUI.
		switch strings.ToLower(strings.TrimPrefix(cmd, "/")) {
		case "quit", "exit", "q":
			return nil
		case "help", "?":
			replHelp()
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
			fmt.Println(Meta.Render("/copy is only available in the interactive TUI"))
		case "mode":
			if mode == "agent" {
				mode = "rag"
			} else {
				mode = "agent"
			}
			fmt.Println(Meta.Render("mode: " + mode))
		case "agent":
			mode = "agent"
			fmt.Println(Meta.Render("mode: agent"))
		case "rag":
			if toggle, on, q := ragArg(rest); toggle {
				p := loadPrefs()
				p.Rag = on
				_ = savePrefs(p)
				fmt.Println(Meta.Render("rag " + boolOnOff(on)))
			} else if q != "" {
				ans, err := replForceAsk(q, &rc, convo)
				printErr(err)
				recordConvo(q, ans)
			} else {
				mode = "rag"
				fmt.Println(Meta.Render("mode: rag"))
			}
		case "search", "s":
			last = replSearch(rest, last, &rc)
		case "ask", "a":
			ans, err := replAsk(mode, rest, &rc, convo)
			printErr(err)
			recordConvo(rest, ans)
		case "hermes":
			printErr(runHermes([]string{rest}))
		case "open", "o":
			printErr(replOpen(rest, last))
		default:
			// Bare input with no recognized verb is an ask (matches the TUI); in
			// agent mode it runs the hermes agent instead.
			ans, err := replAsk(mode, line, &rc, convo)
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

// replForceAsk forces grounding for one query (the /rag <question> form),
// bypassing the router and the rag toggle. history is the prior conversation;
// it returns the answer text so the caller can record the turn.
func replForceAsk(query string, c *replClient, history []priorTurn) (string, error) {
	rc, err := c.get()
	if err != nil {
		return "", err
	}
	return askWith(rc, history, []string{"--rag", query})
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
type replClient struct{ rc *retrieval.Client }

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

// replAsk routes a question by mode: rag mode uses the RAG answer path
// (askWith); agent mode runs the hermes agent (subprocess one-shot). It mirrors
// the TUI's dual-mode dispatch for the non-TTY fallback. history is the prior
// conversation (rag mode only); it returns the answer text so the caller can
// record the turn. Agent mode keeps its memory in the Hermes gateway, so it
// returns no text.
func replAsk(mode, query string, c *replClient, history []priorTurn) (string, error) {
	if mode == "agent" {
		return "", runHermes([]string{query})
	}
	rc, err := c.get()
	if err != nil {
		return "", err
	}
	return askWith(rc, history, []string{query})
}

// replSearch runs a search, prints it, and returns the new results (or the
// previous ones on error/empty query, so `open N` keeps working).
func replSearch(query string, prev []retrieval.Result, c *replClient) []retrieval.Result {
	query = strings.TrimSpace(query)
	if query == "" {
		return prev
	}
	base, err := c.get()
	if err != nil {
		printErr(err)
		return prev
	}
	rc := followPrefs(base, loadPrefs())
	ctx, cancel := context.WithTimeout(context.Background(), loadConfig().RequestTimeout())
	defer cancel()
	results, err := rc.Search(ctx, query, 0, nil)
	if err != nil {
		printErr(err)
		return prev
	}
	printResults(query, results, 0)
	return results
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
func replGroups() []rowGroup {
	return []rowGroup{
		{hgAsk, []helpRow{
			{"<question>", "type a question with no command to ask it"},
			{"/ask <q>", replSpecDesc("ask")},
			{"/search <q>", replSpecDesc("search")},
			{"/open <N|path>", replSpecDesc("open")},
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
		{hgAgent, []helpRow{
			{"/hermes <prompt>", replSpecDesc("hermes")},
			{"/mode", replSlashDesc("mode")},
			{"/agent", replSlashDesc("agent")},
			{"/rag [on|off|question]", replSlashDesc("rag")},
		}},
		{hgSetup, []helpRow{
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
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

// printErr prints a non-nil error in the REPL without aborting the loop.
func printErr(err error) {
	reportError(os.Stderr, err)
}
