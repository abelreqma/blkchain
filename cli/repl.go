package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"blkchain/cli/internal/client"
	"blkchain/cli/internal/ragconfig"
	"golang.org/x/term"
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
// TERM is not "dumb" (CHARM-PATTERNS.md). Only then is the full TUI usable.
func isInteractive() bool {
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
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
	var last []client.SearchResult
	mode := "rag"

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
			mode = "rag"
			fmt.Println(Meta.Render("mode: rag"))
		case "search", "s":
			last = replSearch(rest, last)
		case "ask", "a":
			printErr(replAsk(mode, rest))
		case "hermes":
			printErr(runHermes([]string{rest}))
		case "open", "o":
			printErr(replOpen(rest, last))
		default:
			// Bare input with no recognized verb is an ask (matches the TUI); in
			// agent mode it runs the hermes agent instead.
			printErr(replAsk(mode, line))
		}
	}
}

// replAsk routes a question by mode: rag mode uses the RAG answer path
// (runAsk); agent mode runs the hermes agent (subprocess one-shot). It mirrors
// the TUI's dual-mode dispatch for the non-TTY fallback.
func replAsk(mode, query string) error {
	if mode == "agent" {
		return runHermes([]string{query})
	}
	return runAsk([]string{query})
}

// replSearch runs a search, prints it, and returns the new results (or the
// previous ones on error/empty query, so `open N` keeps working).
func replSearch(query string, prev []client.SearchResult) []client.SearchResult {
	query = strings.TrimSpace(query)
	if query == "" {
		return prev
	}
	rc, err := newRetrievalClient()
	if err != nil {
		printErr(err)
		return prev
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(ragconfig.Load().RequestTimeoutSeconds)*time.Second)
	defer cancel()
	results, err := rc.Search(ctx, query, 0, nil)
	if err != nil {
		printErr(err)
		return prev
	}
	adapted := toClientResults(results)
	printResults(query, adapted, 0)
	return adapted
}

// replOpen opens the N-th result from the last search, or a literal path.
func replOpen(arg string, last []client.SearchResult) error {
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
		return openFile(path, false)
	}
	return openFile(arg, false)
}

// replSpecDesc is a command's shared one-line description.
func replSpecDesc(name string) string {
	c, _ := lookupCommand(name)
	return c.desc
}

// replModelsDesc is /models' description from the slash-command registry: the
// plain REPL's /models is the TUI's, not the `blk models` report.
func replModelsDesc() string {
	c, _ := slashCommand("models")
	return c.desc
}

// replGroups lists the commands the plain REPL supports, in the same groups and
// with the same descriptions as the usage. Lines that exist only in the REPL
// (bare text, /mode, /quit) have their own wording.
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
			{"/models [verb <name>]", replModelsDesc()},
		}},
		{hgAgent, []helpRow{
			{"/hermes <prompt>", replSpecDesc("hermes")},
			{"/mode", "toggle ask between the knowledge base and Hermes"},
			{"/agent", "use Hermes for questions from now on"},
			{"/rag", "answer from the knowledge base again"},
		}},
		{hgSetup, []helpRow{
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
