package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"blkchain/cli/internal/client"
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

// plainREPL is the non-TTY fallback: a simple line loop that mirrors the TUI's
// command model so behavior is consistent across both. Bare input is an ask
// (the headline verb for a Q&A KB); a leading "/" (or the bare verb) switches
// modes. It keeps the last search results so `open N` can open the N-th hit.
func plainREPL() error {
	c := client.NewClient()
	var last []client.SearchResult
	mode := "rag"

	fmt.Printf("%s  %s\n", bold("blkChain"), dim("type a question to ask · /mode · /search <q> · /help · Ctrl-D to quit"))

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for {
		fmt.Print(cyan("blk› "))
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
		case "copy":
			fmt.Println(dim("/copy is only available in the interactive TUI"))
		case "mode":
			if mode == "agent" {
				mode = "rag"
			} else {
				mode = "agent"
			}
			fmt.Println(dim("mode: " + mode))
		case "agent":
			mode = "agent"
			fmt.Println(dim("mode: agent"))
		case "rag":
			mode = "rag"
			fmt.Println(dim("mode: rag"))
		case "search", "s":
			last = replSearch(c, rest, last)
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
func replSearch(c *client.Client, query string, prev []client.SearchResult) []client.SearchResult {
	query = strings.TrimSpace(query)
	if query == "" {
		return prev
	}
	resp, err := c.Search(query, 0, nil)
	if err != nil {
		printErr(err)
		return prev
	}
	printResults(query, resp.Results, 0)
	return resp.Results
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

func replHelp() {
	fmt.Printf(`%s
  <question>          ask (rag streams a cited answer; agent runs Hermes)
  /mode              toggle rag / agent mode     (also /agent, /rag)
  /search <q>        find ranked source chunks   (alias: s)
  /ask <q>           ask explicitly              (alias: a)
  /hermes <prompt>   one-shot Hermes agent turn
  /open <N|path>     open result N from the last search, or a path (alias: o)
  /health            API + dependency status
  /up | /down | /status  manage the local services
  /doctor            diagnose the whole stack
  /logs [name]       tail a service log (api, embed_server)
  /copy              (TUI only; not available here)
  /help              this help                   (alias: ?)
  /quit              leave                        (alias: exit, q, Ctrl-D)
`, bold("Commands:"))
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
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", red("✗"), err)
	}
}
