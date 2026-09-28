package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"blkchain/cli/internal/client"
)

// runREPL is the interactive loop entered by bare `blk` (or `blk repl`). Bare
// input is treated as a search; prefixes switch modes. It keeps the last search
// results so `open N` can open the N-th hit.
func runREPL() error {
	c := client.NewClient()
	var last []client.SearchResult

	fmt.Printf("%s  %s\n", bold("blkChain"), dim("interactive — type `help`, or a query to search; Ctrl-D to quit"))

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

		switch cmd {
		case "quit", "exit", "q":
			return nil
		case "help", "?":
			replHelp()
		case "health":
			printErr(runHealth(nil))
		case "up", "down", "status":
			printErr(runStack(cmd))
		case "ask", "a":
			printErr(runAsk([]string{rest}))
		case "agent", "hermes":
			printErr(runHermes([]string{rest}))
		case "open", "o":
			printErr(replOpen(rest, last))
		case "search", "s":
			last = replSearch(c, rest, last)
		default:
			// Bare input with no recognized verb is a search.
			last = replSearch(c, line, last)
		}
	}
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
	printResults(query, resp.Results)
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
  <query>            search (default)
  ask   <question>   synthesized, cited answer   (alias: a)
  agent <prompt>     answer via the Hermes agent (alias: hermes)
  open  <N|path>     open result N from the last search, or a path (alias: o)
  health             API + dependency status
  up | down | status manage the local services
  help               this help                   (alias: ?)
  quit               leave                        (alias: exit, q, Ctrl-D)
`, bold("REPL commands:"))
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
