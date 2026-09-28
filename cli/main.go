// Command blk is a command-line client for the blkChain RAG API.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"blkchain/cli/internal/client"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stdout)
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "search":
		err = runSearch(args)
	case "ask":
		err = runAsk(args)
	case "health":
		err = runHealth(args)
	case "up", "down", "status":
		err = runStack(cmd)
	case "install":
		err = runInstall(args)
	case "-h", "--help", "help":
		usage(os.Stdout)
		return
	default:
		fmt.Fprintf(os.Stderr, "%s unknown command %q\n\n", red("blk:"), cmd)
		usage(os.Stderr)
		os.Exit(2)
	}

	if err != nil {
		var unreachable *client.UnreachableError
		if errors.As(err, &unreachable) {
			fmt.Fprintf(os.Stderr, "%s %v\n%s  %s\n",
				red("✗"), err, dim("Start the services with:"), bold("blk up"))
		} else {
			fmt.Fprintf(os.Stderr, "%s %v\n", red("✗"), err)
		}
		os.Exit(1)
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `%s - command-line client for the blkChain RAG knowledge base

%s
  blk search <query...>     find ranked source chunks   %s
  blk ask <query...>        get a synthesized, cited answer
  blk up | down | status    start / stop / check the local services
  blk health                check that the API is up
  blk install               install blk onto your PATH (run once, from the project)
  blk help                  show this help

%s
  --top-k N    (search) how many results to return
  --json       print raw JSON instead of formatted text
  Flags may appear anywhere, before or after the query.

%s
  BLKCHAIN_API_URL   API base URL (default http://127.0.0.1:8200)
  BLKCHAIN_ROOT      project root, if blk is run from outside it and not installed
`,
		bold("blk"),
		bold("Commands:"),
		dim("(fast)"),
		bold("Flags:"),
		bold("Environment:"))
}

// runStack drives the service stack (up/down/status) via scripts/stack.sh,
// located dynamically from the saved config, the binary, or the working dir.
func runStack(cmd string) error {
	script, err := findStackScript()
	if err != nil {
		return err
	}
	c := exec.Command(script, cmd)
	c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
	return c.Run()
}

// reorder moves flag tokens ahead of positional args so flags may appear
// anywhere on the line. valueFlags names flags given as "--flag value" (a bool
// flag like --json takes no value); "--flag=value" and "--" are handled too.
func reorder(args []string, valueFlags map[string]bool) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" { // everything after -- is positional
			pos = append(pos, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(a, "=") && valueFlags[name] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func runSearch(args []string) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	topK := fs.Int("top-k", 0, "number of results to return")
	jsonOut := fs.Bool("json", false, "print raw JSON")
	if err := fs.Parse(reorder(args, map[string]bool{"top-k": true})); err != nil {
		return err
	}

	query := strings.Join(fs.Args(), " ")
	if query == "" {
		return errors.New("search: give me something to search for, e.g.  blk search SSRF to cloud metadata")
	}

	c := client.NewClient()
	resp, err := c.Search(query, *topK, nil)
	if err != nil {
		return err
	}

	if *jsonOut {
		return printJSON(resp)
	}

	if len(resp.Results) == 0 {
		fmt.Printf("No results for %q.\n", query)
		return nil
	}
	fmt.Printf("%s\n\n", bold(fmt.Sprintf("%d result(s) for %q", len(resp.Results), query)))
	for i, r := range resp.Results {
		meta := fmt.Sprintf("score %.4f", r.Score)
		if r.Payload.Section != "" {
			meta += " · " + r.Payload.Section
		}
		fmt.Printf("%s %s  %s\n", cyan(fmt.Sprintf("%d.", i+1)), bold(r.Payload.Source), dim(meta))
		if r.Payload.Path != "" {
			fmt.Printf("   %s\n", dim(r.Payload.Path))
		}
		fmt.Printf("   %s\n\n", truncate(r.Payload.Text, 240))
	}
	return nil
}

func runAsk(args []string) error {
	fs := flag.NewFlagSet("ask", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print raw JSON")
	if err := fs.Parse(reorder(args, nil)); err != nil {
		return err
	}

	query := strings.Join(fs.Args(), " ")
	if query == "" {
		return errors.New("ask: give me a question, e.g.  blk ask how do I chain this SSRF to RCE?")
	}

	c := client.NewClient()
	resp, err := c.Answer(query)
	if err != nil {
		return err
	}

	if *jsonOut {
		return printJSON(resp)
	}

	fmt.Println(resp.Answer)
	fmt.Println()
	fmt.Println(bold("Sources:"))
	if len(resp.Citations) == 0 {
		fmt.Println("  (none)")
	}
	for _, cit := range resp.Citations {
		line := "  " + dim("-") + " " + cit.Source
		if cit.Path != "" {
			line += " " + dim("("+cit.Path+")")
		}
		if cit.Section != "" {
			line += " " + dim(cit.Section)
		}
		fmt.Println(line)
	}
	if resp.UsedWeb {
		fmt.Println("\n" + dim("(this answer used a web search)"))
	}
	return nil
}

func runHealth(args []string) error {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	c := client.NewClient()
	h, err := c.Health()
	if err != nil {
		return err
	}
	fmt.Printf("%s blkChain API: %s  %s\n", green("✓"), h.Status, dim("("+c.BaseURL+")"))
	return nil
}

func printJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// truncate shortens s to at most n runes, appending "..." if it was cut.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}
