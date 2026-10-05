package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"blkchain/cli/internal/retrieval"
)

type webCommand struct {
	action string
	value  string
	json   bool
	topK   int
}

func defineWebSearchFlags(fs *flag.FlagSet, c *webCommand) {
	fs.BoolVar(&c.json, "json", false, "print status or search results as JSON")
	fs.IntVar(&c.topK, "top-k", 5, "maximum search results (1 to 20)")
}

func parseWebCommand(args []string) (webCommand, error) {
	var c webCommand
	fs := newFlagSet("web")
	defineWebSearchFlags(fs, &c)
	if err := parseFlags(fs, reorder(args, map[string]bool{"top-k": true})); err != nil {
		return c, err
	}
	rest := fs.Args()
	c.action = "status"
	if len(rest) > 0 {
		c.action = strings.ToLower(rest[0])
		rest = rest[1:]
	}
	switch c.action {
	case "status", "on", "off":
		if len(rest) != 0 {
			return c, usageErr("web %s: unexpected arguments", c.action)
		}
	case "provider":
		if len(rest) != 1 || !validWebProvider(rest[0]) {
			return c, usageErr("web provider: choose auto, duckduckgo, or tavily")
		}
		c.value = rest[0]
	case "search":
		c.value = strings.Join(rest, " ")
		if c.value == "" {
			return c, usageErr("web search: missing query")
		}
		if c.topK < 1 || c.topK > webMaxResults {
			return c, usageErr("web search: top-k must be 1 to %d", webMaxResults)
		}
		if _, err := searchLimit(c.value, c.topK); err != nil {
			return c, usageErr("%s", err)
		}
	default:
		return c, usageErr("web: use status, on, off, provider, or search")
	}
	return c, nil
}

func validWebProvider(value string) bool {
	return value == webProviderAuto || value == webProviderDuckDuckGo || value == webProviderTavily
}

func applyWebCommand(p modelPrefs, c webCommand) (modelPrefs, string, error) {
	switch c.action {
	case "on":
		if activeWebProvider() == webProviderNone {
			return p, "", fmt.Errorf("web: provider unavailable; select duckduckgo or configure TAVILY_API_KEY")
		}
		p.Web = true
	case "off":
		p.Web = false
	case "provider":
		p.WebProvider = c.value
	case "status":
		return p, webStatus(p), nil
	default:
		return p, "", fmt.Errorf("web: search requires a network request")
	}
	if err := savePrefs(p); err != nil {
		return p, "", err
	}
	switch c.action {
	case "on":
		return p, "web on: answers may search the internet", nil
	case "off":
		return p, "web off: answers never search the web", nil
	default:
		return p, "web provider " + c.value, nil
	}
}

func webStatus(p modelPrefs) string {
	return fmt.Sprintf("web %s   provider %s (%s)", boolOnOff(p.Web), oneLine(sanitizeTerminal(webProviderSetting(p))), activeWebProvider())
}

func webSearchResults(ctx context.Context, c webCommand) ([]retrieval.Result, error) {
	if !loadPrefs().Web {
		return nil, fmt.Errorf("web: disabled; enable web before searching the internet")
	}
	return webSearch(ctx, tavilyKey(), c.value, c.topK, nil)
}

func runWebSearch(args []string) error {
	c, err := parseWebCommand(args)
	if err != nil {
		return err
	}
	if c.action == "search" {
		ctx, cancel := context.WithTimeout(context.Background(), loadConfig().RequestTimeout())
		defer cancel()
		if !c.json {
			_, _, _, err := printGroundedText(ctx, nil, loadConfig(), c.value, AnswerOpts{WebOnly: true, NoWeb: !loadPrefs().Web, SearchTopK: c.topK}, false)
			return err
		}
		results, err := webSearchResults(ctx, c)
		if err != nil {
			return err
		}
		return printJSON(searchResponse{Results: results})
	}
	p, note, err := applyWebCommand(loadPrefs(), c)
	if err != nil {
		return err
	}
	if c.json {
		return printJSON(webReport(p))
	}
	fmt.Println(Meta.Render(note))
	return nil
}

func replWebSearch(arg string, previous []retrieval.Result) []retrieval.Result {
	args, err := webArguments(arg)
	if err != nil {
		printErr(err)
		return previous
	}
	c, err := parseWebCommand(args)
	if err != nil {
		printErr(err)
		return previous
	}
	if c.action != "search" {
		printErr(runWebSearch(args))
		return previous
	}
	ctx, cancel := context.WithTimeout(context.Background(), loadConfig().RequestTimeout())
	defer cancel()
	if !c.json {
		_, _, results, err := printGroundedText(ctx, nil, loadConfig(), c.value, AnswerOpts{WebOnly: true, NoWeb: !loadPrefs().Web, SearchTopK: c.topK}, false)
		if err != nil {
			printErr(err)
			return previous
		}
		return results
	}
	results, err := webSearchResults(ctx, c)
	if err != nil {
		printErr(err)
		return previous
	}
	printErr(printJSON(searchResponse{Results: results}))
	return results
}

type webStatusReport struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	Selected string `json:"selected"`
}

func webReport(p modelPrefs) webStatusReport {
	return webStatusReport{p.Web, activeWebProvider(), webProviderSetting(p)}
}

func formatWebJSON(value any) (string, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", err
	}
	return string(escapeJSONControls(data)), nil
}

func runWeb(args []string) error {
	return runWebSearch(args)
}
