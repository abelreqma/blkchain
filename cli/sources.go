package main

import (
	"context"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"blkchain/cli/internal/retrieval"
)

// sourcesOpts holds the flags of `blk sources`.
type sourcesOpts struct{ json bool }

func defineSourcesFlags(fs *flag.FlagSet, o *sourcesOpts) {
	fs.BoolVar(&o.json, "json", false, "print JSON instead of formatted text")
}

// sourceJSON is one source in blk sources --json.
type sourceJSON struct {
	Source string `json:"source"`
	Chunks int    `json:"chunks"`
}

// sourcesResponse is what blk sources --json prints. partial is present, as
// true, only when the source list was cut off.
type sourcesResponse struct {
	Collection  string       `json:"collection"`
	TotalChunks int          `json:"total_chunks"`
	Sources     []sourceJSON `json:"sources"`
	Partial     bool         `json:"partial,omitempty"`
}

// runSources lists each indexed source with its chunk count. It only reads.
func runSources(args []string) error {
	var o sourcesOpts
	fs := newFlagSet("sources")
	defineSourcesFlags(fs, &o)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usageErr(`sources: takes no arguments, got %q. See "blk help sources".`, fs.Arg(0))
	}

	rc, err := newRetrievalClient(loadConfig())
	if err != nil {
		return err
	}
	defer rc.Close()
	rows, partial, err := rc.SourceCounts(context.Background())
	if err != nil {
		return err
	}
	collection := collectionName()
	if o.json {
		resp := sourcesResponse{Collection: collection, Sources: make([]sourceJSON, len(rows)), Partial: partial}
		for i, r := range rows {
			resp.Sources[i] = sourceJSON{Source: r.Source, Chunks: r.Count}
			resp.TotalChunks += r.Count
		}
		return printJSON(resp)
	}
	fmt.Print(formatSources(collection, rows, partial, terminalWidth()))
	return nil
}

// formatSources renders the SOURCES banner and one row per source, count
// right-aligned, or a friendly note when nothing is indexed. Source names come
// from the index and are untrusted, so each is sanitized and kept to one line:
// a name too long for the row is cut with an ellipsis, never wrapped.
func formatSources(collection string, rows []retrieval.SourceCount, partial bool, width int) string {
	if len(rows) == 0 {
		return " " + Body.Render("no sources indexed yet; add some with `blk add <path>`") + "\n"
	}
	hw := wrapWidth(width, 78)
	total := 0
	for _, r := range rows {
		total += r.Count
	}
	summary := fmt.Sprintf("%s %s, %s %s", commaInt(len(rows)), plural(len(rows), "source"),
		commaInt(total), plural(total, "chunk"))
	name := ellipsize(cleanLine(collection), hw-len("SOURCES  ")-utf8.RuneCountInString(summary)-2)
	banner := H1.Render("SOURCES") + "  " + H1.Render(name)

	var b strings.Builder
	fmt.Fprintln(&b, " "+headerLine(banner, Meta.Render(summary), width))
	fmt.Fprintln(&b)
	for _, r := range rows {
		count := commaInt(r.Count)
		title := ellipsize(cleanLine(r.Source), hw-3-len(count)-1)
		fmt.Fprintln(&b, headerLine("   "+Body.Render(title), Meta.Render(count), width))
	}
	if partial {
		fmt.Fprintf(&b, "\n %s\n", Meta.Render("counts are partial: the source list was cut off"))
	}
	return b.String()
}

// cleanLine strips terminal control sequences from s and folds its whitespace so
// it stays on one line.
func cleanLine(s string) string {
	return strings.Join(strings.Fields(sanitizeTerminal(s)), " ")
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// commaInt formats a non-negative n with thousands separators, such as 8,432.
func commaInt(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
