// Command blk is a command-line client for the blkChain RAG API.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/qdrant/go-client/qdrant"

	"blkchain/cli/internal/client"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

// defaultCollection is the Qdrant collection used when BLKCHAIN_COLLECTION is
// unset, matching the Python engine's code default (blkchain.config).
const defaultCollection = "blkchain"

// newRetrievalClient builds a Go-native retrieval client (Task 8): it reads
// the shared RAG config plus BLKCHAIN_COLLECTION, replacing the Python
// /search HTTP call for the search command and RAG streaming.
func newRetrievalClient() (*retrieval.Client, error) {
	cfg := ragconfig.Load()
	collection := os.Getenv("BLKCHAIN_COLLECTION")
	if collection == "" {
		collection = defaultCollection
	}
	return retrieval.New(cfg, collection)
}

// toClientResults adapts retrieval.Result (the Go-native retrieval package's
// output) to client.SearchResult (identical fields), so the existing
// printResults/formatResults rendering and the --json output shape stay
// unchanged.
func toClientResults(rs []retrieval.Result) []client.SearchResult {
	out := make([]client.SearchResult, len(rs))
	for i, r := range rs {
		out[i] = client.SearchResult{
			ID:    r.ID,
			Score: r.Score,
			Payload: client.Payload{
				Source:  r.Payload.Source,
				Path:    r.Payload.Path,
				Section: r.Payload.Section,
				Type:    r.Payload.Type,
				Text:    r.Payload.Text,
			},
		}
	}
	return out
}

func main() {
	loadProjectEnv()

	if len(os.Args) < 2 {
		// Bare `blk` drops into the interactive REPL — the friendliest entry
		// point for repeated search/ask without re-invoking the binary.
		if err := runREPL(); err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", Fail.Render(Glyph(GlyphErr)), err)
			os.Exit(1)
		}
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
	case "add":
		err = runAdd(args)
	case "health":
		err = runHealth(args)
	case "up", "down", "status":
		err = runStack(cmd)
	case "mcp":
		err = runMCP(args)
	case "install":
		err = runInstall(args)
	case "doctor":
		err = runDoctor(args)
	case "models":
		err = runModels(args)
	case "logs":
		err = runLogs(args)
	case "open":
		err = runOpen(args)
	case "hermes":
		err = runHermes(args)
	case "gateway":
		err = runGateway(args)
	case "repl", "chat":
		err = runREPL()
	case "version", "--version", "-v":
		printVersion(os.Stdout)
		return
	case "completion":
		err = runCompletion(args)
	case "-h", "--help", "help":
		usage(os.Stdout)
		return
	default:
		fmt.Fprintf(os.Stderr, "%s unknown command %q\n\n", Fail.Render("blk:"), cmd)
		usage(os.Stderr)
		os.Exit(2)
	}

	if err != nil {
		var unreachable *client.UnreachableError
		if errors.As(err, &unreachable) {
			fmt.Fprintf(os.Stderr, "%s %v\n%s  %s\n",
				Fail.Render(Glyph(GlyphErr)), err, Meta.Render("Start the services with:"), Key.Render("blk up"))
		} else {
			fmt.Fprintf(os.Stderr, "%s %v\n", Fail.Render(Glyph(GlyphErr)), err)
		}
		os.Exit(1)
	}
}

// usageCmd is one row of the COMMANDS section: a command name (as typed
// after "blk"), its description, and whether it's the primary/default verb
// marked with the accent ❯ (DESIGN-SPEC.md §3's help mockup).
type usageCmd struct {
	name    string
	desc    string
	primary bool
}

var usageCmds = []usageCmd{
	{"ask <query...>", "get a synthesized, cited answer", true},
	{"search <query...>", "find ranked source chunks", false},
	{"add <path|url>", "index your own docs into the KB", false},
	{"repl", "interactive REPL (bare blk too — search/ask without re-launching)", false},
	{"open <path|N>", "open a source file in $PAGER/$EDITOR", false},
	{"hermes <prompt...>", "run a Hermes agent turn (has the blkChain KB tools)", false},
	{"gateway", "provision ~/.hermes/.env + start hermes gateway (richer agent mode)", false},
	{"up|down|status", "start / stop / check the local services", false},
	{"mcp", "run the Hermes MCP stdio server (for ~/.hermes/config.yaml)", false},
	{"health", "check the API and its dependencies", false},
	{"doctor", "diagnose the whole stack (+ Hermes MCP wiring)", false},
	{"models", "readiness + live perf of the chat/embed/rerank models", false},
	{"logs [name]", "tail a service log (api, embed_server)", false},
	{"install", "install blk onto your PATH (run once, from the project)", false},
	{"version", "show version and build info", false},
	{"completion bash|zsh", "print a shell-completion script", false},
	{"help", "show this help", false},
}

// usageRow is a name/description pair, used for FLAGS and ENVIRONMENT.
type usageRow struct{ name, desc string }

var usageFlags = []usageRow{
	{"--top-k N", "(search) how many results to return"},
	{"--source S", "(search) only results from source S (repeatable)"},
	{"--type T", "(search) only results of type T"},
	{"--filter k=v", "(search) arbitrary payload filter (repeatable)"},
	{"--sources", "(ask) also print the retrieved chunks"},
	{"--agent", "(ask) answer via the Hermes agent instead of plain RAG"},
	{"--source S", "(add) source label (default: derived from the path)"},
	{"--type T", "(add) force chunking as md, txt, or pdf"},
	{"--json", "print raw JSON instead of formatted text"},
}

var usageEnv = []usageRow{
	{"BLKCHAIN_API_URL", "API base URL (default http://127.0.0.1:8200)"},
	{"BLKCHAIN_ROOT", "project root, if blk is run from outside it and not installed"},
	{"NO_COLOR", "disable colored output"},
}

// usage prints the help menu per DESIGN-SPEC.md §3: an H1 banner + version,
// a single rule, then H2 sections with Key-styled names and Body
// descriptions. The primary command is marked with the accent ❯.
func usage(w *os.File) {
	v, _, _, _ := versionInfo()
	fmt.Fprintln(w, " "+headerLine(H1.Render("blk · knowledge-base client"), Meta.Render(v)))
	fmt.Fprintln(w, " "+RuleS.Render(strings.Repeat("─", wrapWidth(terminalWidth(), 78))))

	fmt.Fprintln(w, " "+H2.Render("USAGE"))
	fmt.Fprintf(w, "   %s\n", Key.Render("blk <command> [flags]"))

	fmt.Fprintln(w, " "+H2.Render("COMMANDS"))
	nameWidth := 0
	for _, c := range usageCmds {
		if len(c.name) > nameWidth {
			nameWidth = len(c.name)
		}
	}
	for _, c := range usageCmds {
		marker := "  "
		if c.primary {
			marker = Prompt.Render(Glyph(GlyphPrompt)) + " "
		}
		fmt.Fprintf(w, " %s%s  %s\n", marker, Key.Render(pad(c.name, nameWidth)), Body.Render(c.desc))
	}

	fmt.Fprintln(w, " "+H2.Render("FLAGS"))
	printUsageRows(w, usageFlags)
	fmt.Fprintf(w, "   %s\n", Meta.Render("Flags may appear anywhere, before or after the query."))

	fmt.Fprintln(w, " "+H2.Render("ENVIRONMENT"))
	printUsageRows(w, usageEnv)

	fmt.Fprintf(w, " %s\n", Meta.Render(`Run "blk <command> --help" for detail.`))
}

// printUsageRows renders a FLAGS/ENVIRONMENT-style two-column block: Key name
// padded to align, Meta description.
func printUsageRows(w *os.File, rows []usageRow) {
	width := 0
	for _, r := range rows {
		if len(r.name) > width {
			width = len(r.name)
		}
	}
	for _, r := range rows {
		fmt.Fprintf(w, "   %s   %s\n", Key.Render(pad(r.name, width)), Meta.Render(r.desc))
	}
}

// pad right-pads s with spaces to width (a no-op if s is already that long).
func pad(s string, width int) string {
	if n := width - len(s); n > 0 {
		return s + strings.Repeat(" ", n)
	}
	return s
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
	var sources, filters multiFlag
	var typ string
	fs.Var(&sources, "source", "only results from this source (repeatable)")
	fs.StringVar(&typ, "type", "", "only results of this type")
	fs.Var(&filters, "filter", "payload filter key=value (repeatable)")
	valueFlags := map[string]bool{"top-k": true, "source": true, "type": true, "filter": true}
	if err := fs.Parse(reorder(args, valueFlags)); err != nil {
		return err
	}

	query := strings.Join(fs.Args(), " ")
	if query == "" {
		return errors.New("search: give me something to search for, e.g.  blk search SSRF to cloud metadata")
	}

	filterMap, err := buildFilters(sources, typ, filters)
	if err != nil {
		return err
	}

	rc, err := newRetrievalClient()
	if err != nil {
		return err
	}
	start := time.Now()
	results, err := rc.Search(context.Background(), query, *topK, filterMap)
	elapsed := time.Since(start)
	if err != nil {
		return err
	}
	adapted := toClientResults(results)

	if *jsonOut {
		return printJSON(client.SearchResponse{Results: adapted})
	}
	printResults(query, adapted, elapsed)
	return nil
}

// buildFilters folds --source/--type/--filter into the API's {field: value}
// filter map. Later values win on key collision; an empty result is nil (no
// filtering), which the API treats as "match everything".
func buildFilters(sources multiFlag, typ string, kv multiFlag) (map[string]interface{}, error) {
	m := map[string]interface{}{}
	for _, s := range sources {
		m["source"] = s // last --source wins; the API filter is single-valued per field
	}
	if typ != "" {
		m["type"] = typ
	}
	for _, f := range kv {
		k, v, ok := strings.Cut(f, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("search: --filter must be key=value, got %q", f)
		}
		m[k] = v
	}
	if len(m) == 0 {
		return nil, nil
	}
	return m, nil
}

// printResults renders ranked search results per DESIGN-SPEC.md §3's SEARCH
// banner + ranked-row layout (rank Meta, title Body, path Meta, score
// right-aligned and banded via scoreStyle), or a friendly empty message.
// elapsed is omitted from the banner when zero (the --sources path under
// runAsk has no separate timing to show).
func printResults(query string, results []client.SearchResult, elapsed time.Duration) {
	fmt.Print(formatResults(query, results, elapsed))
}

// formatResults builds the same rendering as printResults but returns it as a
// string, so the TUI REPL can commit it to scrollback via tea.Println instead
// of writing straight to stdout (which would corrupt the live region).
func formatResults(query string, results []client.SearchResult, elapsed time.Duration) string {
	var b strings.Builder
	if len(results) == 0 {
		fmt.Fprintf(&b, " %s\n", Body.Render(fmt.Sprintf("No results for %q.", query)))
		return b.String()
	}

	banner := H1.Render("SEARCH") + "  " + H1.Render(fmt.Sprintf("%q", query))
	count := fmt.Sprintf("%d result(s)", len(results))
	if elapsed > 0 {
		count = fmt.Sprintf("%s · %s", count, elapsed.Round(time.Millisecond))
	}
	fmt.Fprintln(&b, " "+headerLine(banner, Meta.Render(count)))
	fmt.Fprintln(&b)

	for i, r := range results {
		title := r.Payload.Source
		if r.Payload.Section != "" {
			title += " · " + r.Payload.Section
		}
		left := fmt.Sprintf(" %s  %s", Meta.Render(fmt.Sprintf("%2d", i+1)), Body.Render(title))
		score := scoreStyle(r.Score).Render(fmt.Sprintf("%.4f", r.Score))
		fmt.Fprintln(&b, headerLine(left, score))
		if r.Payload.Path != "" {
			fmt.Fprintf(&b, "      %s\n", Meta.Render(r.Payload.Path))
		}
		fmt.Fprintf(&b, "      %s\n\n", truncate(r.Payload.Text, 240))
	}
	return b.String()
}

func runAsk(args []string) error {
	fs := flag.NewFlagSet("ask", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print raw JSON")
	showSources := fs.Bool("sources", false, "also print the retrieved chunks")
	agent := fs.Bool("agent", false, "answer via the Hermes agent instead of plain RAG")
	if err := fs.Parse(reorder(args, nil)); err != nil {
		return err
	}

	query := strings.Join(fs.Args(), " ")
	if query == "" {
		return errors.New("ask: give me a question, e.g.  blk ask how do I chain this SSRF to RCE?")
	}

	// --agent hands the question to the Hermes agent (which has the blkChain KB
	// tools plus web/tool access), rather than the Go answer loop.
	if *agent {
		return runHermes([]string{query})
	}

	rc, err := newRetrievalClient()
	if err != nil {
		return err
	}
	cfg := ragconfig.Load()

	// Only the plain text path streams: --json needs the full struct and
	// --sources needs the retrieved chunks, neither of which the token stream
	// carries.
	if !*jsonOut && !*showSources {
		var full strings.Builder
		_, cits, usedWeb, _, _, err := AnswerLoop(context.Background(), rc, cfg, query, AnswerOpts{
			Stream: func(b []byte) {
				full.Write(b)
				os.Stdout.Write(b)
			},
		})
		if err != nil && full.Len() == 0 {
			return err
		}
		if !strings.HasSuffix(full.String(), "\n") {
			fmt.Println()
		}
		printSources(cits, usedWeb)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s stream ended early: %v\n", Fail.Render(Glyph(GlyphErr)), err)
		}
		return nil
	}

	answer, cits, usedWeb, results, _, err := AnswerLoop(context.Background(), rc, cfg, query, AnswerOpts{})
	if err != nil {
		return err
	}
	resp := &client.AnswerResponse{
		Answer:    answer,
		Citations: cits,
		UsedWeb:   usedWeb,
		Results:   toClientResults(results),
	}

	if *jsonOut {
		return printJSON(resp)
	}

	// Glow-format markdown output (BUILD-BRIEF.md): let glamour own the
	// answer body's rendering instead of hand-formatting it.
	fmt.Println(strings.TrimRight(glowRender(resp.Answer, terminalWidth()), "\n"))
	if *showSources && len(resp.Results) > 0 {
		fmt.Println()
		fmt.Println(H2.Render("RETRIEVED CHUNKS"))
		fmt.Println()
		printResults(query, resp.Results, 0)
	}
	printSources(resp.Citations, resp.UsedWeb)
	return nil
}

// printSources renders the SOURCES block to stdout, shared by the streaming and
// non-streaming ask paths.
func printSources(citations []client.Citation, usedWeb bool) {
	fmt.Println()
	fmt.Println(H2.Render("SOURCES"))
	if len(citations) == 0 {
		fmt.Println("  " + Meta.Render("(none)"))
	}
	for i, cit := range citations {
		line := "  " + Key.Render(fmt.Sprintf("[%d]", i+1)) + "  " + Body.Render(cit.Source)
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
		fmt.Println(line)
	}
	if usedWeb {
		fmt.Println()
		fmt.Println(Meta.Render("(this answer used a web search)"))
	}
}

func runHealth(args []string) error {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := ragconfig.Load()
	qdrantOK, embedOK := probeHealth(cfg)
	fmt.Println("blkChain services:")
	fmt.Printf("  %s qdrant        %s\n", check(qdrantOK), Meta.Render("("+cfg.QdrantGRPCURL+")"))
	fmt.Printf("  %s embed_server  %s\n", check(embedOK), Meta.Render("("+cfg.EmbedServerURL+")"))
	return nil
}

// healthProbeTimeout bounds each liveness probe so `blk health` never hangs
// on a dead dependency.
const healthProbeTimeout = 4 * time.Second

// probeHealth checks Qdrant and embed_server directly (Task 16), replacing
// the old dependency on the Python API's GET /health. The two probes are
// independent so one dead dependency never masks the state of the other.
func probeHealth(cfg ragconfig.Config) (qdrantOK, embedOK bool) {
	return probeQdrant(cfg), probeEmbedServer(cfg)
}

// probeQdrant dials Qdrant's gRPC endpoint and issues a real liveness RPC
// (HealthCheck). qdrant.NewClient itself never dials eagerly, so failure can
// only be observed by making a call.
func probeQdrant(cfg ragconfig.Config) bool {
	host, port := qdrantHostPort(cfg.QdrantGRPCURL)
	qc, err := qdrant.NewClient(&qdrant.Config{
		Host: host,
		Port: port,
		// Skip the server-version compatibility check: it performs its own
		// RPC during NewClient, which we don't need since HealthCheck below
		// already proves liveness.
		SkipCompatibilityCheck: true,
	})
	if err != nil {
		return false
	}
	defer qc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), healthProbeTimeout)
	defer cancel()
	_, err = qc.HealthCheck(ctx)
	return err == nil
}

// qdrantHostPort parses a "host:port" address, defaulting the port to 6334
// (Qdrant's gRPC default) when absent. Mirrors
// internal/retrieval.splitHostPort so the health probe dials the same target
// `blk search` does.
func qdrantHostPort(addr string) (string, int) {
	const defaultPort = 6334
	if addr == "" {
		return "127.0.0.1", defaultPort
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, defaultPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, defaultPort
	}
	return host, port
}

// probeEmbedServer proves embed_server can actually serve a request: a tiny
// POST to /embed with one word, bounded by a short timeout and a capped
// response read so a misbehaving endpoint cannot hang or exhaust memory.
func probeEmbedServer(cfg ragconfig.Config) bool {
	body, err := json.Marshal(map[string][]string{"texts": {"ping"}})
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), healthProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.EmbedServerURL+"/embed", bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: healthProbeTimeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	return resp.StatusCode == http.StatusOK
}

// check renders the theme's OK/Fail glyph for a boolean dependency state
// (DESIGN-SPEC.md §2, §4).
func check(ok bool) string {
	if ok {
		return OK.Render(Glyph(GlyphOK))
	}
	return Fail.Render(Glyph(GlyphErr))
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

// multiFlag is a flag.Value that accumulates repeated occurrences, so a flag
// like --source may be given more than once.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
