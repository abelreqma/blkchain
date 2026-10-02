// Command blk is the blkChain client: search, cited answers, the MCP server,
// and the local service stack.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

// defaultCollection is the Qdrant collection used when BLKCHAIN_COLLECTION is
// unset, matching the indexer's code default (blkchain.config).
const defaultCollection = "blkchain"

// collectionName is the Qdrant collection blk reads: BLKCHAIN_COLLECTION, or
// defaultCollection when it is unset.
func collectionName() string {
	if c := os.Getenv("BLKCHAIN_COLLECTION"); c != "" {
		return c
	}
	return defaultCollection
}

// newRetrievalClient builds a retrieval client from cfg plus
// BLKCHAIN_COLLECTION. It follows the saved reranker switch (/models). The
// caller closes it.
func newRetrievalClient(cfg ragconfig.Config) (*retrieval.Client, error) {
	rc, err := retrieval.New(cfg, collectionName())
	if err != nil {
		return nil, err
	}
	return followPrefs(rc, loadPrefs()), nil
}

// followPrefs returns a copy of rc that skips the reranker when p turns it off.
// A long-running server applies it per call, so a /models change reaches it
// without a restart.
func followPrefs(rc *retrieval.Client, p modelPrefs) *retrieval.Client {
	c := *rc
	c.SkipRerank = !p.Rerank
	return &c
}

// searchResponse is what blk search --json prints.
type searchResponse struct {
	Results []retrieval.Result `json:"results"`
}

// citation is one source of an answer, as blk ask --json and kb_answer
// report it.
type citation struct {
	Source  string `json:"source"`
	Path    string `json:"path"`
	Section string `json:"section"`
	// Untrusted is true for a web citation, whose text came from the open web
	// and not the local corpus. Local citations omit it.
	Untrusted bool `json:"untrusted,omitempty"`
}

// answerResponse is what blk ask --json prints. Results carries the retrieved
// chunks the answer was synthesized from, so callers can show the evidence
// behind an answer, not just the citation list.
type answerResponse struct {
	Answer    string     `json:"answer"`
	Citations []citation `json:"citations"`
	UsedWeb   bool       `json:"used_web"`
	// Model is the model blk requested for this answer. It is the id blk sent,
	// not one the server reported back.
	Model   string             `json:"model"`
	Results []retrieval.Result `json:"results,omitempty"`
	// Route is the retrieval decision for this answer: "skip", "rag", or "web".
	Route string `json:"route,omitempty"`
}

// serviceHealth is one probe of the services an answer needs.
type serviceHealth struct {
	Qdrant, EmbedServer, LLM bool
	// LLMRedirect is set when the LLM server answered with a redirect, which
	// blk does not follow.
	LLMRedirect bool
}

// ok reports whether every service answered.
func (h serviceHealth) ok() bool { return h.Qdrant && h.EmbedServer && h.LLM }

func main() {
	loadProjectEnv()
	err := execute(os.Args[1:])
	reportError(os.Stderr, err)
	os.Exit(exitCode(err))
}

// execute runs blk with the arguments after the program name. No arguments
// starts the interactive session, the friendliest entry point for repeated
// search and ask without re-invoking the binary.
func execute(args []string) error {
	if len(args) == 0 {
		return runREPL()
	}
	return dispatch(args[0], args[1:])
}

// dispatch runs the named command. A help flag as the first argument prints
// the command's help for every command, including those that take no flags.
func dispatch(cmd string, args []string) error {
	if cmd == "__vizdemo" { // hidden dev driver, deliberately not in the registry or help
		return runVizDemo()
	}
	c, ok := lookupCommand(cmd)
	if !ok {
		return unknownCommand(cmd)
	}
	if helpRequested(args) {
		printCommandHelp(os.Stdout, c)
		return nil
	}
	return c.run(args)
}

// runVizDemo is a DEMO and verification vehicle, not a shipped feature. It
// drives the progress view end to end against the real mmdflux: a scripted
// stub engagement advances step by step, printing the committed DAG block when
// the revision changed and a live-bar line (the shape of model.vizBar).
func runVizDemo() error {
	stub := newStubEngagement("acme")
	r := newVizRenderer(newMmdfluxRunner())
	ctx := context.Background()

	task := func(id, kind, target string, st eng.Status, deps ...string) eng.Task {
		return eng.Task{ID: id, Kind: kind, Target: target, Objective: target, Status: st, DependsOn: deps}
	}
	steps := []eng.Engagement{
		{
			Tasks: []eng.Task{
				task("recon", "recon", "acme.test", eng.StatusDone),
				task("enum", "enum", "services", eng.StatusActive, "recon"),
				task("sqli", "web", "SQLi /login", eng.StatusTodo, "enum"),
			},
			ActiveID: "enum",
			Stage:    eng.Stage{Label: "enum: services", Step: 1, Total: 4},
		},
		{
			Tasks: []eng.Task{
				task("recon", "recon", "acme.test", eng.StatusDone),
				task("enum", "enum", "services", eng.StatusDone, "recon"),
				task("sqli", "web", "SQLi /login", eng.StatusActive, "enum"),
			},
			ActiveID: "sqli",
			Stage:    eng.Stage{Label: "web: SQLi", Step: 2, Total: 4},
		},
		{
			Tasks: []eng.Task{
				task("recon", "recon", "acme.test", eng.StatusDone),
				task("enum", "enum", "services", eng.StatusDone, "recon"),
				task("sqli", "web", "SQLi /login", eng.StatusDone, "enum"),
				task("idor", "web", "IDOR /api/orders", eng.StatusActive, "enum"),
				task("evidence", "evidence", "findings", eng.StatusTodo, "sqli", "idor"),
			},
			ActiveID: "idor",
			Stage:    eng.Stage{Label: "web: IDOR", Step: 3, Total: 4},
		},
		{
			Tasks: []eng.Task{
				task("recon", "recon", "acme.test", eng.StatusDone),
				task("enum", "enum", "services", eng.StatusDone, "recon"),
				task("sqli", "web", "SQLi /login", eng.StatusDone, "enum"),
				task("idor", "web", "IDOR /api/orders", eng.StatusDone, "enum"),
				task("evidence", "evidence", "findings", eng.StatusDone, "sqli", "idor"),
				task("report", "report", "acme", eng.StatusActive, "evidence"),
			},
			ActiveID: "report",
			Stage:    eng.Stage{Label: "report", Step: 4, Total: 4},
		},
	}

	bar := func(e eng.Engagement) string {
		frac := float64(e.Stage.Step) / float64(e.Stage.Total)
		return " " + sanitizeTerminal(e.Stage.Label) + "  " + plMeter(frac, 12, plCurrentTier()) +
			fmt.Sprintf("  %d/%d", e.Stage.Step, e.Stage.Total)
	}
	show := func(label string) error {
		block, changed, err := r.Block(ctx, stub)
		if err != nil {
			return err
		}
		fmt.Println(label)
		if changed {
			fmt.Println(block)
		} else {
			fmt.Println("(no revision change, no new block)")
		}
		return nil
	}
	for i, e := range steps {
		stub.setSnapshot(e)
		if err := show(fmt.Sprintf("--- step %d ---", i+1)); err != nil {
			return err
		}
		fmt.Println(bar(e))
		time.Sleep(300 * time.Millisecond)
		if i == 1 { // same revision again: must print no new block
			if err := show("--- step 2 (unchanged) ---"); err != nil {
				return err
			}
		}
	}
	return nil
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

// searchOpts holds the flags of `blk search`.
type searchOpts struct {
	topK    int
	json    bool
	sources multiFlag
	typ     string
	filters multiFlag
}

// defineSearchFlags declares `blk search`'s flags. Placeholders are the
// backquoted words, which the FLAGS help section shows after each flag name.
func defineSearchFlags(fs *flag.FlagSet, o *searchOpts, defaultTopK int) {
	fs.IntVar(&o.topK, "top-k", 0, fmt.Sprintf("return `N` results (default %d)", defaultTopK))
	fs.BoolVar(&o.json, "json", false, "print JSON instead of formatted text")
	fs.Var(&o.sources, "source", "only results from source `NAME` (the last one wins)")
	fs.StringVar(&o.typ, "type", "", "only results of this `TYPE`, such as doc, note, or payload")
	fs.Var(&o.filters, "filter", "match a payload field, as `KEY=VALUE` (repeatable)")
}

func runSearch(args []string) error {
	var o searchOpts
	cfg := loadConfig()
	fs := newFlagSet("search")
	defineSearchFlags(fs, &o, cfg.TopK)
	valueFlags := map[string]bool{"top-k": true, "source": true, "type": true, "filter": true}
	if err := parseFlags(fs, reorder(args, valueFlags)); err != nil {
		return err
	}
	topK, jsonOut, sources, typ, filters := &o.topK, &o.json, o.sources, o.typ, o.filters

	query := strings.Join(fs.Args(), " ")
	if query == "" {
		return missingArg("search", "missing query", `search "SSRF to cloud metadata"`)
	}

	filterMap, err := buildFilters(sources, typ, filters)
	if err != nil {
		return err
	}

	rc, err := newRetrievalClient(cfg)
	if err != nil {
		return err
	}
	defer rc.Close()
	start := time.Now()
	results, err := rc.Search(context.Background(), query, *topK, filterMap)
	elapsed := time.Since(start)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(searchResponse{results})
	}
	printResults(query, results, elapsed)
	return nil
}

// buildFilters folds --source/--type/--filter into the {field: value} payload
// filter map. Later values win on key collision; an empty result is nil (no
// filtering), which matches everything.
func buildFilters(sources multiFlag, typ string, kv multiFlag) (map[string]interface{}, error) {
	m := map[string]interface{}{}
	for _, s := range sources {
		m["source"] = s // last --source wins; the filter is single-valued per field
	}
	if typ != "" {
		m["type"] = typ
	}
	for _, f := range kv {
		k, v, ok := strings.Cut(f, "=")
		if !ok || k == "" {
			return nil, usageErr(`search: --filter must be KEY=VALUE, got %q. Example: blk search --filter section=intro "ssrf". See "blk help search".`, f)
		}
		m[k] = v
	}
	if len(m) == 0 {
		return nil, nil
	}
	return m, nil
}

// printResults renders ranked search results as a SEARCH banner and ranked
// rows (rank Meta, title Body, path Meta, score right-aligned and banded via
// scoreStyle), or a friendly empty message.
// elapsed is omitted from the banner when zero (the --sources path under
// runAsk has no separate timing to show).
func printResults(query string, results []retrieval.Result, elapsed time.Duration) {
	fmt.Print(formatResults(query, results, elapsed, terminalWidth()))
}

// formatResults builds the same rendering as printResults but returns it as a
// string, so the TUI REPL can commit it to scrollback via tea.Println instead
// of writing straight to stdout (which would corrupt the live region). width
// is the terminal or model width: no line exceeds it, and long unbroken
// tokens are hard-broken rather than overflowing. The one exception is the
// source path, which stays a single line so it can be copied intact.
func formatResults(query string, results []retrieval.Result, elapsed time.Duration, width int) string {
	var b strings.Builder
	if len(results) == 0 {
		fmt.Fprintf(&b, " %s\n", Body.Render(fmt.Sprintf("No results for %q.", query)))
		return b.String()
	}

	hw := wrapWidth(width, 78)
	indent := 6
	if hw < 20 {
		indent = 2
	}

	count := fmt.Sprintf("%d result(s)", len(results))
	if elapsed > 0 {
		count = joinSep(count, elapsed.Round(time.Millisecond).String())
	}
	quoted := ellipsize(fmt.Sprintf("%q", query), hw-len("SEARCH  ")-utf8.RuneCountInString(count)-1)
	banner := H1.Render("SEARCH") + "  " + H1.Render(quoted)
	fmt.Fprintln(&b, " "+headerLine(banner, Meta.Render(count), width))
	fmt.Fprintln(&b)

	for i, r := range results {
		title := sanitizeTerminal(r.Payload.Source)
		if r.Payload.Section != "" {
			title += " " + Glyph(GlyphSep) + " " + sanitizeTerminal(r.Payload.Section)
		}
		rank := fmt.Sprintf("%2d", i+1)
		scoreText := fmt.Sprintf("%.4f", r.Score)
		// The row is " <rank>  <title> ... <score>": 4 columns of fixed chrome
		// around the rank, plus one column between title and score.
		title = ellipsize(title, hw-len(rank)-4-len(scoreText)-1)
		left := fmt.Sprintf(" %s  %s", Meta.Render(rank), Body.Render(title))
		fmt.Fprintln(&b, headerLine(left, scoreStyle(r.Score).Render(scoreText), width))
		if r.Payload.Path != "" {
			// One logical line, never hard-wrapped: the path is a copy target for
			// blk open, and the terminal soft-wraps it without inserting a newline.
			path := strings.Join(strings.Fields(sanitizeTerminal(r.Payload.Path)), " ")
			fmt.Fprintln(&b, Meta.Render(strings.Repeat(" ", indent)+path))
		}
		// Chunk text carries newlines and tabs; collapse them so the preview
		// keeps the row indent.
		preview := strings.Join(strings.Fields(sanitizeTerminal(r.Payload.Text)), " ")
		fmt.Fprintf(&b, "%s\n\n", wrapIndent(ellipsize(preview, 240), indent, hw))
	}
	return b.String()
}

// newAskStream returns the token callback for the streaming ask path: it strips
// control sequences (holding back one split across tokens), writes the clean
// text to w, and records it in full.
func newAskStream(w io.Writer, full *strings.Builder) func([]byte) {
	var ts termStream
	return func(b []byte) {
		clean := ts.Write(string(b))
		full.WriteString(clean)
		io.WriteString(w, clean)
	}
}

// askOpts holds the flags of `blk ask`.
type askOpts struct {
	json    bool
	sources bool
	agent   bool
	rag     bool
}

// askRoutes builds the router's enabled-route set from the saved model prefs.
func askRoutes(p modelPrefs) enabledRoutes {
	return enabledRoutes{Local: p.Rag, Web: p.Web}
}

func defineAskFlags(fs *flag.FlagSet, o *askOpts) {
	fs.BoolVar(&o.json, "json", false, "print the answer as JSON instead of formatted text")
	fs.BoolVar(&o.sources, "sources", false, "also print the retrieved passages")
	fs.BoolVar(&o.agent, "agent", false, "answer with the Hermes agent instead of the knowledge base alone")
	fs.BoolVar(&o.rag, "rag", false, "force a grounded answer from the knowledge base, skipping adaptive routing")
}

func runAsk(args []string) error {
	// One-shot ask has no prior conversation.
	_, err := askWith(nil, nil, args)
	return err
}

// askWith runs `blk ask` with args. rc is a long-lived retrieval client to
// reuse, such as the plain REPL's; nil makes one for this call and closes it.
func askWith(rc *retrieval.Client, history []priorTurn, args []string) (string, error) {
	var o askOpts
	fs := newFlagSet("ask")
	defineAskFlags(fs, &o)
	if err := parseFlags(fs, reorder(args, nil)); err != nil {
		return "", err
	}
	jsonOut, showSources, agent := &o.json, &o.sources, &o.agent

	query := strings.Join(fs.Args(), " ")
	if query == "" {
		return "", missingArg("ask", "missing question", `ask "what is SSRF?"`)
	}

	// --agent hands the question to the Hermes agent (which has the blkChain KB
	// tools plus web/tool access), rather than the Go answer loop.
	if *agent {
		return "", runHermes([]string{query})
	}

	// Conversation memory: the full prior turns are fed to the answer loop so
	// the model remembers the session and retrieval is history-aware. The shared
	// answer path (adaptiveAnswer) compresses them to the budget when needed, so
	// no truncation happens here. Empty history is the stateless single-turn case.

	cfg := loadConfig()
	if rc == nil {
		c, err := newRetrievalClient(cfg)
		if err != nil {
			return "", err
		}
		defer c.Close()
		rc = c
	} else {
		rc = followPrefs(rc, loadPrefs())
	}

	// Only the plain text path streams: --json needs the full struct and
	// --sources needs the retrieved chunks, neither of which the token stream
	// carries.
	if !*jsonOut && !*showSources {
		// Tokens are untrusted LLM output: strip control sequences before they
		// reach the terminal. termStream holds back a sequence split across tokens.
		var full strings.Builder
		p := loadPrefs()
		_, cits, usedWeb, _, _, _, err := adaptiveAnswerFn(context.Background(), rc, cfg, query, askRoutes(p), o.rag, AnswerOpts{
			Stream:  newAskStream(os.Stdout, &full),
			NoWeb:   !p.Web,
			History: history,
			Persona: func(domain string) {
				fmt.Println(Meta.Render("answering as " + personaLabel(domain)))
			},
		})
		if errors.Is(err, ErrNoResults) {
			return "", reportNoResults(os.Stderr, false, "")
		}
		err = timeoutOrErr(err)
		if err != nil && full.Len() == 0 {
			return "", err
		}
		if !strings.HasSuffix(full.String(), "\n") {
			fmt.Println()
		}
		printSources(cits, usedWeb, rc.SkipRerank)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s stream ended early: %s\n", errMark(), sanitizeTerminal(err.Error()))
		}
		return full.String(), nil
	}

	// Resolve the model once, up front, so the id in the JSON is the id the
	// answer loop was asked to use.
	model := resolveModel(cfg)
	p := loadPrefs()
	answer, cits, usedWeb, results, _, route, err := adaptiveAnswerFn(context.Background(), rc, cfg, query, askRoutes(p), o.rag, AnswerOpts{Model: model, NoWeb: !p.Web, History: history})
	if errors.Is(err, ErrNoResults) {
		return "", reportNoResults(os.Stderr, *jsonOut, model)
	}
	if err != nil {
		return "", timeoutOrErr(err)
	}
	resp := &answerResponse{
		Answer:    answer,
		Citations: cits,
		UsedWeb:   usedWeb,
		Model:     model,
		Results:   results,
		Route:     route,
	}

	if *jsonOut {
		return resp.Answer, printJSON(resp)
	}

	// Glow-format markdown output: let glamour own the
	// answer body's rendering instead of hand-formatting it.
	fmt.Println(strings.TrimRight(glowRender(resp.Answer, terminalWidth()), "\n"))
	if *showSources && len(resp.Results) > 0 {
		fmt.Println()
		fmt.Println(H2.Render("RETRIEVED CHUNKS"))
		fmt.Println()
		printResults(query, resp.Results, 0)
	}
	printSources(resp.Citations, resp.UsedWeb, rc.SkipRerank)
	return resp.Answer, nil
}

// reportNoResults handles AnswerLoop's ErrNoResults for the non-interactive ask
// paths. Text mode prints the warning and next steps to stderr and leaves
// stdout empty. JSON mode keeps the AnswerResponse wire shape, with the plain
// no-results statement as the answer, no citations, and the requested model.
func reportNoResults(stderr io.Writer, jsonOut bool, model string) error {
	if jsonOut {
		return printJSON(&answerResponse{Answer: noResultsAnswer, Citations: []citation{}, Model: model})
	}
	fmt.Fprintln(stderr, formatNoResultsErr())
	return nil
}

// isWebCitation reports whether a citation came from the live web search
// fallback.
func isWebCitation(cit citation) bool { return cit.Source == webSource }

// webTag is the plain-text marker shown next to web citations. It is text so it
// survives without color.
const webTag = "[web, untrusted]"

// citationLine renders one numbered SOURCES row: index, source, path and
// section (all sanitized, they come from the corpus or the web), and the web tag.
func citationLine(indent string, i int, cit citation) string {
	line := indent + Key.Render(fmt.Sprintf("[%d]", i+1)) + "  " + Body.Render(sanitizeTerminal(cit.Source))
	meta := sanitizeTerminal(cit.Path)
	if cit.Section != "" {
		if meta != "" {
			meta += " " + Glyph(GlyphSep) + " "
		}
		meta += sanitizeTerminal(cit.Section)
	}
	if meta != "" {
		line += "  " + Meta.Render(meta)
	}
	if isWebCitation(cit) {
		line += "  " + Caut.Render(webTag)
	}
	return line
}

// rerankOffNote is the sources-block line for an answer made with the reranker
// turned off in /models.
const rerankOffNote = "(the reranker was off for this answer, so sources are in hybrid order)"

// printSources renders the SOURCES block to stdout, shared by the streaming and
// non-streaming ask paths. rerankOff adds rerankOffNote.
func printSources(citations []citation, usedWeb, rerankOff bool) {
	fmt.Println()
	fmt.Println(H2.Render("SOURCES"))
	if len(citations) == 0 {
		fmt.Println("  " + Meta.Render("(none)"))
	}
	for i, cit := range citations {
		fmt.Println(citationLine("  ", i, cit))
	}
	if usedWeb || rerankOff {
		fmt.Println()
	}
	if usedWeb {
		fmt.Println(Meta.Render("(this answer used a web search)"))
	}
	if rerankOff {
		fmt.Println(Meta.Render(rerankOffNote))
	}
}

// healthResponse is what blk health --json prints. ok is true only when every
// probed service is up.
type healthResponse struct {
	OK          bool `json:"ok"`
	Qdrant      bool `json:"qdrant"`
	EmbedServer bool `json:"embed_server"`
	LLM         bool `json:"llm"`
}

func newHealthResponse(h *serviceHealth) healthResponse {
	return healthResponse{OK: h.ok(), Qdrant: h.Qdrant, EmbedServer: h.EmbedServer, LLM: h.LLM}
}

// healthOpts holds the flags of `blk health`.
type healthOpts struct{ json bool }

func defineHealthFlags(fs *flag.FlagSet, o *healthOpts) {
	fs.BoolVar(&o.json, "json", false, "print the status as JSON instead of formatted text")
}

// runHealth prints the service table (or, with --json, one JSON object) and
// returns errDegraded when any service is down, so scripts can gate on exit
// status.
func runHealth(args []string) error {
	var o healthOpts
	fs := newFlagSet("health")
	defineHealthFlags(fs, &o)
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	cfg := loadConfig()
	rc, err := newRetrievalClient(cfg)
	if err == nil {
		defer rc.Close()
	}
	h := nativeHealth(cfg, rc)
	if o.json {
		if err := printJSON(newHealthResponse(h)); err != nil {
			return err
		}
	} else {
		fmt.Println("blkChain services:")
		fmt.Printf("  %s qdrant        %s\n", check(h.Qdrant), Meta.Render("("+cfg.QdrantGRPCURL+")"))
		fmt.Printf("  %s embed_server  %s\n", check(h.EmbedServer), Meta.Render("("+cfg.EmbedServerURL+")"))
		fmt.Printf("  %s llm           %s\n", check(h.LLM), Meta.Render("("+redactedURL(omlxBaseURL())+")"))
		if h.LLMRedirect {
			fmt.Printf("    %s\n", Meta.Render(errLLMRedirect.Error()))
		}
	}
	if !h.ok() {
		return errDegraded
	}
	return nil
}

// loadConfig is how the retrieval and health paths read the RAG config. It is a variable so
// tests can point the embed server at a dead loopback port instead of the
// real default one; the embed URL has no environment override.
var loadConfig = ragconfig.Load

// healthProbeTimeout bounds each liveness probe so `blk health` never hangs
// on a dead dependency.
const healthProbeTimeout = 4 * time.Second

// nativeHealth probes Qdrant (on rc's connection; a nil rc is down),
// embed_server, and the LLM server directly, the same probes search and ask
// depend on. The LLM probe runs alongside the retrieval probes so a dead
// service does not add its timeout to the others.
func nativeHealth(cfg ragconfig.Config, rc *retrieval.Client) *serviceHealth {
	llmErr := make(chan error, 1)
	go func() { llmErr <- probeLLM(omlxBaseURL(), omlxAPIKey(), healthProbeTimeout) }()
	h := &serviceHealth{Qdrant: probeQdrant(rc), EmbedServer: probeEmbedServer(cfg)}
	err := <-llmErr
	h.LLM, h.LLMRedirect = err == nil, errors.Is(err, errLLMRedirect)
	return h
}

// probeQdrant issues a real liveness RPC (HealthCheck), since the client never
// dials until a call is made.
func probeQdrant(rc *retrieval.Client) bool {
	if rc == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthProbeTimeout)
	defer cancel()
	return rc.Health(ctx) == nil
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

	resp, err := localHTTP.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	return resp.StatusCode == http.StatusOK
}

// embedHealth is embed_server's GET /health report of which of its models
// loaded.
type embedHealth struct {
	Embedder bool `json:"embedder"`
	Reranker bool `json:"reranker"`
}

// probeEmbedHealth reads embed_server's GET /health, bounded by the probe
// timeout and a 1 MiB body cap. ok is false when it does not answer with a
// 200 and valid JSON.
func probeEmbedHealth(cfg ragconfig.Config) (h embedHealth, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), healthProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.EmbedServerURL+"/health", nil)
	if err != nil {
		return h, false
	}
	resp, err := localHTTP.Do(req)
	if err != nil {
		return h, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return h, false
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&h); err != nil {
		return embedHealth{}, false
	}
	return h, true
}

// probeLLM checks that the LLM server at baseURL answers GET /models with a
// 2xx status within timeout; nil means it does. A redirect, which it never
// follows, is errLLMRedirect. The API key, when set, goes in the Authorization
// header and is never printed. The body read is capped at 1 MiB and discarded.
func probeLLM(baseURL, apiKey string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/models", nil)
	if err != nil {
		return err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := llmHTTP.Do(req)
	if errors.Is(err, errLLMRedirect) {
		return errLLMRedirect
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("LLM server status %d", resp.StatusCode)
	}
	return nil
}

// llmDownHint is the line under a down llm row: the redirect, when that is why,
// else where to start the LLM server. llmBase is already redacted.
func llmDownHint(h *serviceHealth, llmBase string) string {
	if h.LLMRedirect {
		return errLLMRedirect.Error()
	}
	return "start the LLM server at " + llmBase
}

// downServices names the services h reports as down, in status-line order.
func downServices(h *serviceHealth) []string {
	var down []string
	if !h.Qdrant {
		down = append(down, "qdrant")
	}
	if !h.EmbedServer {
		down = append(down, "embed_server")
	}
	if !h.LLM {
		down = append(down, "llm")
	}
	return down
}

// check renders the theme's OK/Fail glyph for a boolean dependency state.
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
	fmt.Println(string(escapeJSONControls(data)))
	return nil
}

// escapeJSONControls rewrites DEL and the C1 runes (U+0080..U+009F) in marshaled
// JSON as \uXXXX. encoding/json emits them raw, and a terminal would act on
// U+009B (CSI) or U+009D (OSC). They can only occur inside string literals, so
// the JSON stays valid and decodes to the same strings. Other bytes are copied
// unchanged.
func escapeJSONControls(data []byte) []byte {
	var out []byte
	last := 0
	for i := 0; i < len(data); {
		r, n := utf8.DecodeRune(data[i:])
		if r == 0x7f || (r >= 0x80 && r <= 0x9f && n > 1) {
			if out == nil {
				out = make([]byte, 0, len(data)+16)
			}
			out = append(out, data[last:i]...)
			out = append(out, fmt.Sprintf(`\u%04x`, r)...)
			last = i + n
		}
		i += n
	}
	if out == nil {
		return data
	}
	return append(out, data[last:]...)
}

// multiFlag is a flag.Value that accumulates repeated occurrences, so a flag
// like --source may be given more than once.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
