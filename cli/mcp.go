package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/skillcat"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcp.go is blkChain's MCP stdio server (`blk mcp`). It exposes retrieval,
// answer, skill routing, engagement, and knowledge graph tools over the
// modelcontextprotocol/go-sdk.

// mcpSearchIn is kb_search's tool input. TopK is a pointer so "not provided"
// (nil) is distinguishable from an explicit 0.
type mcpSearchIn struct {
	Query   string         `json:"query" jsonschema:"the search query"`
	TopK    *int           `json:"top_k,omitempty" jsonschema:"number of results to return (default: server config)"`
	Filters map[string]any `json:"filters,omitempty" jsonschema:"optional payload filters, e.g. {\"source\": \"...\"}"`
}

// mcpAnswerIn is kb_answer's tool input.
type mcpAnswerIn struct {
	Query string `json:"query" jsonschema:"the question to answer"`
}

// mcpRouteIn is route_skill's tool input.
type mcpRouteIn struct {
	Domain string `json:"domain" jsonschema:"an engagement domain (generic, recon, web, ad, cloud, k8s, wifi, exploit-dev) or a kind/vuln-class keyword such as kerberos, xss, or adcs, to route a skill for"`
}

// Bounds on chat's caller-supplied strings. Generated session ids are well
// under mcpChatMaxSessionID bytes.
const (
	mcpChatMaxMessage    = 256 << 10
	mcpChatMaxSessionID  = 128
	mcpChatMaxBrowserCDP = 256
)

// mcpChatMaxInFlight bounds the chat turns one server runs at once. The SDK
// dispatches tool calls asynchronously, and a turn drives a model with the whole
// tool registry, a sandbox container and web fetches behind it, so a few at once
// is as much as one local model host carries; past that a turn is refused rather
// than queued.
const mcpChatMaxInFlight = 4

// errChatBusy refuses a chat turn because mcpChatMaxInFlight are already
// running.
var errChatBusy = fmt.Errorf("chat: %d turns are already in flight; retry when one finishes", mcpChatMaxInFlight)

// acquireChatSlot takes one in-flight chat slot and returns its release. It
// never queues: a full server refuses the turn, and a request whose context is
// already done is refused with that error instead of taking a slot no one is
// waiting on.
func acquireChatSlot(ctx context.Context, slots chan struct{}) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, nil
	default:
		return nil, errChatBusy
	}
}

// mcpChatMaxSessions bounds how many of its own session ids one server tracks.
// The least recently used is forgotten when the cap is reached, so that
// conversation can no longer be continued while the recently used ones can.
const mcpChatMaxSessions = 128

// errChatForeignSession refuses a chat turn that names a session this server
// process did not create. chat writes memory rows the next turn in that session
// reads back as its own prior turn, so a turn another surface is holding (a TUI,
// another blk process) must not be appended to from here. Reading any session
// as a session:// resource is unrestricted.
var errChatForeignSession = errors.New("chat: session was not created by this server")

// errChatLocalHostRefused refuses tool_host local to a caller that is not a
// local process.
var errChatLocalHostRefused = errors.New("chat: tool_host local is only available to a local caller")

// errChatBrowserCDPRefused refuses browser_cdp to a caller that is not a local
// process.
var errChatBrowserCDPRefused = errors.New("chat: browser_cdp is only available to a local caller")

// chatSessionOwner is the set of session ids the chat tool created on one
// server. It lives in memory only, so after a restart no earlier session can be
// continued: the write side stays with the process that opened the
// conversation.
type chatSessionOwner struct {
	mu    sync.Mutex
	ids   map[string]struct{}
	order []string
}

func newChatSessionOwner() *chatSessionOwner {
	return &chatSessionOwner{ids: make(map[string]struct{}, mcpChatMaxSessions)}
}

// own records a session this server created, forgetting the least recently used
// id once the set is at mcpChatMaxSessions.
func (o *chatSessionOwner) own(id string) {
	if id == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.ids[id]; ok {
		return
	}
	if len(o.order) >= mcpChatMaxSessions {
		delete(o.ids, o.order[0])
		o.order = o.order[1:]
	}
	o.ids[id] = struct{}{}
	o.order = append(o.order, id)
}

// touch reports whether this server created the session, and when it did marks
// the session as the most recently used.
func (o *chatSessionOwner) touch(id string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.ids[id]; !ok {
		return false
	}
	if i := slices.Index(o.order, id); i >= 0 {
		o.order = append(slices.Delete(o.order, i, i+1), id)
	}
	return true
}

// mcpChatIn is chat's tool input. An empty SessionID opens a new session;
// supplying one continues it. ToolHost accepts local and BrowserCDP accepts an
// endpoint only from a local caller (see clientVantage). ForceRag and WebOnly
// are routing hints and are mutually exclusive.
type mcpChatIn struct {
	Message    string `json:"message" jsonschema:"the message for this turn"`
	SessionID  string `json:"session_id,omitempty" jsonschema:"continue this session; omit to start a new one"`
	Agent      string `json:"agent,omitempty" jsonschema:"native answer specialist name; omit for automatic selection"`
	ToolHost   string `json:"tool_host,omitempty" jsonschema:"file and terminal host: sandbox (default) or local. local is permitted only to a local caller, meaning the stdio transport or a loopback HTTP request, because such a caller already holds the operator's privileges"`
	BrowserCDP string `json:"browser_cdp,omitempty" jsonschema:"loopback CDP endpoint of a browser whose signed-in state the browser tools copy, for example http://127.0.0.1:9222. Permitted only to a local caller, meaning the stdio transport or a loopback HTTP request, because such a caller already holds the operator's privileges: it hands the agent the operator's authenticated browser session"`
	ForceRag   bool   `json:"force_rag,omitempty" jsonschema:"skip adaptive routing and answer from the local knowledge base; cannot be combined with web_only"`
	WebOnly    bool   `json:"web_only,omitempty" jsonschema:"answer from the public web only for this turn; cannot be combined with force_rag"`
}

// Session resources: sessionResourceMaxBytes bounds one payload, since a
// transcript can be up to maxSessionBytes on disk, and sessionResourceListCap
// bounds how many existing sessions resources/list enumerates.
const (
	sessionResourceScheme   = "session://"
	sessionResourceMaxBytes = 256 << 10
	sessionResourceListCap  = 50
)

// errInvalidSessionResource marks a session URI or id that is malformed, as
// distinct from a well-formed id that names no session.
var errInvalidSessionResource = errors.New("invalid session resource")

func sessionResourceURI(id string) string { return sessionResourceScheme + id }

// sessionIDFromURI extracts the session id from a session:// URI. The URI comes
// from the client, so the id is validated before any caller can build a file
// path from it.
func sessionIDFromURI(uri string) (string, error) {
	id, ok := strings.CutPrefix(uri, sessionResourceScheme)
	if !ok {
		return "", fmt.Errorf("%w: not a session URI: %s", errInvalidSessionResource, sanitizeTerminal(uri))
	}
	if !validSessionID(id) {
		return "", fmt.Errorf("%w: bad session id", errInvalidSessionResource)
	}
	return id, nil
}

// sessionTurn is one turn in a session resource payload.
type sessionTurn struct {
	Role    string `json:"role"`
	Content string `json:"content"`
	TS      int64  `json:"ts,omitempty"`
}

// cutSessionTurn shortens a turn's content, on a rune boundary, to the longest
// prefix whose encoded turn is at most limit bytes. JSON escaping makes the
// encoded size a non-linear function of the raw length, so the prefix is found
// by binary search over the raw length rather than by subtracting encoded
// overage from a raw count.
func cutSessionTurn(t sessionTurn, limit int) sessionTurn {
	full := t.Content
	if limit <= 0 {
		t.Content = ""
		return t
	}
	aligned := func(n int) int {
		for n > 0 && n < len(full) && !utf8.RuneStart(full[n]) {
			n--
		}
		return n
	}
	fits := func(n int) bool {
		t.Content = full[:n]
		enc, _ := json.Marshal(t)
		return len(enc) <= limit
	}
	lo, hi := 0, min(len(full), limit)
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if fits(aligned(mid)) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	t.Content = full[:aligned(lo)]
	return t
}

// mcpSessionResource renders one session as JSON: its listing fields plus its
// turns, keeping the newest turns when the payload would exceed the cap.
func mcpSessionResource(id string) ([]byte, error) {
	if !validSessionID(id) {
		return nil, fmt.Errorf("%w: bad session id", errInvalidSessionResource)
	}
	if !sessionExists(id) {
		return nil, sessionNotFound(id)
	}
	recs, err := loadMessages(id)
	if err != nil {
		return nil, err
	}
	out := struct {
		ID       string        `json:"id"`
		Title    string        `json:"title,omitempty"`
		MsgCount int           `json:"msg_count"`
		Model    string        `json:"model,omitempty"`
		Turns    []sessionTurn `json:"turns"`
		Trimmed  bool          `json:"trimmed,omitempty"`
	}{ID: id, MsgCount: len(recs), Turns: []sessionTurn{}, Trimmed: true}
	if metas, lerr := listSessions(); lerr == nil {
		for _, m := range metas {
			if m.ID == id {
				out.Title, out.Model = m.Title, m.Model
				break
			}
		}
	}
	// The window is chosen in one backward pass with each turn encoded once, so
	// a long transcript costs one walk rather than one marshal per dropped turn.
	// Sizes are of the encoded turn because JSON escaping can expand content.
	// The scaffolding is measured with Trimmed set, its largest form.
	scaffold, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	budget := sessionResourceMaxBytes - len(scaffold)
	var kept []sessionTurn
	cut := false
	for i := len(recs) - 1; i >= 0; i-- {
		t := sessionTurn{Role: recs[i].Role, Content: recs[i].Content, TS: recs[i].TS}
		enc, err := json.Marshal(t)
		if err != nil {
			return nil, err
		}
		cost := len(enc) + 1 // the separating comma
		if cost > budget {
			if len(kept) == 0 {
				kept = append(kept, cutSessionTurn(t, budget-1))
				cut = true
			}
			break
		}
		budget -= cost
		kept = append(kept, t)
	}
	slices.Reverse(kept)
	if kept != nil {
		out.Turns = kept
	}
	out.Trimmed = cut || len(kept) < len(recs)
	return json.Marshal(out)
}

// sessionResourceHandler serves session://{id}. A malformed URI is rejected
// before any lookup; a well-formed id with no session is reported as a missing
// resource.
func sessionResourceHandler(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	id, err := sessionIDFromURI(req.Params.URI)
	if err != nil {
		return nil, err
	}
	payload, err := mcpSessionResource(id)
	if errors.Is(err, errSessionNotFound) {
		return nil, mcp.ResourceNotFoundError(req.Params.URI)
	}
	if err != nil {
		return nil, err
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
		URI:      req.Params.URI,
		MIMEType: "application/json",
		Text:     string(payload),
	}}}, nil
}

// mcpChatOut is chat's structured result. Error is set when the turn produced
// an answer but did not finish cleanly, such as a transcript that could not be
// written, so the caller keeps the answer and still sees that the turn was not
// recorded. It lives here rather than on turnResult, which ask --json shares.
type mcpChatOut struct {
	turnResult
	Error string `json:"error,omitempty"`
}

// runMCP starts the MCP stdio server exposing kb_search, kb_answer, and
// route_skill. It runs in-process against the Go retrieval client and answer
// loop, so embed_server and Qdrant must be up.
func runMCP(_ []string) error {
	cfg := loadConfig()
	rc, err := newRetrievalClient(cfg)
	if err != nil {
		return err
	}
	defer rc.Close()

	cat, err := loadEngageCatalog()
	if err != nil {
		return err
	}

	// The client of a stdio server is the process that spawned it, so the caller
	// is local.
	s := newMCPServer(rc, cfg, cat, vantageLocal)
	return s.Run(context.Background(), &mcp.StdioTransport{MaxLineLength: 1 << 20})
}

// newMCPServer builds the blkchain MCP server and registers its tools.
// runMCP and the round-trip test both use it, so the test covers the real
// registration. vantage applies to every caller of the returned server.
func newMCPServer(rc *retrieval.Client, cfg ragconfig.Config, cat *skillcat.Catalog, vantage clientVantage) *mcp.Server {
	v, _, _, _ := versionInfo()
	s := mcp.NewServer(&mcp.Implementation{Name: "blkchain", Version: v}, nil)
	// One set of chat slots and one owned-session set per server, so a test's
	// server bounds and owns only its own turns.
	chatSlots := make(chan struct{}, mcpChatMaxInFlight)
	owned := newChatSessionOwner()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "kb_search",
		Description: "Hybrid retrieval (dense + BM25, RRF-fused, cross-encoder reranked) over the local blkChain knowledge base. Returns the top-ranked chunks with source pointers.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpSearchIn) (*mcp.CallToolResult, any, error) {
		topK, err := mcpSearchTopK(in, cfg)
		if err != nil {
			return nil, nil, err
		}
		res, err := followPrefs(rc, loadPrefs()).Search(ctx, in.Query, topK, in.Filters)
		if err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"results": res}, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "kb_answer",
		Description: "Bounded, source-cited answer over the local knowledge base. Exact CVEs add direct NVD details and public PoC search when web research is enabled.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpAnswerIn) (*mcp.CallToolResult, any, error) {
		p := loadPrefs()
		out, err := kbAnswer(ctx, followPrefs(rc, p), cfg, in.Query, !p.Web)
		if err != nil {
			return nil, nil, err
		}
		return nil, out, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "chat",
		Description: "One turn of the blkChain agent: adaptive routing, the local knowledge base, files, terminal, browser and web research, with the operator's connected MCP servers. Omit session_id to start a conversation, pass the returned session_id back to continue it. Only a session this server process started can be continued: an id from anywhere else, including one this server returned before it was restarted, is refused. Every session is still readable as a session://{id} resource.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpChatIn) (*mcp.CallToolResult, any, error) {
		release, err := acquireChatSlot(ctx, chatSlots)
		if err != nil {
			return nil, nil, err
		}
		defer release()
		res, err := mcpChatResult(ctx, followPrefs(rc, loadPrefs()), cfg, owned, in, vantage)
		if err != nil && strings.TrimSpace(res.Answer) == "" {
			return nil, nil, err
		}
		out := mcpChatOut{turnResult: res}
		if err != nil {
			out.Error = err.Error()
		}
		return nil, out, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "route_skill",
		Description: "Get the playbook for an engagement domain. Provide one domain (generic, recon, web, ad, cloud, k8s, wifi, exploit-dev) or a kind/vuln-class keyword (for example kerberos, xss, adcs); the harness selects the skill deterministically and returns its playbook. You cannot choose a specific skill by name; an unrecognized domain returns the generic playbook or a clear no-skill message.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpRouteIn) (*mcp.CallToolResult, any, error) {
		return nil, mcpRouteResult(cat, in.Domain), nil
	})

	s.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: sessionResourceScheme + "{id}",
		Name:        "blkChain session",
		Description: "A conversation transcript, from any blk surface. Readable whatever created it; only a session this server process started can be continued with the chat tool.",
		MIMEType:    "application/json",
	}, sessionResourceHandler)
	// A template is not listed by resources/list, so the sessions that exist
	// when the server starts are also registered as concrete resources.
	if metas, err := listSessions(); err == nil {
		for i, m := range metas {
			if i >= sessionResourceListCap {
				break
			}
			s.AddResource(&mcp.Resource{
				URI:      sessionResourceURI(m.ID),
				Name:     firstNonEmpty(m.Title, m.ID),
				MIMEType: "application/json",
			}, sessionResourceHandler)
		}
	}

	registerEngageTool(s, defaultEngageService(rc, cfg, cat))
	registerKGTool(s)

	return s
}

// mcpChatResult runs one native turn for the chat tool. It is the handler body,
// factored out so the tests drive it without a live transport. The caller's
// session id is always an id, never a selector: new and last are rejected so
// a client cannot attach to whichever session was used most recently, and it
// must be one this server created (see errChatForeignSession).
func mcpChatResult(ctx context.Context, rc *retrieval.Client, cfg ragconfig.Config, owned *chatSessionOwner, in mcpChatIn, v clientVantage) (turnResult, error) {
	if err := checkChatVantage(v, in.ToolHost, in.BrowserCDP); err != nil {
		return turnResult{}, err
	}
	if in.ForceRag && in.WebOnly {
		return turnResult{}, usageErr("chat: web_only cannot be combined with force_rag")
	}
	if len(in.Message) > mcpChatMaxMessage {
		return turnResult{}, usageErr("chat: message exceeds %d bytes", mcpChatMaxMessage)
	}
	selector := strings.TrimSpace(in.SessionID)
	switch {
	case selector == "":
		selector = sessionTargetNew
	case len(selector) > mcpChatMaxSessionID:
		return turnResult{}, usageErr("chat: session id exceeds %d bytes", mcpChatMaxSessionID)
	case selector == sessionTargetNew || selector == sessionTargetLast:
		return turnResult{}, usageErr("chat: invalid session id")
	case !owned.touch(selector):
		return turnResult{}, fmt.Errorf("%w: %s", errChatForeignSession, sanitizeTerminal(selector))
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout())
	defer cancel()
	res, err := runNativeTurn(ctx, rc, cfg, turnRequest{
		Question:   in.Message,
		SessionID:  selector,
		Agent:      in.Agent,
		ToolHost:   in.ToolHost,
		BrowserCDP: in.BrowserCDP,
		ForceRag:   in.ForceRag,
		WebOnly:    in.WebOnly,
	})
	owned.own(res.SessionID)
	return res, timeoutOrErr(err)
}

// mcpSearchTopK validates kb_search's input and resolves its effective top_k,
// mirroring the loop tool (kbtools.go): it rejects an empty query and clamps
// top_k to at most kbSearchMaxTopK, with a non-positive or omitted top_k
// falling back to the config default. Factored out for direct testing.
func mcpSearchTopK(in mcpSearchIn, cfg ragconfig.Config) (int, error) {
	if strings.TrimSpace(in.Query) == "" {
		return 0, fmt.Errorf("query is required")
	}
	topK := cfg.TopK
	if in.TopK != nil && *in.TopK > 0 {
		topK = *in.TopK
	}
	if topK > kbSearchMaxTopK {
		topK = kbSearchMaxTopK
	}
	return topK, nil
}

// mcpRouteResult is route_skill's read-only handler body, factored out for
// direct testing. It calls the shared routeSkillFor selection, records no
// receipt, and opens no file.
func mcpRouteResult(cat *skillcat.Catalog, domain string) map[string]any {
	sk, ok := routeSkillFor(cat, domain)
	if !ok {
		return map[string]any{"found": false, "domain": resolveDomain(domain)}
	}
	body := sk.Body
	truncated := false
	if r := []rune(body); len(r) > routeSkillBodyCap {
		body = string(r[:routeSkillBodyCap])
		truncated = true
	}
	return map[string]any{
		"found":       true,
		"skill":       sk.Name,
		"domain":      sk.Domain,
		"description": sk.Description,
		"body":        body,
		"truncated":   truncated,
		"digest":      sk.Digest,
	}
}

// kbAnswer runs the answer loop for the kb_answer tool. Finding nothing is a
// normal result whose answer says so, not a tool error, so an MCP client can
// tell "no sources" from a failure. noWeb is the /models web switch turned off.
func kbAnswer(ctx context.Context, rc searcher, cfg ragconfig.Config, query string, noWeb bool) (map[string]any, error) {
	ctx, metrics := withCallMetrics(ctx)
	answer, cits, usedWeb, results, _, err := AnswerLoop(ctx, rc, cfg, query, AnswerOpts{NoWeb: noWeb})
	if errors.Is(err, ErrNoResults) {
		answer, cits, err = noResultsAnswer, []citation{}, nil
	}
	if err != nil {
		return nil, err
	}
	response := map[string]any{
		"answer":    answer,
		"citations": cits,
		"used_web":  usedWeb,
		"results":   results,
	}
	if calls, partial := metrics.snapshot(); len(calls) > 0 {
		response["llm_calls"] = calls
		if partial {
			response["llm_calls_partial"] = true
		}
	}
	return response, nil
}
