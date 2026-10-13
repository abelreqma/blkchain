package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
	mcpChatMaxMessage   = 256 << 10
	mcpChatMaxSessionID = 128
)

// mcpChatIn is chat's tool input. An empty SessionID opens a new session;
// supplying one continues it. ToolHost accepts local because the server speaks
// only over stdio, so its client is a local process that already holds the
// operator's privileges. A network transport would need that revisited.
type mcpChatIn struct {
	Message   string `json:"message" jsonschema:"the message for this turn"`
	SessionID string `json:"session_id,omitempty" jsonschema:"continue this session; omit to start a new one"`
	Agent     string `json:"agent,omitempty" jsonschema:"native answer specialist name; omit for automatic selection"`
	ToolHost  string `json:"tool_host,omitempty" jsonschema:"file and terminal host: sandbox (default) or local. local is permitted because this server speaks only over stdio to a local client that already holds the operator's privileges"`
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

	s := newMCPServer(rc, cfg, cat)
	return s.Run(context.Background(), &mcp.StdioTransport{MaxLineLength: 1 << 20})
}

// newMCPServer builds the blkchain MCP server and registers its tools.
// runMCP and the round-trip test both use it, so the test covers the real
// registration.
func newMCPServer(rc *retrieval.Client, cfg ragconfig.Config, cat *skillcat.Catalog) *mcp.Server {
	v, _, _, _ := versionInfo()
	s := mcp.NewServer(&mcp.Implementation{Name: "blkchain", Version: v}, nil)

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
		Description: "One turn of the blkChain agent: adaptive routing, the local knowledge base, files, terminal, browser and web research, with the operator's connected MCP servers. Omit session_id to start a conversation, pass the returned session_id back to continue it.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpChatIn) (*mcp.CallToolResult, any, error) {
		res, err := mcpChatResult(ctx, followPrefs(rc, loadPrefs()), cfg, in)
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

	registerEngageTool(s, defaultEngageService(rc, cfg, cat))
	registerKGTool(s)

	return s
}

// mcpChatResult runs one native turn for the chat tool. It is the handler body,
// factored out so the tests drive it without a live transport. The caller's
// session id is always an id, never a selector: new and last are rejected so
// a client cannot attach to whichever session was used most recently.
func mcpChatResult(ctx context.Context, rc *retrieval.Client, cfg ragconfig.Config, in mcpChatIn) (turnResult, error) {
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
	}
	return runNativeTurn(ctx, rc, cfg, turnRequest{
		Question:  in.Message,
		SessionID: selector,
		Agent:     in.Agent,
		ToolHost:  in.ToolHost,
	})
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
