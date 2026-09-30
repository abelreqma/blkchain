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

// mcp.go is blkChain's MCP stdio server (`blk mcp`). It exposes three tools,
// kb_search, kb_answer, and route_skill, over the official
// modelcontextprotocol/go-sdk, using the in-process retrieval.Client and
// AnswerLoop plus the read-only skill catalog.

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

// newMCPServer builds the blkchain MCP server and registers all three tools.
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
		Description: "Bounded, code-orchestrated agentic answer over the local blkChain knowledge base: retrieves, grades sufficiency, optionally rewrites the query or falls back to web search, then synthesizes a grounded, source-cited answer.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpAnswerIn) (*mcp.CallToolResult, any, error) {
		p := loadPrefs()
		out, err := kbAnswer(ctx, followPrefs(rc, p), cfg, in.Query, !p.Web)
		if err != nil {
			return nil, nil, err
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

	return s
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
	answer, cits, usedWeb, results, _, err := AnswerLoop(ctx, rc, cfg, query, AnswerOpts{NoWeb: noWeb})
	if errors.Is(err, ErrNoResults) {
		answer, cits, err = noResultsAnswer, []citation{}, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"answer":    answer,
		"citations": cits,
		"used_web":  usedWeb,
		"results":   results,
	}, nil
}
