package main

import (
	"context"

	"blkchain/cli/internal/ragconfig"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcp.go is the native Go MCP stdio server for blkChain (Task 15),
// replacing the old `blk mcp` behavior of exec'ing the Python
// blkchain.mcp_server. It exposes the same two tools, kb_search and
// kb_answer, over the official modelcontextprotocol/go-sdk, using the
// in-process retrieval.Client and AnswerLoop instead of an HTTP round trip.

// mcpSearchIn is kb_search's tool input. TopK is a pointer so "not provided"
// (nil) is distinguishable from an explicit 0, matching the Python MCP
// server's optional top_k.
type mcpSearchIn struct {
	Query   string         `json:"query" jsonschema:"the search query"`
	TopK    *int           `json:"top_k,omitempty" jsonschema:"number of results to return (default: server config)"`
	Filters map[string]any `json:"filters,omitempty" jsonschema:"optional payload filters, e.g. {\"source\": \"...\"}"`
}

// mcpAnswerIn is kb_answer's tool input.
type mcpAnswerIn struct {
	Query string `json:"query" jsonschema:"the question to answer"`
}

// runMCP starts a native MCP stdio server exposing kb_search and kb_answer,
// replacing the previous exec of `python -m blkchain.mcp_server`. It runs
// in-process against the Go retrieval client and answer loop, so it needs no
// running api service (embed_server and Qdrant still must be up).
func runMCP(_ []string) error {
	cfg := ragconfig.Load()
	rc, err := newRetrievalClient()
	if err != nil {
		return err
	}

	v, _, _, _ := versionInfo()
	s := mcp.NewServer(&mcp.Implementation{Name: "blkchain", Version: v}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "kb_search",
		Description: "Hybrid retrieval (dense + BM25, RRF-fused, cross-encoder reranked) over the local blkChain knowledge base. Returns the top-ranked chunks with source pointers.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpSearchIn) (*mcp.CallToolResult, any, error) {
		topK := cfg.TopK
		if in.TopK != nil {
			topK = *in.TopK
		}
		res, err := rc.Search(ctx, in.Query, topK, in.Filters)
		if err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"results": res}, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "kb_answer",
		Description: "Bounded, code-orchestrated agentic answer over the local blkChain knowledge base: retrieves, grades sufficiency, optionally rewrites the query or falls back to web search, then synthesizes a grounded, source-cited answer.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpAnswerIn) (*mcp.CallToolResult, any, error) {
		answer, cits, usedWeb, results, _, err := AnswerLoop(ctx, rc, cfg, in.Query, AnswerOpts{})
		if err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{
			"answer":    answer,
			"citations": cits,
			"used_web":  usedWeb,
			"results":   results,
		}, nil
	})

	return s.Run(context.Background(), &mcp.StdioTransport{MaxLineLength: 1 << 20})
}
