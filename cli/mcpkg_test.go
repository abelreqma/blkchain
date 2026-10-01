package main

import (
	"context"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/skillcat"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestKGQueryRoundTrip drives the PRODUCTION newMCPServer registration: it builds
// the server exactly as `blk mcp` does, so if registerKGTool(s) is dropped from
// newMCPServer the kg_query tool is neither listed nor callable and this test
// fails. It then calls kg_query against a seeded workspace and asserts nodes come
// back.
func TestKGQueryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	seedKGWorkspace(t, dir)

	skillDir := t.TempDir()
	writeTestSkill(t, skillDir, "aaa-web", "---\nname: aaa-web\ndescription: web\n---\nBODY\n")
	cat, err := skillcat.Load(skillDir)
	if err != nil {
		t.Fatal(err)
	}
	srv := newMCPServer(&retrieval.Client{}, ragconfig.Config{}, cat)

	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// kg_query must be registered by the production server.
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tl := range tools.Tools {
		if tl.Name == "kg_query" {
			found = true
		}
	}
	if !found {
		t.Fatalf("kg_query not registered by newMCPServer; have %v", tools.Tools)
	}

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "kg_query", Arguments: map[string]any{"workspace": dir}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("kg_query returned an error result: %+v", res)
	}
	out, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("kg_query structured content is not an object: %T", res.StructuredContent)
	}
	nodes, ok := out["nodes"].([]any)
	if !ok || len(nodes) == 0 {
		t.Fatalf("kg_query returned no nodes: %+v", out)
	}
}
