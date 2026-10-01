package main

import (
	"context"
	"fmt"

	"blkchain/cli/internal/engagement"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcpkg.go adds the read-only kg_query MCP tool, exposing the engagement
// knowledge graph over `blk mcp`. It reuses engageGraph (kgcmd.go), so the MCP
// result is identical to `blk kg`. Registration is one line in newMCPServer
// (mcp.go); the tool and handler live here.

// mcpKGIn is kg_query's tool input. All fields are optional: node queries one
// node's neighborhood, type filters to one node type, and both empty returns the
// whole graph. Workspace overrides which engagement is read (default: the most
// recent persisted engagement).
type mcpKGIn struct {
	Node      string `json:"node,omitempty" jsonschema:"query one node's neighborhood by id (e.g. asset:10.0.0.1, task:<id>, evidence:<rowid>)"`
	Type      string `json:"type,omitempty" jsonschema:"filter to one node type: task, asset, or evidence"`
	Workspace string `json:"workspace,omitempty" jsonschema:"engagement workspace directory to read (default: the most recent persisted engagement)"`
}

// registerKGTool registers the read-only kg_query tool on s. Call it once from
// newMCPServer.
func registerKGTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "kg_query",
		Description: "Query the engagement knowledge graph: a read-only, in-process projection of the engagement store that correlates tasks, assets, and evidence. Node ids are namespaced task:/asset:/evidence:; edges are targets, depends_on, derived_from, and evidenced_by. With `node` set it returns that node's one-hop neighborhood; with `type` it returns all nodes of that type; with neither it returns the whole graph. Reads the most recent persisted engagement unless `workspace` is given.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpKGIn) (*mcp.CallToolResult, any, error) {
		wsDir := in.Workspace
		if wsDir == "" {
			latest, err := latestEngagementDir()
			if err != nil {
				return nil, nil, fmt.Errorf("kg_query: %w", err)
			}
			wsDir = latest
		}
		v, err := engageGraph(wsDir, engagement.GraphQuery{Node: in.Node, Type: in.Type})
		if err != nil {
			return nil, nil, err
		}
		return nil, v, nil
	})
}
