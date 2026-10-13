package main

import (
	"context"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "sandbox-fixture", Version: "1"}, nil)
	type input struct {
		Message string `json:"message"`
	}
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "echo a value"}, func(_ context.Context, _ *mcp.CallToolRequest, in input) (*mcp.CallToolResult, any, error) {
		return nil, map[string]any{"echo": in.Message}, nil
	})
	if server.Run(context.Background(), &mcp.StdioTransport{}) != nil {
		os.Exit(1)
	}
}
