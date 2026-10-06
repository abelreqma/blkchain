package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestEngageMCPStdioRoERouteE2E(t *testing.T) {
	if os.Getenv("BLKCHAIN_ENGAGE_MCP_E2E") != "1" {
		t.Skip("requires built blk, local LLM stack, and isolated runner image")
	}
	binary := os.Getenv("BLK_BIN")
	if binary == "" {
		t.Fatal("BLK_BIN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	roeText := "## In Scope\n192.0.2.1\n"
	trustedPath := filepath.Join(t.TempDir(), "ROE.md")
	if err := os.WriteFile(trustedPath, []byte(roeText), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "mcp")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "BLKCHAIN_COLLECTION=blkchain_dwq", "BLKCHAIN_ENGAGE_MAX_ROUNDS=1", "BLK_ENABLE_THINKING=0", "BLKCHAIN_MCP_ROE_PATH="+trustedPath, "XDG_CONFIG_HOME="+t.TempDir())
	client := mcp.NewClient(&mcp.Implementation{Name: "engage-e2e", Version: "0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "engage", Arguments: map[string]any{
		"goal": "Create one web inspection task for 192.0.2.1. Do not dispatch it or claim findings.",
		"roe":  roeText,
	}})
	if err != nil || result.IsError {
		t.Fatalf("production MCP route failed: %v %+v", err, result)
	}
	out, ok := result.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("unexpected MCP result type: %T", result.StructuredContent)
	}
	workspace, ok := out["workspace"].(string)
	workspaceParent, parentErr := filepath.EvalSymlinks(filepath.Dir(workspace))
	tempRoot, tempErr := filepath.EvalSymlinks(os.TempDir())
	if !ok || parentErr != nil || tempErr != nil || workspaceParent != tempRoot || !strings.HasPrefix(filepath.Base(workspace), "blkengage-mcp-ws-") {
		t.Fatalf("unexpected workspace: %q", workspace)
	}
	for _, name := range []string{"run.json", "policy.json", "actions.jsonl", "report.json"} {
		if _, err := os.Stat(filepath.Join(workspace, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
	if final, _ := out["final"].(string); !strings.Contains(final, "Engagement paused:") {
		t.Fatalf("MCP final did not expose incomplete run: %q", final)
	}
	t.Logf("MCP policy=%v workspace=%s", out["policy_hash"], workspace)
}
