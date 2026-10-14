package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tmc/langchaingo/llms"
)

// driveChatThroughMCPTool runs one MCP chat turn whose router outcome is the
// mcp action and whose model calls tool once with args and then answers. The
// chat entry point, the turn assembly, adviseLoop, the tool registry and the
// outbound MCP client are the real ones; only the router's classification and
// the model are scripted.
func driveChatThroughMCPTool(t *testing.T, tool, args string) (turnResult, *fakeModel, error) {
	t.Helper()
	model := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", tool, args), textResp("done")}}
	prev := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = prev })
	adaptiveAnswerFn = func(ctx context.Context, rc searcher, cfg ragconfig.Config, question string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		opts.requiredAction = "mcp"
		answer, tokens, err := adviseLoop(ctx, model, rc, cfg, nil, question, opts)
		return answer, []citation{}, false, nil, tokens, "rag", err
	}
	// The stdio transport is the one blk mcp serves, and its client is local.
	res, err := mcpChatResult(context.Background(), nil, loadConfig(), newChatSessionOwner(), mcpChatIn{Message: "Use the MCP server"}, vantageLocal)
	return res, model, err
}

// A tool from an outbound MCP server in the operator config is in the registry
// of an MCP chat turn and runs through the turn's tool loop.
func TestMCPChatCallsAToolOfAnOutboundMCPServer(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	type input struct {
		Message string `json:"message"`
	}
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "fixture tool"}, func(_ context.Context, _ *mcp.CallToolRequest, in input) (*mcp.CallToolResult, any, error) {
		return nil, map[string]any{"echo": in.Message}, nil
	})
	endpoint := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{JSONResponse: true}))
	defer endpoint.Close()
	data, err := json.Marshal(chatMCPConfig{Servers: []chatMCPServer{{Name: "fixture", Transport: "http", URL: endpoint.URL, AllowTools: []string{"echo"}}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mcp-clients.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_MCP_CLIENT_CONFIG", path)

	res, model, err := driveChatThroughMCPTool(t, "mcp__fixture__echo", `{"message":"operator-tool-value"}`)
	if err != nil || res.Answer != "done" {
		t.Fatalf("answer=%q err=%v", res.Answer, err)
	}
	if !slices.Contains(res.Actions, turnAction{Tool: "mcp__fixture__echo", Status: string(ToolDone)}) {
		t.Fatalf("the MCP tool call was not recorded as done: %+v", res.Actions)
	}
	if model.calls != 2 || !strings.Contains(msgText(model.seen[1][len(model.seen[1])-1]), "operator-tool-value") {
		t.Fatalf("the tool result did not reach the model: calls=%d", model.calls)
	}
}

// TestMCPChatReachesAnOperatorConfiguredMCPServer is the live check of the
// mechanism the Burp acceptance depends on: a tool of a server in the
// operator's MCP client config is offered to an MCP chat turn and a call to it
// completes. It sends nothing to a target and scripts the model, so it needs no
// LLM; it does call the one tool the operator names.
//
// Set BLKCHAIN_CHAT_MCP_OPERATOR_E2E=1, BLKCHAIN_MCP_CLIENT_CONFIG to the
// operator's config file (go test redirects the default location into a
// temporary directory, so the default is never found), and
// BLKCHAIN_CHAT_MCP_OPERATOR_TOOL to the exposed name of a read-only tool,
// mcp__<server>__<tool>, for example the Burp proxy history reader.
// BLKCHAIN_CHAT_MCP_OPERATOR_ARGS is its JSON arguments and defaults to {}. The
// tool output is never logged, because proxy history and similar results can
// hold secrets.
//
// It proves that the config loads, the server connects, the allowlisted tool is
// in the registry that adviseLoop builds for a turn the router classified as
// mcp, and the call returns without error through the outbound client. It does
// not prove that the router classifies a real question as mcp, that a real model
// calls the tool, or anything about what Burp recorded.
//
// Burp acceptance, run by the operator. Preconditions:
//
//  1. The MCP client config (mcp-clients.json beside the preferences file,
//     ~/.config/blkchain by default) has a server entry for the Burp MCP
//     server, with allow_tools naming the Burp tools to expose and any
//     credential given through token_env. cli/mcp-clients.example.json is a
//     template.
//  2. Burp is running with its MCP server enabled and reachable by that entry.
//  3. The target is in scope and the operator is authorized to test it.
//
// Burp carries blk's traffic on two paths, and each one's evidence is different.
// Checking one path by the other's evidence fails on a working implementation.
//
// Path one, the agent calling Burp's own tools. Burp's request tools return the
// request and response pair to the caller and add no Proxy history entry, so the
// returned pair is the only evidence this path produces. Procedure:
//
//  1. Run this test against a read-only Burp tool and require a pass.
//  2. Note the time, start `blk mcp`, and call chat with a message that names
//     the target host and asks for one request through the Burp tool. Note the
//     time again.
//  3. Record the returned pair. Do not expect it in Proxy history.
//
// Path two, blk's own engage web traffic, which traverses Burp's proxy listener
// and therefore does land in history. Procedure:
//
//  1. Note the time and run `blk engage web collect` against the target under an
//     RoE that scopes it, with BLKCHAIN_WEB_PROXY on its default or naming
//     Burp's listener. Note the time again.
//  2. Read Proxy > HTTP history, or query it through Burp MCP with a narrow
//     filter, and match each request the run sent by host, path, method and a
//     timestamp inside the noted window. Compare the count sent with the count
//     found.
//  3. Write down what was observed. A request with no matching entry is a failed
//     acceptance, not a skipped one.
//
// WebSocket acquisition takes the same path: the handshake goes through a CONNECT
// tunnel to the same listener, so it lands in Proxy > WebSockets history. An
// empty WebSockets history means no WebSocket was opened, not that the traffic
// bypassed the proxy.
//
// No marker header, altered user-agent or tracer parameter is added to any
// request on either path. A marker changes the request fingerprint, so the
// measurement would describe the instrument instead of the target. Correlation
// uses only the fields a real request already has. Burp's own normalization of
// hop-by-hop and Accept-Encoding headers is visible in history and is Burp's,
// not blk's.
func TestMCPChatReachesAnOperatorConfiguredMCPServer(t *testing.T) {
	if os.Getenv("BLKCHAIN_CHAT_MCP_OPERATOR_E2E") != "1" {
		t.Skip("set BLKCHAIN_CHAT_MCP_OPERATOR_E2E=1 with an MCP client config naming a running server")
	}
	path := os.Getenv("BLKCHAIN_MCP_CLIENT_CONFIG")
	if path == "" {
		t.Skip("set BLKCHAIN_MCP_CLIENT_CONFIG to the operator's MCP client config; its default location is redirected into a temporary directory under go test")
	}
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		t.Skipf("no MCP client config at %s; create one with a server entry first", path)
	}
	config, err := loadChatMCPConfig()
	if err != nil {
		t.Fatalf("MCP client config at %s: %v", path, err)
	}
	if len(config.Servers) == 0 {
		t.Skipf("the MCP client config at %s lists no servers", path)
	}
	tool := os.Getenv("BLKCHAIN_CHAT_MCP_OPERATOR_TOOL")
	if !strings.HasPrefix(tool, "mcp__") {
		t.Fatal("set BLKCHAIN_CHAT_MCP_OPERATOR_TOOL to the exposed name of a read-only tool, mcp__<server>__<tool>")
	}
	args := os.Getenv("BLKCHAIN_CHAT_MCP_OPERATOR_ARGS")
	if args == "" {
		args = "{}"
	}
	if !json.Valid([]byte(args)) {
		t.Fatal("BLKCHAIN_CHAT_MCP_OPERATOR_ARGS is not valid JSON")
	}
	useDeadServices(t)

	res, model, err := driveChatThroughMCPTool(t, tool, args)
	if err != nil {
		t.Fatalf("the turn failed: %v", err)
	}
	if !slices.Contains(res.Actions, turnAction{Tool: tool, Status: string(ToolDone)}) {
		t.Fatalf("%s was not recorded as done: %+v", tool, res.Actions)
	}
	t.Logf("%s completed through an MCP chat turn; the model was called %d times", tool, model.calls)
}
