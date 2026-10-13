package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/tooldef"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestChatMCPClientExposesOnlyAllowlistedHTTPTools(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	type input struct {
		Message string `json:"message"`
	}
	for _, name := range []string{"allowed", "denied"} {
		mcp.AddTool(server, &mcp.Tool{Name: name, Description: "fixture tool"}, func(_ context.Context, _ *mcp.CallToolRequest, in input) (*mcp.CallToolResult, any, error) {
			return nil, map[string]any{"echo": in.Message}, nil
		})
	}
	endpoint := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{JSONResponse: true}))
	defer endpoint.Close()
	config := chatMCPConfig{Servers: []chatMCPServer{{Name: "fixture", Transport: "http", URL: endpoint.URL, AllowTools: []string{"allowed"}}}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mcp-clients.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_MCP_CLIENT_CONFIG", path)
	registry := tooldef.NewRegistry()
	closeTools, err := registerChatMCPTools(context.Background(), registry, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	if _, ok := registry.Get("mcp__fixture__denied"); ok {
		t.Fatal("MCP tool outside the allowlist was exposed")
	}
	tool, ok := registry.Get("mcp__fixture__allowed")
	if !ok {
		t.Fatal("allowed MCP tool was not exposed")
	}
	out, err := tool.Call(context.Background(), `{"message":"fixture-value"}`)
	if err != nil || !strings.Contains(out, "fixture-value") || !strings.Contains(out, "UNTRUSTED") {
		t.Fatalf("MCP call failed: out=%q err=%v", out, err)
	}
	if os.Getenv("BLKCHAIN_CHAT_TOOLS_E2E") == "1" {
		var stages []string
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		answer, _, _, _, _, _, err := adaptiveAnswer(ctx, nil, loadConfig(),
			"Use the configured MCP fixture tool to send message blue and report its result.", enabledRoutes{}, false,
			AnswerOpts{Agent: "auto", Stage: func(stage string) { stages = append(stages, stage) }})
		if err != nil || !strings.Contains(strings.Join(stages, " "), "tool mcp__fixture__allowed") || !strings.Contains(answer, "blue") {
			t.Fatalf("local model did not use the allowed MCP tool: stages=%v answer=%q err=%v", stages, answer, err)
		}
	}
}

func TestChatMCPConfigRequiresPerServerAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp-clients.json")
	t.Setenv("BLKCHAIN_MCP_CLIENT_CONFIG", path)
	for _, config := range []string{
		`{"servers":[{"name":"fixture","transport":"http","url":"http://127.0.0.1:1234/mcp"}]}`,
		`{"servers":[{"name":"fixture","transport":"stdio","host":"local","command":"relative","allow_tools":["x"]}]}`,
	} {
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadChatMCPConfig(); err == nil {
			t.Fatalf("invalid MCP config accepted: %s", config)
		}
	}
}

func TestChatMCPHTTPBearerNeverFollowsRedirect(t *testing.T) {
	var redirected bool
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, receiver.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	t.Setenv("BLKCHAIN_TEST_MCP_TOKEN", "fixture-token")
	transport, err := chatMCPTransport(context.Background(), chatMCPServer{
		Name: "fixture", Transport: "http", URL: server.URL, TokenEnv: "BLKCHAIN_TEST_MCP_TOKEN",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if session, err := client.Connect(ctx, transport, nil); err == nil {
		session.Close()
		t.Fatal("redirected MCP endpoint connected")
	}
	if redirected {
		t.Fatal("MCP bearer token was sent to a redirected endpoint")
	}
}

func TestChatMCPHTTPResponseIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", chatMCPResponseBytes+1)))
	}))
	defer server.Close()
	client := &http.Client{Transport: chatMCPAuthTransport{base: http.DefaultTransport}}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, err = io.ReadAll(response.Body)
	var limit *http.MaxBytesError
	if !errors.As(err, &limit) {
		t.Fatalf("oversized MCP HTTP response was accepted: %v", err)
	}
}

func TestChatMCPExposedNamesAreBoundedAndDistinct(t *testing.T) {
	first := chatMCPExposedName("fixture", "tools/read.file")
	second := chatMCPExposedName("fixture", "tools-read-file")
	if first == second || len(first) > 64 || len(second) > 64 || !chatMCPToolNamePattern.MatchString(first) {
		t.Fatalf("invalid exposed MCP names: %q and %q", first, second)
	}
}

func TestChatMCPStdioHelper(t *testing.T) {
	if os.Getenv("BLKCHAIN_MCP_TEST_HELPER") != "1" {
		return
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "stdio-fixture", Version: "1"}, nil)
	type input struct {
		Message string `json:"message"`
	}
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "echo a value"}, func(_ context.Context, _ *mcp.CallToolRequest, in input) (*mcp.CallToolResult, any, error) {
		return nil, map[string]any{"echo": in.Message}, nil
	})
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestChatMCPClientConnectsToLocalStdioWhenConfigured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp-clients.json")
	config := chatMCPConfig{Servers: []chatMCPServer{{
		Name: "stdio_fixture", Transport: "stdio", Host: "local", Command: os.Args[0],
		Args: []string{"-test.run=^TestChatMCPStdioHelper$"}, AllowTools: []string{"echo"},
		Env: map[string]string{"BLKCHAIN_MCP_TEST_HELPER": "BLKCHAIN_MCP_TEST_HELPER"},
	}}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_MCP_CLIENT_CONFIG", path)
	t.Setenv("BLKCHAIN_MCP_TEST_HELPER", "1")
	registry := tooldef.NewRegistry()
	closeTools, err := registerChatMCPTools(context.Background(), registry, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, ok := registry.Get("mcp__stdio_fixture__echo")
	if !ok {
		t.Fatal("stdio MCP tool was not discovered")
	}
	out, err := tool.Call(context.Background(), `{"message":"stdio-value"}`)
	if err != nil || !strings.Contains(out, "stdio-value") {
		t.Fatalf("stdio call failed: out=%q err=%v", out, err)
	}
}

func TestChatMCPClientConnectsToSandboxStdio(t *testing.T) {
	if os.Getenv("BLKCHAIN_CHAT_MCP_SANDBOX_E2E") != "1" {
		t.Skip("set BLKCHAIN_CHAT_MCP_SANDBOX_E2E=1 with Docker running")
	}
	codeDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	root, err := chatWorkspaceRoot("")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "mcp-echo")
	build := exec.Command("go", "build", "-o", binary, "./testdata/mcp_echo")
	build.Dir = codeDir
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build sandbox fixture: %v: %s", err, out)
	}
	config := chatMCPConfig{Servers: []chatMCPServer{{Name: "sandbox_fixture", Transport: "stdio", Command: "/work/mcp-echo", AllowTools: []string{"echo"}}}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mcp-clients.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_MCP_CLIENT_CONFIG", path)
	name := chatContainerName(root)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = chatDocker(ctx, nil, "rm", "-f", name)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	registry := tooldef.NewRegistry()
	closeTools, err := registerChatMCPTools(ctx, registry, root)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, ok := registry.Get("mcp__sandbox_fixture__echo")
	if !ok {
		t.Fatal("sandbox MCP tool was not registered")
	}
	out, err := tool.Call(ctx, `{"message":"sandbox-mcp-value"}`)
	if err != nil || !strings.Contains(out, "sandbox-mcp-value") {
		t.Fatalf("sandbox MCP call failed: out=%q err=%v", out, err)
	}
}
