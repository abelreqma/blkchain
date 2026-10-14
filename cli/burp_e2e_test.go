package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"
	"github.com/gorilla/websocket"
)

// These two tests automate the Burp acceptance whose full procedure, and the
// reason each path has its own evidence, is in mcpchat_operator_test.go.
//
// Both need BLKCHAIN_BURP_E2E=1, a running Burp with its MCP server enabled, and
// an MCP client config naming it. go test redirects the default config location
// into a temporary directory, so BLKCHAIN_MCP_CLIENT_CONFIG has to name the
// operator's file. Every request these tests send goes to a loopback fixture
// they start.

func requireBurpE2E(t *testing.T) string {
	t.Helper()
	if os.Getenv("BLKCHAIN_BURP_E2E") != "1" {
		t.Skip("set BLKCHAIN_BURP_E2E=1 with Burp running, its MCP server enabled, and its proxy listener up")
	}
	return useOperatorMCPConfig(t)
}

// TestBurpMCPServerRegistersItsAllowlistedTools pins that the operator's config
// loads and that every tool its allowlist names reaches the chat registry. It
// reports any allowlisted tool the server did not offer.
func TestBurpMCPServerRegistersItsAllowlistedTools(t *testing.T) {
	path := requireBurpE2E(t)
	config, err := loadChatMCPConfig()
	if err != nil {
		t.Fatalf("MCP client config at %s: %v", path, err)
	}
	var wanted []string
	for _, server := range config.Servers {
		for _, tool := range server.AllowTools {
			wanted = append(wanted, chatMCPExposedName(server.Name, tool))
		}
	}
	if len(wanted) == 0 {
		t.Skipf("the MCP client config at %s allowlists no tools", path)
	}
	registry := tooldef.NewRegistry()
	closeMCP, err := registerChatMCPTools(context.Background(), registry, t.TempDir(), vantageLocal)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	defer closeMCP()
	registered := map[string]bool{}
	for _, name := range registry.Names() {
		registered[name] = true
	}
	var missing []string
	for _, name := range wanted {
		if !registered[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("%d of %d allowlisted tools did not register: %s", len(missing), len(wanted), strings.Join(missing, " "))
	}
	t.Logf("%d allowlisted MCP tools registered", len(wanted))
}

// TestBurpProxyCapturesEngageWebCollect pins the second path: engage web collect
// against a loopback fixture traverses Burp's listener, and the request is found
// in Proxy history by its own fields. History is read through the Burp MCP tool
// and never logged, because proxy history can hold secrets.
func TestBurpProxyCapturesEngageWebCollect(t *testing.T) {
	requireBurpE2E(t)
	registry := tooldef.NewRegistry()
	closeMCP, err := registerChatMCPTools(context.Background(), registry, t.TempDir(), vantageLocal)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	defer closeMCP()
	history, ok := registry.Get("mcp__burp__get_proxy_http_history_regex")
	if !ok {
		t.Skip("the configured Burp server does not expose get_proxy_http_history_regex, so capture cannot be verified here")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>burp acceptance fixture</body></html>"))
	}))
	defer target.Close()
	useBurpE2EProxy(t)
	roePath := filepath.Join(t.TempDir(), "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := webExecute(context.Background(), []string{"collect", target.URL, "--workspace", t.TempDir(), "--roe", roePath, "--transcript", "off", "--no-rdns"}, secgate.Auto, nil, false, 120); err != nil {
		t.Fatalf("engage web collect failed: %v", err)
	}
	host := strings.TrimPrefix(target.URL, "http://")
	args, err := json.Marshal(map[string]any{"regex": regexp.QuoteMeta(host), "count": 5, "offset": 0})
	if err != nil {
		t.Fatal(err)
	}
	out, err := history.Call(context.Background(), string(args))
	if err != nil {
		t.Fatalf("reading Burp proxy history failed: %v", err)
	}
	if !strings.Contains(out, host) {
		t.Fatalf("the collected request was not found in Burp's proxy history (%d bytes of history matched %q)", len(out), host)
	}
	t.Logf("engage web collect against %s was found in Burp's proxy history", target.URL)
}

// TestBurpWebSocketHistoryCapturesAcquisition pins that WebSocket acquisition
// traverses Burp's listener too, which is the only thing that makes the
// allowlisted WebSocket history tools return anything. The fixture sends the
// frame, so the check stays on the passive path the default RoE permits. The
// frame body is a fixed fixture string and the history result is never logged.
func TestBurpWebSocketHistoryCapturesAcquisition(t *testing.T) {
	requireBurpE2E(t)
	registry := tooldef.NewRegistry()
	closeMCP, err := registerChatMCPTools(context.Background(), registry, t.TempDir(), vantageLocal)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	defer closeMCP()
	history, ok := registry.Get("mcp__burp__get_proxy_websocket_history_regex")
	if !ok {
		t.Skip("the configured Burp server does not expose get_proxy_websocket_history_regex, so WebSocket capture cannot be verified here")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, upgradeErr := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if upgradeErr != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.TextMessage, []byte("burp acceptance fixture"))
	}))
	defer target.Close()
	useBurpE2EProxy(t)
	scope, err := secgate.ParseScope(strings.NewReader("127.0.0.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	gate := &secgate.Gate{Mode: secgate.Auto, Scope: scope, Policy: secgate.DefaultPolicy()}
	if err = gate.Start(); err != nil {
		t.Fatal(err)
	}
	broker := newWebBroker(gate, nil)
	if broker.Policy.Upstream == nil {
		t.Fatal("the engagement broker did not pick up the proxy")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw := "ws" + strings.TrimPrefix(target.URL, "http") + "/stream"
	socket, response, err := broker.OpenWebSocket(ctx, raw, nil, nil)
	if err != nil || response.Status != http.StatusSwitchingProtocols {
		t.Fatalf("the WebSocket handshake through Burp failed: %+v %v", response, err)
	}
	kind, body, err := socket.Receive()
	if err != nil || kind != websocket.TextMessage || string(body) != "burp acceptance fixture" {
		t.Fatalf("receiving a frame through Burp failed: %d %q %v", kind, body, err)
	}
	socket.Close()
	args, err := json.Marshal(map[string]any{"regex": "burp acceptance fixture", "count": 5, "offset": 0})
	if err != nil {
		t.Fatal(err)
	}
	out, err := history.Call(ctx, string(args))
	if err != nil {
		t.Fatalf("reading Burp WebSocket history failed: %v", err)
	}
	if !strings.Contains(out, "burp acceptance fixture") {
		t.Fatalf("the sent frame was not found in Burp's WebSocket history (%d bytes of history matched)", len(out))
	}
	t.Logf("a WebSocket frame sent to %s was found in Burp's WebSocket history", target.URL)
}

// burpE2EProxyAddress is Burp's default proxy listener.
const burpE2EProxyAddress = "127.0.0.1:8080"

// useBurpE2EProxy routes the web stack through Burp's listener, skipping the
// test when the listener or the operator-exported Burp CA named by
// webProxyCAEnv is missing.
func useBurpE2EProxy(t *testing.T) {
	t.Helper()
	if os.Getenv(webProxyCAEnv) == "" {
		t.Skipf("set %s to Burp's exported CA certificate", webProxyCAEnv)
	}
	forgetWebProxy(burpE2EProxyAddress)
	t.Setenv(webProxyEnv, burpE2EProxyAddress)
	t.Cleanup(func() { forgetWebProxy(burpE2EProxyAddress) })
	if upstream := webUpstreamProxy(); upstream == nil {
		t.Skipf("no usable proxy at %s; start Burp's proxy listener", burpE2EProxyAddress)
	}
}
