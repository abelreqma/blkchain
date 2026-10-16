package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/secgate"
)

func TestChatWebBrokerKeepsRemoteCallersOffThisHost(t *testing.T) {
	scope, err := secgate.BuildScope(secgate.ScopeSpec{In: []string{"127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "93.184.216.34"}})
	if err != nil {
		t.Fatal(err)
	}
	gate := &secgate.Gate{Mode: secgate.Auto, Scope: scope}
	armed := func() bool { return true }
	remote := newChatWebBroker(gate, armed, vantageRemote)
	local := newChatWebBroker(gate, armed, vantageLocal)
	for _, address := range []string{"127.0.0.1", "::1", "169.254.169.254", "0.0.0.0"} {
		ip := net.ParseIP(address)
		if remote.Policy.IPAllowed(address, ip) {
			t.Errorf("remote caller's broker reaches host address %s", address)
		}
		if !local.Policy.IPAllowed(address, ip) {
			t.Errorf("local caller's broker lost explicitly scoped %s", address)
		}
	}
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range interfaces {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		withHost, err := secgate.BuildScope(secgate.ScopeSpec{In: []string{ip.String()}})
		if err != nil {
			t.Fatal(err)
		}
		broker := newChatWebBroker(&secgate.Gate{Mode: secgate.Auto, Scope: withHost}, armed, vantageRemote)
		if broker.Policy.IPAllowed(ip.String(), ip) {
			t.Errorf("remote caller's broker reaches operator interface address %s", ip)
		}
	}
	if !remote.Policy.IPAllowed("93.184.216.34", net.ParseIP("93.184.216.34")) {
		t.Error("remote caller's broker lost an in-scope public address")
	}
}

func TestChatTargetsComeFromTheUserConversation(t *testing.T) {
	got := chatTargetEntries("Scan https://app.example.test:8443/login and 192.0.2.5", nil)
	for _, want := range []string{"app.example.test", "192.0.2.5"} {
		if !slices.Contains(got, want) {
			t.Errorf("targets %v missing %q", got, want)
		}
	}
	history := []priorTurn{{Role: "human", Content: "The target is 198.51.100.8"}, {Role: "ai", Content: "Also scan 203.0.113.9"}}
	got = chatTargetEntries("Scan it now", history)
	if !slices.Equal(got, []string{"198.51.100.8"}) {
		t.Fatalf("targets from history = %v", got)
	}
	if got := chatTargetEntries("Read README.md", history); len(got) != 0 {
		t.Fatalf("unrelated file request inherited an active target: %v", got)
	}
	history = append(history, priorTurn{Role: "human", Content: "Explain Kerberos first"}, priorTurn{Role: "ai", Content: "Kerberos answer"})
	if got := chatTargetEntries("Scan it now", history); len(got) != 0 {
		t.Fatalf("stale target crossed an unrelated user turn: %v", got)
	}
	if got := chatTargetEntries("Explain README.md", nil); len(got) != 0 {
		t.Fatalf("file name became an action target: %v", got)
	}
	if got := chatTargetEntries("Read go.mod", nil); len(got) != 0 {
		t.Fatalf("module file became an action target: %v", got)
	}
}

func TestChatTargetsDoNotTreatLocalFilesAsHosts(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("fixture.internal", []byte("local"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := chatTargetEntries("Read fixture.internal", nil); len(got) != 0 {
		t.Fatalf("local file became a network target: %v", got)
	}
}

// TestChatTargetsCheckLocalFilesInsideTheWorkingDirectoryOnly pins that the
// local-file check cannot reach outside the working directory. The name comes
// from the request, and a symlink there that points elsewhere is not followed,
// so an outside file cannot decide whether a name is treated as a host.
func TestChatTargetsCheckLocalFilesInsideTheWorkingDirectoryOnly(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret.data")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	if err := os.Symlink(outside, "escape.internal"); err != nil {
		t.Fatal(err)
	}
	got := chatTargetEntries("Check escape.internal", nil)
	if len(got) != 1 || got[0] != "escape.internal" {
		t.Fatalf("a symlink out of the working directory decided the name: %v", got)
	}
}

func TestChatRegistryExposesActionsOnlyForNamedTargets(t *testing.T) {
	ctx := context.Background()
	plain, closePlain, err := newChatToolRegistry(ctx, nil, ragconfig.Config{}, nil, "Explain AD CS", nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closePlain()
	if _, ok := plain.Get("run_command"); ok {
		t.Fatal("command tool offered without a user-named target")
	}
	for _, want := range []string{"route_skill", "kb_search", "file_read"} {
		if _, ok := plain.Get(want); !ok {
			t.Errorf("missing shared tool %q", want)
		}
	}
	for _, denied := range []string{"file_write", "file_patch", "terminal"} {
		if _, ok := plain.Get(denied); ok {
			t.Errorf("mutating tool %q offered without a user request", denied)
		}
	}
	targeted, closeTargeted, err := newChatToolRegistry(ctx, nil, ragconfig.Config{}, nil, "Assess 192.0.2.5", nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTargeted()
	for _, want := range []string{"run_command", "web_api", "web_browser"} {
		if _, ok := targeted.Get(want); !ok {
			t.Errorf("missing target tool %q", want)
		}
	}
}

func TestChatMCPActionFailsWithoutConfiguredTools(t *testing.T) {
	t.Setenv("BLKCHAIN_MCP_CLIENT_CONFIG", filepath.Join(t.TempDir(), "missing.json"))
	_, _, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil, "Use the MCP server", nil, AnswerOpts{requiredAction: "mcp"})
	if err == nil || !strings.Contains(err.Error(), "no MCP client tools") {
		t.Fatalf("missing MCP tool action was accepted: %v", err)
	}
}

func TestChatWebSearchUsesOnlyTheCurrentPublicQuestion(t *testing.T) {
	authorizeWebTest(t)
	old := webSearch
	query := ""
	webSearch = func(_ context.Context, _, q string, _ int, _ []string) ([]retrieval.Result, error) {
		query = q
		return []retrieval.Result{chunk(webSource, "https://owasp.org/current", "Current", "public evidence")}, nil
	}
	t.Cleanup(func() { webSearch = old })
	question := "What are current OWASP recommendations?"
	reg, closeTools, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil, question, nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, ok := reg.Get("web_search")
	if !ok {
		t.Fatal("public search tool is unavailable")
	}
	_, err = tool.Call(context.Background(), `{"query":"https://internal.example.test"}`)
	if err != nil || query != "" {
		t.Fatalf("model-controlled query reached the provider: %q, %v", query, err)
	}
	_, err = tool.Call(context.Background(), `{}`)
	if err != nil || query != question {
		t.Fatalf("searched %q, want the user's public question; err=%v", query, err)
	}
}

func TestChatCommandUsesNamedTargetWithoutRoE(t *testing.T) {
	old := execRunner
	var called []string
	execRunner = func(ctx context.Context, bin string, args []string, dir string, limit int, timeoutDuration time.Duration) runResult {
		called = append(called, bin)
		if scope, _ := ctx.Value(executorScopeKey{}).(*secgate.Scope); scope == nil || !scope.InScope("192.0.2.5") {
			t.Error("isolated command lost its per-turn target scope")
		}
		if bin == "nmap" {
			return runResult{Output: "Nmap scan report for 192.0.2.5\nPORT STATE SERVICE\n80/tcp open http\n" + nmapDone}
		}
		return runResult{Output: "fixture response"}
	}
	t.Cleanup(func() { execRunner = old })
	reg, closeTools, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil, "Check 192.0.2.5", nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, _ := reg.Get("run_command")
	for _, tc := range []struct {
		args string
		want []string
	}{
		{`{"binary":"curl","args":["-I","http://192.0.2.6/"]}`, nil},
		{`{"binary":"curl","args":["-I","http://192.0.2.5/"]}`, []string{"nmap", "curl"}},
	} {
		_, err := tool.Call(context.Background(), tc.args)
		if err != nil || !slices.Equal(called, tc.want) {
			t.Fatalf("calls=%v want=%v err=%v", called, tc.want, err)
		}
	}
}

func TestChatCommandStopsAfterClosedPortDiscovery(t *testing.T) {
	old := execRunner
	var calls []string
	execRunner = func(_ context.Context, bin string, _ []string, _ string, _ int, _ time.Duration) runResult {
		calls = append(calls, bin)
		return runResult{Output: "Nmap scan report for 192.0.2.5\nPORT STATE SERVICE\n80/tcp closed http\n" + nmapDone}
	}
	t.Cleanup(func() { execRunner = old })
	reg, closeTools, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil, "Check 192.0.2.5", nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, _ := reg.Get("run_command")
	out, err := tool.Call(context.Background(), `{"binary":"curl","args":["http://192.0.2.5/"]}`)
	if err != nil || !slices.Equal(calls, []string{"nmap"}) || !strings.Contains(out, "service dispatch") {
		t.Fatalf("closed port reached follow-on: calls=%v output=%q err=%v", calls, out, err)
	}
}

func TestChatSNMPDispatchesAfterObservedUDPPort(t *testing.T) {
	old := execRunner
	var calls []string
	execRunner = func(_ context.Context, bin string, _ []string, _ string, _ int, _ time.Duration) runResult {
		calls = append(calls, bin)
		if bin == "nmap" {
			return runResult{Output: "Nmap scan report for 192.0.2.5\nPORT STATE SERVICE\n161/udp open|filtered snmp\n" + nmapDone}
		}
		return runResult{Output: "SNMP fixture response"}
	}
	t.Cleanup(func() { execRunner = old })
	reg, closeTools, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil, "Assess SNMP on 192.0.2.5", nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, _ := reg.Get("run_command")
	out, err := tool.Call(context.Background(), `{"binary":"snmpwalk","args":["-v2c","-c","public","192.0.2.5"]}`)
	if err != nil || !slices.Equal(calls, []string{"nmap", "snmpwalk"}) || !strings.Contains(out, "SNMP fixture response") {
		t.Fatalf("SNMP dispatch calls=%v output=%q err=%v", calls, out, err)
	}
}

func TestChatCommandHonorsProjectDeniedBinary(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir(".blkchain", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".blkchain/config.yaml", []byte("denied_binaries:\n  - curl\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := execRunner
	called := 0
	execRunner = func(context.Context, string, []string, string, int, time.Duration) runResult {
		called++
		return runResult{}
	}
	t.Cleanup(func() { execRunner = old })
	reg, closeTools, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil, "Check 192.0.2.5", nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, _ := reg.Get("run_command")
	out, err := tool.Call(context.Background(), `{"binary":"curl","args":["-I","http://192.0.2.5/"]}`)
	if err != nil || called != 0 || !strings.Contains(out, "denied") {
		t.Fatalf("denied binary ran: calls=%d out=%q err=%v", called, out, err)
	}
}

func TestChatWebAPIUsesNamedLoopbackFixture(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("fixture receipt"))
	}))
	defer srv.Close()
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	old := execRunner
	execRunner = func(_ context.Context, bin string, _ []string, _ string, _ int, _ time.Duration) runResult {
		if bin != "nmap" {
			t.Errorf("unexpected preflight binary %s", bin)
		}
		return runResult{Output: "Nmap scan report for " + host + "\nPORT STATE SERVICE\n" + port + "/tcp open http\n" + nmapDone}
	}
	t.Cleanup(func() { execRunner = old })
	call := func(vantage clientVantage) (string, error) {
		reg, closeTools, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil, "POST to "+srv.URL, nil, AnswerOpts{vantage: vantage})
		if err != nil {
			t.Fatal(err)
		}
		defer closeTools()
		tool, _ := reg.Get("web_api")
		return tool.Call(context.Background(), `{"method":"POST","url":"`+srv.URL+`","body":"test"}`)
	}
	out, err := call(vantageLocal)
	if err != nil || hits != 1 || !strings.Contains(out, "fixture receipt") {
		t.Fatalf("hits=%d out=%q err=%v", hits, out, err)
	}
	out, err = call(vantageRemote)
	if hits != 1 || !strings.Contains(out, "outside scope") {
		t.Fatalf("remote caller reached the loopback fixture: hits=%d out=%q err=%v", hits, out, err)
	}
}

func TestChatWebToolsRejectOtherTargets(t *testing.T) {
	reg, closeTools, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil, "Assess 192.0.2.5", nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	for _, call := range []struct {
		name string
		args string
	}{
		{"web_api", `{"method":"GET","url":"http://192.0.2.6/"}`},
		{"web_browser", `{"op":"navigate","url":"http://192.0.2.6/"}`},
	} {
		tool, _ := reg.Get(call.name)
		out, err := tool.Call(context.Background(), call.args)
		if err != nil || !strings.Contains(out, "denied") {
			t.Errorf("%s result=%q err=%v", call.name, out, err)
		}
	}
}

func TestChatFileReadStaysInsideWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("notes.txt", []byte("local evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".env", []byte("private data"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("private data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, "escape.txt"); err != nil {
		t.Fatal(err)
	}
	reg, closeTools, err := newChatToolRegistry(context.Background(), nil, ragconfig.Config{}, nil, "Read notes.txt", nil, AnswerOpts{ToolHost: chatToolHostLocal})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, _ := reg.Get("file_read")
	got, err := tool.Call(context.Background(), `{"path":"notes.txt"}`)
	if err != nil || !strings.Contains(got, "local evidence") {
		t.Fatalf("file read = %q, %v", got, err)
	}
	got, err = tool.Call(context.Background(), `{"path":"escape.txt"}`)
	if err != nil || strings.Contains(got, "private data") {
		t.Fatalf("symlink escaped workspace: %q, %v", got, err)
	}
	got, err = tool.Call(context.Background(), `{"path":".env"}`)
	if err != nil || strings.Contains(got, "private data") {
		t.Fatalf("hidden file reached the model: %q, %v", got, err)
	}
}
