package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"blkchain/cli/internal/secgate"
)

// recordingMCPTool stands in for the chat MCP tool a gated wrapper wraps. It
// records every call, so a test can assert that a refusal never reached the
// remote server, and returns a canned body, so a test can assert an allowed call
// returns the inner output unchanged.
type recordingMCPTool struct {
	name   string
	output string
	calls  int
	args   string
}

func (r *recordingMCPTool) Name() string           { return r.name }
func (r *recordingMCPTool) Description() string    { return "recording inner tool" }
func (r *recordingMCPTool) Schema() map[string]any { return map[string]any{"type": "object"} }

func (r *recordingMCPTool) Call(ctx context.Context, args string) (string, error) {
	r.calls++
	r.args = args
	return r.output, nil
}

// engageMCPRequestArgs builds one send-tool argument object. content carries the
// JSON escapes the Burp schema expects in a raw request.
func engageMCPRequestArgs(content, host string, port int, https bool) string {
	scheme := "false"
	if https {
		scheme = "true"
	}
	return `{"content":"` + content + `","targetHostname":"` + host +
		`","targetPort":` + strconv.Itoa(port) + `,"usesHttps":` + scheme + `}`
}

// engageMCPActiveTier reports whether the gate tiers a target as active, by
// presenting it to a real gate on an unarmed task: an active web action requires
// an armed task, so a tier denial means active and an allow means recon. The
// assertion is on the gate's outcome rather than on the method string the parser
// returned, so the test cannot pass on whatever the parser happens to produce.
func engageMCPActiveTier(t *testing.T, target engageMCPRequestTarget) bool {
	t.Helper()
	d := webConfirmGate(t).AuthorizeAPIRequest(context.Background(),
		secgate.APIRequest{Method: target.Method, URL: target.URL, Armed: false})
	if d.Allowed {
		return false
	}
	if !strings.Contains(d.Reason, "requires an armed task") {
		t.Fatalf("unarmed denial for %+v was not the phase tier: %q", target, d.Reason)
	}
	return true
}

func TestEngageMCPClassifyDeniesWhatItDoesNotKnow(t *testing.T) {
	var zero engageMCPAction
	if zero != engageMCPDenied {
		t.Fatalf("the zero engageMCPAction must deny, got %v", zero)
	}
	for _, c := range []struct{ server, tool string }{
		{"burp", "no_such_tool"},
		{"github", "create_pull_request"},
		{"", ""},
	} {
		if got := engageMCPClassify(c.server, c.tool); got != engageMCPDenied {
			t.Errorf("engageMCPClassify(%q, %q) = %v, want engageMCPDenied", c.server, c.tool, got)
		}
	}
}

func TestEngageMCPClassifyCoversEveryConfiguredBurpTool(t *testing.T) {
	want := map[string]engageMCPAction{
		"send_http1_request":                engageMCPRequest,
		"send_http2_request":                engageMCPRequest,
		"send_to_intruder":                  engageMCPRequest,
		"get_proxy_http_history":            engageMCPRead,
		"get_proxy_http_history_regex":      engageMCPRead,
		"get_proxy_websocket_history":       engageMCPRead,
		"get_proxy_websocket_history_regex": engageMCPRead,
		"get_organizer_items":               engageMCPRead,
		"get_organizer_items_regex":         engageMCPRead,
		"get_scanner_issues":                engageMCPRead,
		"get_active_editor_contents":        engageMCPRead,
		"get_collaborator_interactions":     engageMCPRead,
		"base64_encode":                     engageMCPPure,
		"base64_decode":                     engageMCPPure,
		"url_encode":                        engageMCPPure,
		"url_decode":                        engageMCPPure,
		"generate_random_string":            engageMCPPure,
		"generate_collaborator_payload":     engageMCPPure,
		"create_repeater_tab":               engageMCPDenied,
		"create_repeater_tab_http2":         engageMCPDenied,
		"set_active_editor_contents":        engageMCPDenied,
		"set_project_options":               engageMCPDenied,
		"set_proxy_intercept_state":         engageMCPDenied,
		"set_task_execution_engine_state":   engageMCPDenied,
		"set_user_options":                  engageMCPDenied,
		"output_project_options":            engageMCPDenied,
		"output_user_options":               engageMCPDenied,
	}
	if len(want) != 27 {
		t.Fatalf("the table holds %d Burp tools, want the 27 the operator configured", len(want))
	}
	// The table is asserted against the classifier's own size, so a tool added
	// there without a row here fails rather than going unasserted.
	if len(engageMCPActions["burp"]) != len(want) {
		t.Fatalf("the classifier holds %d Burp tools and this table holds %d",
			len(engageMCPActions["burp"]), len(want))
	}
	counts := map[engageMCPAction]int{}
	for _, action := range want {
		counts[action]++
	}
	for action, n := range map[engageMCPAction]int{
		engageMCPRequest: 3,
		engageMCPRead:    9,
		engageMCPPure:    6,
		engageMCPDenied:  9,
	} {
		if counts[action] != n {
			t.Errorf("the table holds %d tools of action %v, want %d", counts[action], action, n)
		}
	}
	for tool, action := range want {
		if got := engageMCPClassify("burp", tool); got != action {
			t.Errorf("engageMCPClassify(\"burp\", %q) = %v, want %v", tool, got, action)
		}
	}
	// Every classified name is reachable only under the burp server key.
	for tool := range want {
		if got := engageMCPClassify("not-burp", tool); got != engageMCPDenied {
			t.Errorf("engageMCPClassify(\"not-burp\", %q) = %v, want engageMCPDenied", tool, got)
		}
	}
}

// TestEngageMCPClassifyMatchesTheShippedBurpAllowlist ties the classifier to the
// tool list the shipped config carries, which is the list of tools an operator
// starts from. A tool added there without a ruling here fails rather than
// landing in the denied group unnoticed, and a ruling for a tool the config does
// not name fails too.
func TestEngageMCPClassifyMatchesTheShippedBurpAllowlist(t *testing.T) {
	data, err := os.ReadFile("mcp-clients.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var config chatMCPConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	var allowed []string
	for _, server := range config.Servers {
		if server.Name == engageMCPWebInstrument {
			allowed = server.AllowTools
		}
	}
	if len(allowed) == 0 {
		t.Fatalf("mcp-clients.example.json names no %q server with an allow_tools list", engageMCPWebInstrument)
	}
	classified := engageMCPActions[engageMCPWebInstrument]
	for _, tool := range allowed {
		if _, ok := classified[tool]; !ok {
			t.Errorf("%s is configured and unclassified, so an engagement refuses it with no ruling behind the refusal", tool)
		}
	}
	for tool := range classified {
		if !slices.Contains(allowed, tool) {
			t.Errorf("%s is classified and the shipped config does not configure it", tool)
		}
	}
}

func TestEngageMCPTargetReadsTheMethodAndURLFromTheArguments(t *testing.T) {
	cases := []struct {
		name       string
		tool       string
		args       string
		wantMethod string
		wantURL    string
	}{
		{
			name:       "https read",
			tool:       "send_http1_request",
			args:       engageMCPRequestArgs(`GET /a HTTP/1.1\r\nHost: x\r\n\r\n`, "app.example", 443, true),
			wantMethod: "GET",
			wantURL:    "https://app.example:443/a",
		},
		{
			name:       "plain http",
			tool:       "send_http1_request",
			args:       engageMCPRequestArgs(`GET /a HTTP/1.1\r\nHost: x\r\n\r\n`, "app.example", 80, false),
			wantMethod: "GET",
			wantURL:    "http://app.example:80/a",
		},
		{
			name:       "state changing method",
			tool:       "send_http2_request",
			args:       engageMCPRequestArgs(`POST /login HTTP/1.1\r\nHost: x\r\n\r\n`, "app.example", 443, true),
			wantMethod: "POST",
			wantURL:    "https://app.example:443/login",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target, err := engageMCPTargetFromArgs(c.tool, c.args)
			if err != nil {
				t.Fatalf("engageMCPTargetFromArgs: %v", err)
			}
			if target.Method != c.wantMethod {
				t.Errorf("method = %q, want %q", target.Method, c.wantMethod)
			}
			if target.URL != c.wantURL {
				t.Errorf("url = %q, want %q", target.URL, c.wantURL)
			}
		})
	}

	// Intruder fuzzes the request whatever verb its request line carries, so a
	// GET request line still reaches the gate as active.
	target, err := engageMCPTargetFromArgs("send_to_intruder",
		engageMCPRequestArgs(`GET /search HTTP/1.1\r\nHost: x\r\n\r\n`, "10.0.0.5", 443, true))
	if err != nil {
		t.Fatalf("engageMCPTargetFromArgs: %v", err)
	}
	if target.URL != "https://10.0.0.5:443/search" {
		t.Errorf("intruder url = %q, want https://10.0.0.5:443/search", target.URL)
	}
	if !engageMCPActiveTier(t, target) {
		t.Error("send_to_intruder with a GET request line must still tier as active")
	}
	// The same request line through a send tool is recon, which is what makes the
	// case above a statement about send_to_intruder and not about the parser.
	read, err := engageMCPTargetFromArgs("send_http1_request",
		engageMCPRequestArgs(`GET /search HTTP/1.1\r\nHost: x\r\n\r\n`, "10.0.0.5", 443, true))
	if err != nil {
		t.Fatalf("engageMCPTargetFromArgs: %v", err)
	}
	if engageMCPActiveTier(t, read) {
		t.Error("a GET through send_http1_request must tier as recon")
	}
}

func TestEngageMCPTargetTreatsAnUnparsableRequestLineAsActive(t *testing.T) {
	for _, content := range []string{``, `\r\n\r\n`, `garbage`} {
		target, err := engageMCPTargetFromArgs("send_http1_request",
			engageMCPRequestArgs(content, "10.0.0.5", 443, true))
		if err != nil {
			t.Fatalf("content %q: engageMCPTargetFromArgs: %v", content, err)
		}
		if !engageMCPActiveTier(t, target) {
			t.Errorf("content %q must tier as active, the gate tiered it as recon", content)
		}
	}
}

func TestEngageMCPTargetRefusesMalformedArguments(t *testing.T) {
	cases := []struct {
		name string
		args string
		want error
	}{
		{"missing host", `{"content":"GET / HTTP/1.1","targetPort":443,"usesHttps":true}`, errEngageMCPHost},
		{"empty host", engageMCPRequestArgs(`GET / HTTP/1.1`, "", 443, true), errEngageMCPHost},
		{"host carries a path", engageMCPRequestArgs(`GET / HTTP/1.1`, "app.example/x", 443, true), errEngageMCPHost},
		// The quote and apostrophe forms matter most: secgate's URL pattern ends
		// its match at either, so without this guard the gate would scope-check a
		// prefix of what the argument named.
		{"host carries a quote", `{"content":"GET / HTTP/1.1","targetHostname":"in.scope.example\"evil.target","targetPort":443}`, errEngageMCPHost},
		{"host carries an apostrophe", engageMCPRequestArgs(`GET / HTTP/1.1`, "in.scope.example'evil.target", 443, true), errEngageMCPHost},
		{"host carries a semicolon", engageMCPRequestArgs(`GET / HTTP/1.1`, "in.scope.example;evil.target", 443, true), errEngageMCPHost},
		{"host carries userinfo", engageMCPRequestArgs(`GET / HTTP/1.1`, "user@real.target", 443, true), errEngageMCPHost},
		{"host is not a DNS name", engageMCPRequestArgs(`GET / HTTP/1.1`, "app_example", 443, true), errEngageMCPHost},
		{"host exceeds the length bound", engageMCPRequestArgs(`GET / HTTP/1.1`, strings.Repeat("a", 4096), 443, true), errEngageMCPHost},
		{"port below the range", engageMCPRequestArgs(`GET / HTTP/1.1`, "app.example", 0, true), errEngageMCPPort},
		{"port above the range", engageMCPRequestArgs(`GET / HTTP/1.1`, "app.example", 65536, true), errEngageMCPPort},
		{"missing port", `{"content":"GET / HTTP/1.1","targetHostname":"app.example","usesHttps":true}`, errEngageMCPPort},
		// Raw arguments, because the helper's int parameter cannot carry a JSON
		// number outside the int range. The range check has to refuse it before
		// any conversion: converting such a float64 to int is undefined in Go.
		{"port beyond the int range", `{"content":"GET / HTTP/1.1","targetHostname":"app.example","targetPort":1e30}`, errEngageMCPPort},
		{"non-string content", `{"content":5,"targetHostname":"app.example","targetPort":443}`, errEngageMCPContent},
		{"not json", `targetHostname=app.example`, errEngageMCPArgs},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target, err := engageMCPTargetFromArgs("send_http1_request", c.args)
			if !errors.Is(err, c.want) {
				t.Fatalf("error = %v, want %v", err, c.want)
			}
			if target.URL != "" || target.Method != "" {
				t.Errorf("a refused argument object must yield no target, got %+v", target)
			}
		})
	}

	// A refused argument object reaches no remote tool. The refusal carries the
	// argument error rather than the missing-gate one, which is the proof the
	// argument check ran before the gate branch.
	inner := &recordingMCPTool{name: "mcp__burp__send_http1_request", output: "sent"}
	tool := gatedMCPTool{inner: inner, server: "burp", remote: "send_http1_request"}
	out, err := tool.Call(context.Background(), `targetHostname=app.example`)
	if err != nil {
		t.Fatal(err)
	}
	if inner.calls != 0 {
		t.Fatalf("a malformed argument object reached the remote tool %d times", inner.calls)
	}
	if !strings.Contains(out, errEngageMCPArgs.Error()) {
		t.Errorf("refusal %q must carry the argument error", out)
	}
}

// TestEngageMCPTargetCarriesTheRequestTarget pins what the operator's
// confirmation reads: the path comes from the request line, and a target that is
// not an origin-form path contributes none rather than moving the authority.
func TestEngageMCPTargetCarriesTheRequestTarget(t *testing.T) {
	for _, c := range []struct {
		name, content, wantURL string
	}{
		{"path and query", `GET /a/b?q=1 HTTP/1.1\r\nHost: x\r\n\r\n`, "https://app.example:443/a/b?q=1"},
		{"root", `GET / HTTP/1.1`, "https://app.example:443/"},
		{"absolute form", `GET http://evil.target/x HTTP/1.1`, "https://app.example:443"},
		{"authority form", `CONNECT evil.target:443 HTTP/1.1`, "https://app.example:443"},
		{"asterisk form", `OPTIONS * HTTP/1.1`, "https://app.example:443"},
		{"second authority", `GET //evil.target/x HTTP/1.1`, "https://app.example:443"},
		{"no target at all", `GET`, "https://app.example:443"},
		{"target over the length bound", `GET /` + strings.Repeat("a", engageMCPRequestTargetMaxBytes) + ` HTTP/1.1`, "https://app.example:443"},
		{"byte outside the origin-form set", `GET /a,b HTTP/1.1`, "https://app.example:443"},
	} {
		t.Run(c.name, func(t *testing.T) {
			target, err := engageMCPTargetFromArgs("send_http1_request",
				engageMCPRequestArgs(c.content, "app.example", 443, true))
			if err != nil {
				t.Fatalf("engageMCPTargetFromArgs: %v", err)
			}
			if target.URL != c.wantURL {
				t.Errorf("url = %q, want %q", target.URL, c.wantURL)
			}
			if strings.Contains(target.URL, "evil.target") {
				t.Errorf("url = %q carries a host the arguments did not name", target.URL)
			}
		})
	}

	// A URL carrying a path is still scope-checked on its authority, so the path
	// buys the confirmation its specificity without costing the scope check.
	inner := &recordingMCPTool{name: "mcp__burp__send_http1_request", output: "HTTP/1.1 200 OK"}
	tool, ok := newGatedMCPTool(inner, "burp", "send_http1_request", autoGate(t), false)
	if !ok {
		t.Fatal("a request tool with a gate must be registered")
	}
	out, err := tool.Call(context.Background(),
		engageMCPRequestArgs(`GET /a/b?q=1 HTTP/1.1\r\nHost: x\r\n\r\n`, "10.0.0.5", 443, true))
	if err != nil {
		t.Fatal(err)
	}
	if inner.calls != 1 || out != "HTTP/1.1 200 OK" {
		t.Errorf("a GET with a path at an in-scope host: calls=%d out=%q", inner.calls, out)
	}
}

// TestEngageMCPMethodCannotForgeASentinel pins that neither sentinel is a label
// a request line can produce. Both carry a hyphen, which the method pattern
// cannot match, so an operator's approval of a send tool is not replayable as an
// approval of Intruder at the same authority.
func TestEngageMCPMethodCannotForgeASentinel(t *testing.T) {
	for _, sentinel := range []string{engageMCPIntruderMethod, engageMCPUnparsedMethod} {
		if engageMCPMethodPattern.MatchString(sentinel) {
			t.Errorf("the method pattern matches %q, so a request line can emit it", sentinel)
		}
	}
	for _, content := range []string{`INTRUDER-FUZZ / HTTP/1.1`, `INTRUDER / HTTP/1.1`, `intruder-fuzz / HTTP/1.1`} {
		for _, tool := range []string{"send_http1_request", "send_http2_request"} {
			target, err := engageMCPTargetFromArgs(tool, engageMCPRequestArgs(content, "10.0.0.5", 443, true))
			if err != nil {
				t.Fatalf("content %q through %s: %v", content, tool, err)
			}
			if target.Method == engageMCPIntruderMethod {
				t.Errorf("content %q through %s produced the Intruder label", content, tool)
			}
			if !engageMCPActiveTier(t, target) {
				t.Errorf("content %q through %s must tier as active", content, tool)
			}
		}
	}

	// send_to_intruder is the only producer of its own label, and the label is
	// tiered active.
	intruder, err := engageMCPTargetFromArgs("send_to_intruder",
		engageMCPRequestArgs(`GET / HTTP/1.1`, "10.0.0.5", 443, true))
	if err != nil {
		t.Fatal(err)
	}
	if intruder.Method != engageMCPIntruderMethod {
		t.Errorf("send_to_intruder method = %q, want %q", intruder.Method, engageMCPIntruderMethod)
	}
	if !engageMCPActiveTier(t, intruder) {
		t.Error("the Intruder sentinel must tier as active")
	}

	// A content whose first token spells the unparsed sentinel has no readable
	// method, so that label is what it gets and it stays accurate.
	unparsed, err := engageMCPTargetFromArgs("send_http1_request",
		engageMCPRequestArgs(engageMCPUnparsedMethod+` / HTTP/1.1`, "10.0.0.5", 443, true))
	if err != nil {
		t.Fatal(err)
	}
	if unparsed.Method != engageMCPUnparsedMethod {
		t.Errorf("an unreadable method = %q, want %q", unparsed.Method, engageMCPUnparsedMethod)
	}
	if !engageMCPActiveTier(t, unparsed) {
		t.Error("the unparsed sentinel must tier as active")
	}
}

// TestEngageMCPMethodBoundsTheRequestLineToken pins the bound on the token the
// method is read from: the token reaches the gate's audit label, so a long run
// of bytes and a control byte each yield the sentinel instead.
func TestEngageMCPMethodBoundsTheRequestLineToken(t *testing.T) {
	for _, content := range []string{
		strings.Repeat("A", 2048) + ` / HTTP/1.1`,
		`A\u0001A / HTTP/1.1`,
	} {
		target, err := engageMCPTargetFromArgs("send_http1_request",
			engageMCPRequestArgs(content, "10.0.0.5", 443, true))
		if err != nil {
			t.Fatalf("engageMCPTargetFromArgs: %v", err)
		}
		if target.Method != engageMCPUnparsedMethod {
			t.Errorf("method for a %d byte token = %q, want %q", len(content), target.Method, engageMCPUnparsedMethod)
		}
		if !engageMCPActiveTier(t, target) {
			t.Errorf("a token outside the method bound must tier as active, the gate tiered it as recon")
		}
	}
}

// TestGatedMCPToolDeniesARequestToolWithNoGate pins that the wrapper is
// independently nil-safe: the type is constructible by literal anywhere in the
// package, and a request classification with no gate denies rather than panics.
func TestGatedMCPToolDeniesARequestToolWithNoGate(t *testing.T) {
	inner := &recordingMCPTool{name: "mcp__burp__send_http1_request", output: "sent"}
	tool := gatedMCPTool{inner: inner, server: "burp", remote: "send_http1_request"}
	out, err := tool.Call(context.Background(),
		engageMCPRequestArgs(`GET /a HTTP/1.1\r\nHost: x\r\n\r\n`, "10.0.0.5", 443, true))
	if err != nil {
		t.Fatal(err)
	}
	if inner.calls != 0 {
		t.Fatalf("a request tool with no gate reached the remote tool %d times", inner.calls)
	}
	if !strings.Contains(out, "no engagement gate") {
		t.Errorf("refusal %q must say no gate authorized the request", out)
	}
}

func TestGatedMCPToolRefusesAnOutOfScopeHost(t *testing.T) {
	inner := &recordingMCPTool{name: "mcp__burp__send_http1_request", output: "sent"}
	tool, ok := newGatedMCPTool(inner, "burp", "send_http1_request", autoGate(t), false)
	if !ok {
		t.Fatal("a request tool with a gate must be registered")
	}
	out, err := tool.Call(context.Background(),
		engageMCPRequestArgs(`GET /a HTTP/1.1\r\nHost: x\r\n\r\n`, "8.8.8.8", 443, true))
	if err != nil {
		t.Fatal(err)
	}
	if inner.calls != 0 {
		t.Fatalf("an out-of-scope host reached the remote tool %d times", inner.calls)
	}
	if !strings.Contains(out, "denied by the security gate") || !strings.Contains(out, "out of scope") {
		t.Errorf("refusal %q must carry the gate's scope denial", out)
	}
}

func TestGatedMCPToolRefusesAStateChangingMethodOnAnUnarmedTask(t *testing.T) {
	inner := &recordingMCPTool{name: "mcp__burp__send_http1_request", output: "sent"}
	tool, ok := newGatedMCPTool(inner, "burp", "send_http1_request", webConfirmGate(t), false)
	if !ok {
		t.Fatal("a request tool with a gate must be registered")
	}
	out, err := tool.Call(context.Background(),
		engageMCPRequestArgs(`POST /login HTTP/1.1\r\nHost: x\r\n\r\n`, "10.0.0.5", 443, true))
	if err != nil {
		t.Fatal(err)
	}
	if inner.calls != 0 {
		t.Fatalf("an unarmed state-changing method reached the remote tool %d times", inner.calls)
	}
	if !strings.Contains(out, "denied by the security gate") || !strings.Contains(out, "requires an armed task") {
		t.Errorf("refusal %q must carry the gate's tier denial", out)
	}
}

func TestGatedMCPToolAllowsAReadMethodAtAnInScopeHost(t *testing.T) {
	inner := &recordingMCPTool{name: "mcp__burp__send_http1_request", output: "HTTP/1.1 200 OK"}
	tool, ok := newGatedMCPTool(inner, "burp", "send_http1_request", autoGate(t), false)
	if !ok {
		t.Fatal("a request tool with a gate must be registered")
	}
	args := engageMCPRequestArgs(`GET /a HTTP/1.1\r\nHost: x\r\n\r\n`, "10.0.0.5", 443, true)
	out, err := tool.Call(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	if inner.calls != 1 {
		t.Fatalf("remote tool calls = %d, want 1", inner.calls)
	}
	if inner.args != args {
		t.Errorf("remote tool saw %q, want the arguments unchanged: %q", inner.args, args)
	}
	if out != "HTTP/1.1 200 OK" {
		t.Errorf("output = %q, want the inner output unchanged", out)
	}
	if tool.Name() != inner.Name() || tool.Description() != inner.Description() {
		t.Error("the wrapper must present the inner tool's name and description")
	}
	if tool.Schema()["type"] != "object" {
		t.Errorf("the wrapper must present the inner tool's schema, got %v", tool.Schema())
	}
}

func TestGatedMCPToolDeniesAnInstrumentStateTool(t *testing.T) {
	inner := &recordingMCPTool{name: "mcp__burp__set_proxy_intercept_state", output: "off"}
	if tool, ok := newGatedMCPTool(inner, "burp", "set_proxy_intercept_state", autoGate(t), true); ok || tool != nil {
		t.Fatalf("an instrument-state tool must not be registered, got tool=%v ok=%v", tool, ok)
	}
	// The refusal is in Call as well, so a registration site cannot hand the
	// model a denied tool. The nil gate proves no gate was consulted: consulting
	// it would panic.
	tool := gatedMCPTool{inner: inner, server: "burp", remote: "set_proxy_intercept_state"}
	out, err := tool.Call(context.Background(), `{"intercept":false}`)
	if err != nil {
		t.Fatal(err)
	}
	if inner.calls != 0 {
		t.Fatalf("a denied tool reached the remote tool %d times", inner.calls)
	}
	if !strings.Contains(out, "set_proxy_intercept_state") {
		t.Errorf("refusal %q must name the tool", out)
	}
}

func TestGatedMCPToolPassesAReadToolThroughUngated(t *testing.T) {
	inner := &recordingMCPTool{name: "mcp__burp__get_proxy_http_history", output: "history rows"}
	// The nil gate proves the read path consults no gate: consulting it would
	// panic.
	tool, ok := newGatedMCPTool(inner, "burp", "get_proxy_http_history", nil, false)
	if !ok {
		t.Fatal("a read tool must be registered without a gate")
	}
	out, err := tool.Call(context.Background(), `{"count":10}`)
	if err != nil {
		t.Fatal(err)
	}
	if inner.calls != 1 {
		t.Fatalf("remote tool calls = %d, want 1", inner.calls)
	}
	if out != "history rows" {
		t.Errorf("output = %q, want the inner output unchanged", out)
	}
}

func TestNewGatedMCPToolRefusesToWrapARequestToolWithNoGate(t *testing.T) {
	inner := &recordingMCPTool{name: "mcp__burp__send_http1_request", output: "sent"}
	for _, remote := range []string{"send_http1_request", "send_http2_request", "send_to_intruder"} {
		tool, ok := newGatedMCPTool(inner, "burp", remote, nil, true)
		if ok || tool != nil {
			t.Errorf("newGatedMCPTool(%q, nil gate) = (%v, %v), want (nil, false)", remote, tool, ok)
		}
	}
}
