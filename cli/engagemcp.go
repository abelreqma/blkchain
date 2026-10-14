package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"
)

// engagemcp.go authorizes an outbound MCP tool for the engagement harness.
//
// chatMCPTool bounds its arguments, its output and its deadline and wraps its
// result as untrusted, and it applies no authorization gate: the allowlist in
// mcp-clients.json is the whole boundary. That holds on the chat path, where an
// operator drives each turn and sees each call. An engagement task runs without
// per-action attention, so a tool that reaches a host goes through the same gate
// as every other engagement action: scope, phase tier, confirmation, recheck,
// rate and audit.
//
// Nothing here changes the chat path. gatedMCPTool wraps a chat MCP tool and
// adds the gate beside it.

// engageMCPAction says what the engagement harness may do with one outbound MCP
// tool.
//
// The zero value denies. A tool this code does not classify, and every tool of a
// server it does not classify, is refused in an engagement: an autonomous task
// inherits only what has been reasoned about, not whatever the operator wired
// for interactive use.
type engageMCPAction int

const (
	engageMCPDenied engageMCPAction = iota
	engageMCPPure
	engageMCPRead
	engageMCPRequest
)

// engageMCPActions classifies each outbound MCP tool, keyed server then tool. A
// miss on either key yields the zero value, which denies.
var engageMCPActions = map[string]map[string]engageMCPAction{
	"burp": {
		// Sends a request at a host, so it goes through the gate.
		"send_http1_request": engageMCPRequest,
		"send_http2_request": engageMCPRequest,
		"send_to_intruder":   engageMCPRequest,

		// Reads the instrument's own state and sends nothing.
		"get_proxy_http_history":            engageMCPRead,
		"get_proxy_http_history_regex":      engageMCPRead,
		"get_proxy_websocket_history":       engageMCPRead,
		"get_proxy_websocket_history_regex": engageMCPRead,
		"get_organizer_items":               engageMCPRead,
		"get_organizer_items_regex":         engageMCPRead,
		"get_scanner_issues":                engageMCPRead,
		"get_active_editor_contents":        engageMCPRead,
		"get_collaborator_interactions":     engageMCPRead,
		"output_project_options":            engageMCPRead,
		"output_user_options":               engageMCPRead,

		// Transforms its arguments and reaches nothing.
		// generate_collaborator_payload allocates on Collaborator infrastructure
		// through the operator's own Burp, the same shape as registering an
		// interactsh payload, and touches no engagement target.
		"base64_encode":                 engageMCPPure,
		"base64_decode":                 engageMCPPure,
		"url_encode":                    engageMCPPure,
		"url_decode":                    engageMCPPure,
		"generate_random_string":        engageMCPPure,
		"generate_collaborator_payload": engageMCPPure,

		// Changes the operator's instrument rather than touching a target, and
		// none of it is evidence about a target. create_repeater_tab and its
		// HTTP/2 variant take the same four arguments as the send tools and do
		// not send: they leave a staged request in the operator's Repeater.
		"create_repeater_tab":             engageMCPDenied,
		"create_repeater_tab_http2":       engageMCPDenied,
		"set_active_editor_contents":      engageMCPDenied,
		"set_project_options":             engageMCPDenied,
		"set_proxy_intercept_state":       engageMCPDenied,
		"set_task_execution_engine_state": engageMCPDenied,
		"set_user_options":                engageMCPDenied,
	},
}

// engageMCPClassify returns what the engagement harness may do with one remote
// tool of one MCP server. An unclassified server or tool returns
// engageMCPDenied.
func engageMCPClassify(server, tool string) engageMCPAction {
	return engageMCPActions[server][tool]
}

// engageMCPRequestTarget is the method and absolute URL one request tool's
// arguments resolve to, as the gate reads them.
type engageMCPRequestTarget struct {
	Method, URL string
}

var (
	errEngageMCPArgs    = errors.New("invalid arguments")
	errEngageMCPHost    = errors.New("targetHostname must be a hostname or IP address")
	errEngageMCPPort    = errors.New("targetPort must be between 1 and 65535")
	errEngageMCPContent = errors.New("content must be a string holding the raw request")
)

// engageMCPMethodPattern bounds the request-line token read as a method: HTTP
// methods are letter tokens, and the token becomes part of the gate's audit
// label, so an arbitrary run of bytes is not carried into it.
var engageMCPMethodPattern = regexp.MustCompile(`^[A-Za-z]{1,24}$`)

const (
	// engageMCPUnparsedMethod is the method reported when content has no
	// readable request line. content is model-authored, so treating a line the
	// parser cannot read as recon would let a malformed first line buy a lower
	// tier. apiMethodActive already tiers every method outside GET, HEAD and
	// OPTIONS as active, so this sentinel inherits the fail-safe direction
	// instead of restating it.
	engageMCPUnparsedMethod = "UNPARSED"

	// engageMCPIntruderMethod is the method reported for send_to_intruder
	// whatever its request line says, because Intruder is a fuzzer. It is a
	// sentinel the gate reads as active, not a substituted HTTP verb: the gate's
	// label becomes web-api:INTRUDER, which states in the audit record what was
	// dispatched rather than attributing a verb the dispatch does not keep.
	engageMCPIntruderMethod = "INTRUDER"
)

// engageMCPMethod reads the method from the first whitespace-delimited token of
// a raw HTTP request, returning engageMCPUnparsedMethod when there is no
// readable token.
func engageMCPMethod(content string) string {
	line := strings.TrimLeft(content, " \t\r\n")
	if i := strings.IndexAny(line, " \t\r\n"); i >= 0 {
		line = line[:i]
	}
	if !engageMCPMethodPattern.MatchString(line) {
		return engageMCPUnparsedMethod
	}
	return strings.ToUpper(line)
}

// engageMCPTargetFromArgs resolves one request tool's arguments to the method
// and URL the gate authorizes.
//
// The URL is built from targetHostname and targetPort, not from the request's
// own Host header: the connection target is what the packet reaches, so that is
// what scope is checked against. A request whose Host header disagrees is still
// scoped on the connection target.
func engageMCPTargetFromArgs(tool, args string) (engageMCPRequestTarget, error) {
	// The same bound chatMCPTool.Call applies to the arguments, ahead of the
	// decode this wrapper adds.
	if len(args) > chatMCPCallMaxBytes {
		return engageMCPRequestTarget{}, errEngageMCPArgs
	}
	var values map[string]any
	if err := json.Unmarshal([]byte(args), &values); err != nil {
		return engageMCPRequestTarget{}, errEngageMCPArgs
	}
	host, ok := values["targetHostname"].(string)
	if !ok || host == "" {
		return engageMCPRequestTarget{}, errEngageMCPHost
	}
	port, ok := values["targetPort"].(float64)
	if !ok || port != float64(int(port)) || port < 1 || port > 65535 {
		return engageMCPRequestTarget{}, errEngageMCPPort
	}
	content, ok := values["content"].(string)
	if !ok {
		return engageMCPRequestTarget{}, errEngageMCPContent
	}
	scheme := "http"
	if https, ok := values["usesHttps"].(bool); ok && https {
		scheme = "https"
	}
	raw := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(int(port)))
	// The host is model-authored, so confirm the URL the gate scope-checks has
	// the host and port given and nothing else: a host carrying a path, userinfo
	// or a second authority would otherwise move the authority the gate reads.
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Path != "" ||
		!strings.EqualFold(parsed.Hostname(), strings.Trim(host, "[]")) ||
		parsed.Port() != strconv.Itoa(int(port)) {
		return engageMCPRequestTarget{}, errEngageMCPHost
	}
	method := engageMCPMethod(content)
	if tool == "send_to_intruder" {
		method = engageMCPIntruderMethod
	}
	return engageMCPRequestTarget{Method: method, URL: raw}, nil
}

// gatedMCPTool wraps one outbound MCP tool for the engagement harness. It
// presents the inner tool's name, description and schema unchanged, and
// dispatches Call on the tool's classification.
type gatedMCPTool struct {
	inner          tooldef.Tool
	server, remote string
	gate           *secgate.Gate
	armed          bool
}

func (t gatedMCPTool) Name() string           { return t.inner.Name() }
func (t gatedMCPTool) Description() string    { return t.inner.Description() }
func (t gatedMCPTool) Schema() map[string]any { return t.inner.Schema() }

// Call authorizes the tool for the engagement and reaches the inner tool only on
// an allow. A denial's text is what the model sees.
func (t gatedMCPTool) Call(ctx context.Context, args string) (string, error) {
	switch engageMCPClassify(t.server, t.remote) {
	case engageMCPPure, engageMCPRead:
		return t.inner.Call(ctx, args)
	case engageMCPRequest:
		target, err := engageMCPTargetFromArgs(t.remote, args)
		if err != nil {
			return t.Name() + ": " + err.Error(), nil
		}
		decision := t.gate.AuthorizeAPIRequest(ctx, secgate.APIRequest{
			Method: target.Method,
			URL:    target.URL,
			Armed:  t.armed,
		})
		if !decision.Allowed {
			return t.Name() + ": denied by the security gate: " + decision.Reason, nil
		}
		return t.inner.Call(ctx, args)
	}
	return t.Name() + ": " + t.server + "/" + t.remote + " is not available in an engagement", nil
}

// newGatedMCPTool wraps one outbound MCP tool for an engagement executor,
// reporting false for a tool it will not register: a tool the classifier denies,
// and a request tool with no gate to authorize it.
func newGatedMCPTool(inner tooldef.Tool, server, remote string, gate *secgate.Gate, armed bool) (tooldef.Tool, bool) {
	action := engageMCPClassify(server, remote)
	if action == engageMCPDenied || (action == engageMCPRequest && gate == nil) {
		return nil, false
	}
	return gatedMCPTool{inner: inner, server: server, remote: remote, gate: gate, armed: armed}, true
}
