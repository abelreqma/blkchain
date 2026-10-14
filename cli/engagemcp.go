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

		// Reads the instrument's own state and sends nothing at a target.
		// get_collaborator_interactions does cause outbound traffic, because Burp
		// polls its Collaborator server to answer it; the destination is not
		// caller-controlled, so it is in the same class as the interactsh server.
		//
		// A read is not filtered by engagement scope. The proxy-history tools
		// return the whole Burp project's history, which can hold the operator's
		// own browsing and another engagement's traffic, credentials in headers
		// included, and get_active_editor_contents returns whatever request is
		// open in the instrument. Denying the two output_* tools below removes the
		// configuration dump, not this exposure.
		"get_proxy_http_history":            engageMCPRead,
		"get_proxy_http_history_regex":      engageMCPRead,
		"get_proxy_websocket_history":       engageMCPRead,
		"get_proxy_websocket_history_regex": engageMCPRead,
		"get_organizer_items":               engageMCPRead,
		"get_organizer_items_regex":         engageMCPRead,
		"get_scanner_issues":                engageMCPRead,
		"get_active_editor_contents":        engageMCPRead,
		"get_collaborator_interactions":     engageMCPRead,

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
		//
		// output_project_options and output_user_options are denied for a
		// different reason: they dump configuration that can carry upstream-proxy
		// credentials, platform-authentication credentials and API keys. On the
		// chat path, which keeps them, an operator sees the call and decides. A
		// task runs without that attention and its output reaches the engagement
		// transcript, so an ungated read there writes the operator's own
		// credentials into a record of an engagement against someone else's
		// estate. Proxy history is readable without them.
		"create_repeater_tab":             engageMCPDenied,
		"create_repeater_tab_http2":       engageMCPDenied,
		"set_active_editor_contents":      engageMCPDenied,
		"set_project_options":             engageMCPDenied,
		"set_proxy_intercept_state":       engageMCPDenied,
		"set_task_execution_engine_state": engageMCPDenied,
		"set_user_options":                engageMCPDenied,
		"output_project_options":          engageMCPDenied,
		"output_user_options":             engageMCPDenied,
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
	errEngageMCPArgs = errors.New("invalid arguments")
	errEngageMCPHost = errors.New("targetHostname must be an IP address or a hostname of at most " +
		strconv.Itoa(engageMCPHostMaxBytes) + " bytes of letters, digits, dots and hyphens")
	errEngageMCPPort          = errors.New("targetPort must be between 1 and 65535")
	errEngageMCPContent       = errors.New("content must be a string holding the raw request")
	errEngageMCPHTTP2Content  = errors.New("send_http2_request takes its request line as pseudoHeaders, not content")
	errEngageMCPPseudoHeaders = errors.New("pseudoHeaders must be an object whose :method and :path are strings")
	errEngageMCPPivotedWeb    = errors.New("a foothold carries the web surface and this tool sends from this host, not through the foothold; use the web tools")
)

const (
	// engageMCPHostMaxBytes is the length bound on targetHostname, the longest a
	// DNS name can be. The host reaches the gate's scope check, its confirmation
	// prompt and its audit record, and the argument is model-authored, so an
	// unbounded run of bytes is not carried into any of them.
	engageMCPHostMaxBytes = 253

	// engageMCPRequestTargetMaxBytes is the length bound on the request target
	// carried out of content, for the same reason. A longer target contributes no
	// path rather than a truncated one, so the URL the gate authorizes is never a
	// prefix of the path the request carries.
	engageMCPRequestTargetMaxBytes = 2048
)

var (
	// engageMCPHostPattern bounds a hostname to the bytes a DNS name is made of.
	// secgate's own URL pattern ends its match at a quote while Go's host grammar
	// permits one, so an unvalidated host lets the gate scope-check a prefix of
	// what the argument named.
	engageMCPHostPattern = regexp.MustCompile(`^[A-Za-z0-9.-]{1,` + strconv.Itoa(engageMCPHostMaxBytes) + `}$`)

	// engageMCPOriginFormPattern matches an origin-form request target: a target
	// that starts at the root and carries only bytes a URL may hold past the
	// authority. Comma, quote and apostrophe are outside the set because
	// secgate's URL pattern ends its match at each of them.
	engageMCPOriginFormPattern = regexp.MustCompile(`^/[A-Za-z0-9._~%!$&()*+;:=@/?-]*$`)

	// engageMCPMethodPattern bounds the request-line token read as a method: HTTP
	// methods are letter tokens, and the token becomes part of the gate's audit
	// label, so an arbitrary run of bytes is not carried into it. The sentinels
	// below carry a hyphen, which this pattern cannot match, so no content can
	// produce one.
	engageMCPMethodPattern = regexp.MustCompile(`^[A-Za-z]{1,24}$`)
)

const (
	// engageMCPUnparsedMethod is the method reported when content has no
	// readable request line. content is model-authored, so treating a line the
	// parser cannot read as recon would let a malformed first line buy a lower
	// tier. apiMethodActive already tiers every method outside GET, HEAD and
	// OPTIONS as active, so this sentinel inherits the fail-safe direction
	// instead of restating it.
	engageMCPUnparsedMethod = "NO-REQUEST-LINE"

	// engageMCPIntruderMethod is the method reported for send_to_intruder
	// whatever its request line says, because Intruder is a fuzzer. It is a
	// sentinel the gate reads as active, not a substituted HTTP verb: the gate's
	// label becomes web-api:INTRUDER-FUZZ, which states in the audit record what
	// was dispatched rather than attributing a verb the dispatch does not keep.
	// Its hyphen is what keeps the label a statement: a content cannot forge it
	// through engageMCPMethodPattern, so an approval of a send tool is not
	// replayable as an approval of Intruder at the same authority.
	engageMCPIntruderMethod = "INTRUDER-FUZZ"
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

// engageMCPRequestPath returns the origin-form request target of a raw HTTP
// request, or the empty string when the request line carries none.
//
// The path is what makes a confirmation specific: with the authority alone the
// prompt reads web-api:POST https://10.0.0.5:443, and one approval covers every
// path and every body for that method class at that authority for the session.
// The native web_api tool passes a full URL, so carrying the path also keeps the
// two comparable in the audit.
//
// The authority still comes from the arguments, because that is what the packet
// reaches. A target that does not start at the root, which is every absolute-form
// and authority-form target, contributes no path rather than overriding the
// authority. A target holding "//" contributes none either: both net/url and
// secgate's URL pattern would read what follows as a second authority.
func engageMCPRequestPath(content string) string {
	line := strings.TrimLeft(content, " \t\r\n")
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	return engageMCPOriginForm(fields[1])
}

// engageMCPOriginForm returns target when it is an origin-form request target
// within the length bound, or the empty string.
func engageMCPOriginForm(target string) string {
	if len(target) > engageMCPRequestTargetMaxBytes || strings.Contains(target, "//") ||
		!engageMCPOriginFormPattern.MatchString(target) {
		return ""
	}
	return target
}

// engageMCPTargetFromArgs resolves one request tool's arguments to the method
// and URL the gate authorizes.
//
// The authority is built from targetHostname and targetPort, not from the
// request's own Host header: the connection target is what the packet reaches,
// so that is what scope is checked against. A request whose Host header
// disagrees is still scoped on the connection target.
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
	if !ok || (net.ParseIP(host) == nil && !engageMCPHostPattern.MatchString(host)) {
		return engageMCPRequestTarget{}, errEngageMCPHost
	}
	// The range check precedes the integrality check, and so precedes every
	// conversion to int: a JSON body can carry 1e30, and converting a float64
	// outside the int range to int is undefined in Go.
	port, ok := values["targetPort"].(float64)
	if !ok || port < 1 || port > 65535 || port != float64(int(port)) {
		return engageMCPRequestTarget{}, errEngageMCPPort
	}
	method, path, err := engageMCPRequestLine(tool, values)
	if err != nil {
		return engageMCPRequestTarget{}, err
	}
	scheme := "http"
	if https, ok := values["usesHttps"].(bool); ok && https {
		scheme = "https"
	}
	raw := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(int(port))) + path
	// The host and the path are both model-authored, so confirm the URL the gate
	// scope-checks reads back as the authority the arguments named. A userinfo
	// form in the host moves the authority net/url reads to what follows the '@';
	// a path in the host narrows it to the prefix before the '/'; a second
	// authority in the path replaces it outright.
	//
	// It is a belt: no host the check above accepts can produce any of those
	// forms, because a net.ParseIP value and an engageMCPHostPattern match both
	// exclude '@' and '/', and engageMCPRequestPath contributes no path unless it
	// is origin form without "//". The readback stays so that loosening either
	// check cannot move the authority without failing here.
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil ||
		!strings.EqualFold(parsed.Hostname(), host) ||
		parsed.Port() != strconv.Itoa(int(port)) {
		return engageMCPRequestTarget{}, errEngageMCPHost
	}
	if tool == "send_to_intruder" {
		method = engageMCPIntruderMethod
	}
	return engageMCPRequestTarget{Method: method, URL: raw}, nil
}

// engageMCPRequestLine reads the method and origin-form path one request tool
// will send. send_http1_request and send_to_intruder carry a raw request in
// content. send_http2_request carries the request line as pseudoHeaders and its
// schema has no content, so a content field there is refused: the gate would
// tier the call on it while Burp sent the pseudo-headers.
func engageMCPRequestLine(tool string, values map[string]any) (method, path string, err error) {
	if tool != "send_http2_request" {
		content, ok := values["content"].(string)
		if !ok {
			return "", "", errEngageMCPContent
		}
		return engageMCPMethod(content), engageMCPRequestPath(content), nil
	}
	if _, ok := values["content"]; ok {
		return "", "", errEngageMCPHTTP2Content
	}
	pseudo, ok := values["pseudoHeaders"].(map[string]any)
	if !ok {
		return "", "", errEngageMCPPseudoHeaders
	}
	method, path = engageMCPUnparsedMethod, ""
	if raw, present := pseudo[":method"]; present {
		value, ok := raw.(string)
		if !ok {
			return "", "", errEngageMCPPseudoHeaders
		}
		if engageMCPMethodPattern.MatchString(value) {
			method = strings.ToUpper(value)
		}
	}
	if raw, present := pseudo[":path"]; present {
		value, ok := raw.(string)
		if !ok {
			return "", "", errEngageMCPPseudoHeaders
		}
		path = engageMCPOriginForm(value)
	}
	return method, path, nil
}

// gatedMCPTool wraps one outbound MCP tool for the engagement harness. It
// presents the inner tool's name, description and schema unchanged, and
// dispatches Call on the tool's classification.
type gatedMCPTool struct {
	inner          tooldef.Tool
	server, remote string
	gate           *secgate.Gate
	// armed is the task's arm state when the tool set was built. Nothing clears
	// Armed on a running task, and exploit.go arms before the registry exists, so
	// the live form buys nothing here: webtool.go's func() bool closes over a
	// by-value copy of the task and is a snapshot too.
	armed bool
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
		// newGatedMCPTool registers no request tool without a gate, and the type
		// is constructible by literal anywhere in the package, so the refusal
		// stands here too rather than in the one constructor.
		if t.gate == nil {
			return t.Name() + ": no engagement gate to authorize a request", nil
		}
		// The instrument sends from this host. While a foothold carries the web
		// surface the gate authorizes against the pivot scope, whose private
		// networks are reached through the foothold, so an allow here would send
		// to the same addresses on this host's own networks. newWebBroker refuses
		// the upstream proxy on that surface for the same reason. The foothold is
		// read per call because one can be attached while the task runs.
		if t.gate.EffectiveFoothold().Covers(secgate.SurfaceWeb) {
			return t.Name() + ": " + errEngageMCPPivotedWeb.Error(), nil
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
