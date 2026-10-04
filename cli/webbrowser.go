package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"blkchain/cli/internal/engagement"
)

// webbrowser.go defines the browser and API actions offered to web-surface
// engagement tasks. Each action passes through secgate before the Playwright
// driver runs, and returned page content is marked untrusted.

// webBrowserOp is a browser action class. navigate is passive (load a page, read
// the DOM); inject and submit are active and state-changing (inject into the DOM
// or submit a form), so they are exploit-phase and require an armed task.
type webBrowserOp string

const (
	webBrowserNavigate webBrowserOp = "navigate"
	webBrowserInject   webBrowserOp = "inject"
	webBrowserSubmit   webBrowserOp = "submit"
)

// valid reports whether op is a known browser action.
func (op webBrowserOp) valid() bool {
	switch op {
	case webBrowserNavigate, webBrowserInject, webBrowserSubmit:
		return true
	}
	return false
}

// active reports whether op injects or changes state (vs. a passive page load).
func (op webBrowserOp) active() bool {
	return op == webBrowserInject || op == webBrowserSubmit
}

// webPhase maps the op to the engagement phase the gate tiers it by: an active
// op is exploit (requires an armed task), a passive op is recon. An unknown op
// fails safe to exploit (the stricter tier); callers validate with valid()
// first, so this only governs the fail-safe default.
func (op webBrowserOp) webPhase() engagement.Phase {
	if op == webBrowserNavigate {
		return engagement.PhaseRecon
	}
	return engagement.PhaseExploit
}

// webBrowserAction is one parsed, validated browser action: a known op, an
// http/https URL, and operation-specific injection or form data.
type webBrowserAction struct {
	Op           webBrowserOp
	URL          string
	Payload      string
	FormSelector string
	Fields       map[string]string
	parsed       *url.URL
}

// webBrowserArgs is the tool's JSON argument shape.
type webBrowserArgs struct {
	Op           string            `json:"op" desc:"the browser action: navigate (passive page load), inject (active DOM injection), or submit (active form submit)"`
	URL          string            `json:"url" desc:"the absolute http/https target URL to act on; its host must be in scope"`
	Payload      string            `json:"payload,omitempty" desc:"for inject, the DOM/script payload"`
	FormSelector string            `json:"form_selector,omitempty" desc:"for submit, CSS selector for the form element"`
	Fields       map[string]string `json:"fields,omitempty" desc:"for submit, map of CSS selectors for form controls to values"`
}

// webParseBrowserAction parses and validates the tool arguments. It fails closed:
// the op must be a known action and the URL must be an absolute http or https URL
// with a host. It never performs any action.
func webParseBrowserAction(argsJSON string) (webBrowserAction, error) {
	if len(argsJSON) > webMaxActionArgsBytes {
		return webBrowserAction{}, errors.New("arguments exceed the size limit")
	}
	var a webBrowserArgs
	if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
		return webBrowserAction{}, fmt.Errorf("invalid arguments: %w", err)
	}
	op := webBrowserOp(strings.TrimSpace(strings.ToLower(a.Op)))
	if !op.valid() {
		return webBrowserAction{}, fmt.Errorf("unknown browser op %q (want navigate, inject, or submit)", a.Op)
	}
	raw := strings.TrimSpace(a.URL)
	if raw == "" {
		return webBrowserAction{}, errors.New("url is required")
	}
	if len(raw) > webMaxURLBytes || len(a.Payload) > webMaxRequestBodyBytes {
		return webBrowserAction{}, errors.New("url or payload exceeds the size limit")
	}
	switch op {
	case webBrowserNavigate:
		if a.Payload != "" || a.FormSelector != "" || len(a.Fields) > 0 {
			return webBrowserAction{}, errors.New("navigate does not accept a payload or form fields")
		}
	case webBrowserInject:
		if strings.TrimSpace(a.Payload) == "" || a.FormSelector != "" || len(a.Fields) > 0 {
			return webBrowserAction{}, errors.New("inject requires a payload and does not accept form fields")
		}
	case webBrowserSubmit:
		if strings.TrimSpace(a.FormSelector) == "" || len(a.FormSelector) > 1024 || len(a.Fields) > 50 || a.Payload != "" {
			return webBrowserAction{}, errors.New("submit requires a form selector and at most 50 field values")
		}
		total := len(a.FormSelector)
		for selector, value := range a.Fields {
			if strings.TrimSpace(selector) == "" || len(selector) > 1024 || len(value) > 16<<10 {
				return webBrowserAction{}, errors.New("form selector or field value exceeds the size limit")
			}
			total += len(selector) + len(value)
		}
		if total > 64<<10 {
			return webBrowserAction{}, errors.New("form data exceeds the size limit")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return webBrowserAction{}, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return webBrowserAction{}, fmt.Errorf("url scheme %q not allowed (want http or https)", u.Scheme)
	}
	if u.Hostname() == "" {
		return webBrowserAction{}, errors.New("url has no host")
	}
	if u.User != nil {
		return webBrowserAction{}, errors.New("url user information is not allowed")
	}
	return webBrowserAction{Op: op, URL: raw, Payload: a.Payload, FormSelector: a.FormSelector, Fields: a.Fields, parsed: u}, nil
}

// host returns the target host for the gate's scope check: the URL hostname with
// no userinfo and no port.
func (a webBrowserAction) host() string {
	if a.parsed != nil {
		return a.parsed.Hostname()
	}
	if u, err := url.Parse(a.URL); err == nil {
		return u.Hostname()
	}
	return ""
}

// webUntrustedTag wraps driver output as untrusted web content before it reaches
// the model. Live page content is attacker-controlled; this mirrors the
// untrusted posture web corpus results get in the answer prompt.
func webUntrustedTag(out string) string {
	return "Browser result (untrusted web content):\n" + out
}

// webAPIRequest is one parsed, validated API request: a known HTTP method, an
// http/https URL, an optional body, and optional header lines ("Name: value").
type webAPIRequest struct {
	Method  string
	URL     string
	Body    string
	Headers []string
	parsed  *url.URL
}

const (
	webMaxActionArgsBytes  = 1 << 20
	webMaxRequestBodyBytes = 1 << 20
	webMaxHeaderLines      = 32
	webMaxHeaderLineBytes  = 8 << 10
	webMaxURLBytes         = 8 << 10
)

// webAPIArgs is the API tool's JSON argument shape.
type webAPIArgs struct {
	Method  string   `json:"method" desc:"the HTTP method: GET/HEAD/OPTIONS are read-only (recon); POST/PUT/PATCH/DELETE change state (exploit, require an armed task)"`
	URL     string   `json:"url" desc:"the absolute http/https request URL; its host must be in scope"`
	Body    string   `json:"body,omitempty" desc:"optional request body"`
	Headers []string `json:"headers,omitempty" desc:"optional request headers, each as 'Name: value'"`
}

// webAPIMethods is the set of HTTP methods the API tool accepts.
var webAPIMethods = map[string]bool{
	"GET": true, "HEAD": true, "OPTIONS": true,
	"POST": true, "PUT": true, "PATCH": true, "DELETE": true,
}

// webParseAPIRequest parses and validates the API tool arguments. It fails closed:
// the method must be a known HTTP method and the URL must be an absolute http or
// https URL with a host. It performs no request.
func webParseAPIRequest(argsJSON string) (webAPIRequest, error) {
	if len(argsJSON) > webMaxActionArgsBytes {
		return webAPIRequest{}, errors.New("arguments exceed the size limit")
	}
	var a webAPIArgs
	if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
		return webAPIRequest{}, fmt.Errorf("invalid arguments: %w", err)
	}
	method := strings.TrimSpace(strings.ToUpper(a.Method))
	if !webAPIMethods[method] {
		return webAPIRequest{}, fmt.Errorf("unknown or unsupported HTTP method %q", a.Method)
	}
	raw := strings.TrimSpace(a.URL)
	if raw == "" {
		return webAPIRequest{}, errors.New("url is required")
	}
	if len(raw) > webMaxURLBytes || len(a.Body) > webMaxRequestBodyBytes || len(a.Headers) > webMaxHeaderLines {
		return webAPIRequest{}, errors.New("url, body, or headers exceed the size limit")
	}
	for _, line := range a.Headers {
		if len(line) > webMaxHeaderLineBytes || strings.ContainsAny(line, "\r\n") {
			return webAPIRequest{}, errors.New("header line exceeds the size limit or contains a line break")
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			return webAPIRequest{}, errors.New("header line has an invalid name")
		}
		name := http.CanonicalHeaderKey(strings.TrimSpace(line[:i]))
		if name == "" {
			return webAPIRequest{}, errors.New("header line has an invalid name")
		}
		switch strings.ToLower(name) {
		case "host", "content-length", "transfer-encoding", "connection", "proxy-connection", "upgrade":
			return webAPIRequest{}, errors.New("header is controlled by the HTTP client")
		}
	}
	if !apiMethodActive(method) && a.Body != "" {
		return webAPIRequest{}, errors.New("read-only methods do not accept a request body")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return webAPIRequest{}, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return webAPIRequest{}, fmt.Errorf("url scheme %q not allowed (want http or https)", u.Scheme)
	}
	if u.Hostname() == "" {
		return webAPIRequest{}, errors.New("url has no host")
	}
	if u.User != nil {
		return webAPIRequest{}, errors.New("url user information is not allowed")
	}
	return webAPIRequest{Method: method, URL: raw, Body: a.Body, Headers: a.Headers, parsed: u}, nil
}

// host returns the target host for the gate's scope check (no userinfo, no port).
func (r webAPIRequest) host() string {
	if r.parsed != nil {
		return r.parsed.Hostname()
	}
	if u, err := url.Parse(r.URL); err == nil {
		return u.Hostname()
	}
	return ""
}

func webSameOrigin(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

func webClearHeaders(headers map[string]string) {
	clear(headers)
}

// webRedirectAuthorizer re-validates a redirect hop by its Location URL/host; the
// driver MUST call it for every redirect hop and abort the navigation/request
// when it returns false. It is wired to Gate.AuthorizeWebRedirect so a 30x cannot
// carry the client to an out-of-scope or internal host.
type webRedirectAuthorizer func(location string) bool

// webDriver performs an already-authorized web action against a live target and
// returns the observed result. It is the seam the real (Playwright-backed) driver
// fills; the gate decides whether an action may run before the driver is ever
// called, and the driver re-checks every redirect hop through redirectOK. One
// driver covers both browser automation and API testing (Playwright does both).
type webDriver interface {
	DoBrowser(ctx context.Context, act webBrowserAction, redirectOK webRedirectAuthorizer) (string, error)
	DoAPIRequest(ctx context.Context, req webAPIRequest, redirectOK webRedirectAuthorizer) (string, error)
}

// errWebDriverUnavailable is the fail-closed error the live driver returns when
// the pinned, checksum-verified, operator-provisioned Playwright artifacts (wired
// via the PLAYWRIGHT_* paths) are absent or fail verification. There is no stub or
// inert driver in production: the shipped webDriver is the real Playwright-backed
// adapter (webplaywright.go), and it fails closed with this error rather than
// driving a target with an unverified driver.
var errWebDriverUnavailable = errors.New("web driver not available: no verified, provisioned Playwright driver is configured")
