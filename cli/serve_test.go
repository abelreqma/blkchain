package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"blkchain/cli/internal/ragconfig"
)

// serve_test.go covers blk serve's exposure decision, the optional bearer
// token, the three defenses that close the API against the browser, the body
// bound, and /health. No turn runs here: the guard chain wraps a stub handler,
// so a request reaching the stub is admission and nothing more.

// The two token strings these tests use. They are distinctive, so searching a
// response body or a header for either one is conclusive.
const (
	serveTestToken      = "serve-test-token-configured"
	serveTestWrongToken = "serve-test-token-presented"
)

// serveStub is the handler the guard chain wraps. ran is atomic because the
// handler runs on the server's goroutine and the assertion runs on the test's.
type serveStub struct{ ran atomic.Bool }

func (h *serveStub) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.ran.Store(true)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"admitted":true}`))
}

// newServeTestServer builds a server value without a retrieval client, which
// the guard chain does not touch.
func newServeTestServer(t *testing.T, o serveOpts, tok string) *serveServer {
	t.Helper()
	if o.bind == "" {
		o.bind = serveDefaultBind
	}
	s, err := newServeServer(nil, ragconfig.Config{}, o, tok)
	if err != nil {
		t.Fatalf("newServeServer(%+v): %v", o, err)
	}
	return s
}

// serveChain starts a server whose guard chain wraps a stub handler.
func serveChain(t *testing.T, s *serveServer) (*httptest.Server, *serveStub) {
	t.Helper()
	stub := &serveStub{}
	srv := httptest.NewServer(s.guard(stub))
	t.Cleanup(srv.Close)
	return srv, stub
}

// serveSend performs one request and returns the response with its body read
// under a bound.
func serveSend(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, serveMaxBody))
	if err != nil {
		t.Fatalf("read %s %s: %v", req.Method, req.URL, err)
	}
	return resp, string(body)
}

// serveJSONPost builds a POST carrying a small JSON body, the shape every
// legitimate call to this API has.
func serveJSONPost(t *testing.T, base string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/v1/sessions", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

// serveFreePort returns a port nothing is listening on, so a later listen on it
// says whether something took it in between.
func serveFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestServeRefusesANonLoopbackBindWithoutTheFlag(t *testing.T) {
	t.Setenv(serveTokenEnv, "")
	port := serveFreePort(t)
	bind := "0.0.0.0:" + port

	err := runServe([]string{"--bind", bind})
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Fatalf("runServe --bind %s error = %#v, want a *usageError", bind, err)
	}
	if !strings.Contains(ue.Error(), "--allow-remote") {
		t.Errorf("usage error = %q, want it to name --allow-remote", ue.Error())
	}

	// The refusal happens before anything is opened, so the port is still free.
	// A listener on 0.0.0.0 would make this listen fail too.
	ln, lerr := net.Listen("tcp", "127.0.0.1:"+port)
	if lerr != nil {
		t.Fatalf("port %s is held after the refusal, so something was bound: %v", port, lerr)
	}
	ln.Close()
}

func TestServeRefusesANonLoopbackBindWithoutAToken(t *testing.T) {
	t.Setenv(serveTokenEnv, "")
	bind := "0.0.0.0:" + serveFreePort(t)

	err := runServe([]string{"--bind", bind, "--allow-remote"})
	if !errors.Is(err, errServeRemoteNeedsToken) {
		t.Fatalf("runServe --bind %s --allow-remote error = %#v, want %v", bind, err, errServeRemoteNeedsToken)
	}
	if !strings.Contains(err.Error(), serveTokenEnv) {
		t.Errorf("error = %q, want it to name %s", err, serveTokenEnv)
	}
}

func TestServeAcceptsLoopbackWithNoToken(t *testing.T) {
	for _, bind := range []string{serveDefaultBind, "127.0.0.1:0", "[::1]:8787", "localhost:8787"} {
		if err := serveBindCheck(bind, false, ""); err != nil {
			t.Errorf("serveBindCheck(%q, false, no token) = %v, want nil", bind, err)
		}
	}

	s := newServeTestServer(t, serveOpts{}, "")
	srv, stub := serveChain(t, s)
	resp, body := serveSend(t, serveJSONPost(t, srv.URL))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d; body %q", resp.StatusCode, http.StatusOK, body)
	}
	if !stub.ran.Load() {
		t.Error("a loopback request with no token did not reach the handler")
	}
}

func TestServeRequiresTheTokenWhenOneIsSet(t *testing.T) {
	// A token that is set is required on loopback too: an operator who sets one
	// wants authentication, and serving loopback unauthenticated while a token
	// exists would make the setting a no-op nobody notices.
	for _, tc := range []struct {
		name   string
		header string
		want   int
		admit  bool
	}{
		{"no authorization header", "", http.StatusUnauthorized, false},
		{"wrong token", "Bearer " + serveTestWrongToken, http.StatusUnauthorized, false},
		{"right token", "Bearer " + serveTestToken, http.StatusOK, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newServeTestServer(t, serveOpts{}, serveTestToken)
			srv, stub := serveChain(t, s)
			req := serveJSONPost(t, srv.URL)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			resp, body := serveSend(t, req)
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d; body %q", resp.StatusCode, tc.want, body)
			}
			if got := stub.ran.Load(); got != tc.admit {
				t.Errorf("handler ran = %v, want %v", got, tc.admit)
			}
		})
	}
}

// serveIsBasicLit reports whether an expression is a literal.
func serveIsBasicLit(e ast.Expr) bool {
	_, ok := e.(*ast.BasicLit)
	return ok
}

func TestServeComparesTheTokenInConstantTimeAndNeverEchoesIt(t *testing.T) {
	// Half one: the comparison goes through crypto/subtle. No response can show
	// the difference between a constant-time compare and ==, so the path itself
	// is pinned in the source, the way this package already pins the prompt
	// floor and the dispatch table.
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, 0)
	if err != nil {
		t.Fatalf("parse serve.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "requireBearerToken" {
			fn = fd
		}
	}
	if fn == nil {
		t.Fatal("requireBearerToken is not declared in serve.go")
	}
	// The constant-time call has to be what decides the refusal, so the
	// condition is what gets pinned. A call whose result is discarded satisfies
	// the call's presence while something else decides.
	constantTimeDecides := false
	ast.Inspect(fn, func(n ast.Node) bool {
		stmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		ast.Inspect(stmt.Cond, func(c ast.Node) bool {
			call, ok := c.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "subtle" && sel.Sel.Name == "ConstantTimeCompare" {
				constantTimeDecides = true
			}
			return true
		})
		return true
	})
	if !constantTimeDecides {
		t.Error("requireBearerToken does not refuse on the result of subtle.ConstantTimeCompare")
	}

	// No == or != in this function may compare two non-literal operands. Every
	// variable-time leak available here is one: `want != got` beside the
	// constant-time call, which Go short-circuits so the fast comparison
	// decides; a discarded call followed by `if want != got`; and
	// `presented != token` placed ahead of the block. Comparing against a
	// literal, as the configured-token check and the compare's own result do,
	// reveals nothing about either token's bytes.
	ast.Inspect(fn, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		if bin.Op != token.EQL && bin.Op != token.NEQ {
			return true
		}
		if serveIsBasicLit(bin.X) || serveIsBasicLit(bin.Y) {
			return true
		}
		t.Errorf("requireBearerToken decides a %s between two non-literal operands at %s, which runs in variable time",
			bin.Op, fset.Position(bin.OpPos))
		return true
	})

	// Half two: neither token reaches the caller, in the body or in any header.
	s := newServeTestServer(t, serveOpts{}, serveTestToken)
	srv, stub := serveChain(t, s)
	req := serveJSONPost(t, srv.URL)
	req.Header.Set("Authorization", "Bearer "+serveTestWrongToken)
	resp, body := serveSend(t, req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if stub.ran.Load() {
		t.Error("a wrong token reached the handler")
	}
	for _, secret := range []string{serveTestToken, serveTestWrongToken} {
		if strings.Contains(body, secret) {
			t.Errorf("the 401 body echoes the token: %q", body)
		}
		for name, values := range resp.Header {
			for _, v := range values {
				if strings.Contains(v, secret) {
					t.Errorf("header %s echoes the token: %q", name, v)
				}
			}
		}
	}
}

func TestServeRejectsABodyWithoutJSONContentType(t *testing.T) {
	// A cross-origin request carrying application/json is not a simple request,
	// so it needs a preflight this server never answers. Requiring the header
	// is what closes the API against a page the operator has open.
	for _, tc := range []struct {
		name        string
		contentType string
		want        int
		admit       bool
	}{
		{"text/plain", "text/plain", http.StatusUnsupportedMediaType, false},
		{"form encoded", "application/x-www-form-urlencoded", http.StatusUnsupportedMediaType, false},
		{"no content type", "", http.StatusUnsupportedMediaType, false},
		{"application/json", "application/json", http.StatusOK, true},
		{"application/json with a charset", "application/json; charset=utf-8", http.StatusOK, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newServeTestServer(t, serveOpts{}, "")
			srv, stub := serveChain(t, s)
			req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/sessions", strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Del("Content-Type")
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			resp, body := serveSend(t, req)
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d; body %q", resp.StatusCode, tc.want, body)
			}
			if got := stub.ran.Load(); got != tc.admit {
				t.Errorf("handler ran = %v, want %v", got, tc.admit)
			}
		})
	}

	// A request with no body carries no content type and is unaffected.
	s := newServeTestServer(t, serveOpts{}, "")
	srv, stub := serveChain(t, s)
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/sessions", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := serveSend(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("a GET with no body: status = %d, want %d; body %q", resp.StatusCode, http.StatusOK, body)
	}
	if !stub.ran.Load() {
		t.Error("a GET with no body did not reach the handler")
	}
}

func TestServeRejectsANonLoopbackHostHeader(t *testing.T) {
	// A name the operator's own resolver points at 127.0.0.1 still arrives with
	// its own Host, so refusing a Host that is not loopback defeats DNS
	// rebinding against this server.
	for _, tc := range []struct {
		host  string
		want  int
		admit bool
	}{
		{"evil.example", http.StatusMisdirectedRequest, false},
		{"evil.example:8787", http.StatusMisdirectedRequest, false},
		{"10.0.0.5:8787", http.StatusMisdirectedRequest, false},
		{"127.0.0.1:8787", http.StatusOK, true},
		{"[::1]:8787", http.StatusOK, true},
		{"localhost:8787", http.StatusOK, true},
	} {
		t.Run(tc.host, func(t *testing.T) {
			s := newServeTestServer(t, serveOpts{}, "")
			srv, stub := serveChain(t, s)
			req := serveJSONPost(t, srv.URL)
			req.Host = tc.host
			resp, body := serveSend(t, req)
			if resp.StatusCode != tc.want {
				t.Errorf("Host %q: status = %d, want %d; body %q", tc.host, resp.StatusCode, tc.want, body)
			}
			if got := stub.ran.Load(); got != tc.admit {
				t.Errorf("Host %q: handler ran = %v, want %v", tc.host, got, tc.admit)
			}
		})
	}
}

func TestServeKeysTheHostCheckOnTheBind(t *testing.T) {
	// The Host rule follows the bind the server opened. --allow-remote says
	// something about the bind, not about the Host: passed alongside a loopback
	// bind it leaves a loopback listener that a page the operator has open can
	// still reach, so the rebinding defense stays on there. The rule relaxes
	// for a wildcard bind alone, where a legitimate client's Host is not
	// predictable. A concrete bind that is not loopback is predictable, so a
	// request has to address it.
	//
	// Every case here passes --allow-remote, and a bind that is not loopback
	// also needs the token serveBindCheck requires of that mode.
	for _, tc := range []struct {
		name  string
		bind  string
		token string
		host  string
		want  int
		admit bool
	}{
		{"loopback bind refuses another Host", serveDefaultBind, "", "evil.example", http.StatusMisdirectedRequest, false},
		{"loopback bind admits loopback", serveDefaultBind, "", "127.0.0.1:8787", http.StatusOK, true},
		{"wildcard bind admits any Host", "0.0.0.0:8787", serveTestToken, "evil.example", http.StatusOK, true},
		{"wildcard v6 bind admits any Host", "[::]:8787", serveTestToken, "evil.example", http.StatusOK, true},
		{"bind with no host admits any Host", ":8787", serveTestToken, "evil.example", http.StatusOK, true},
		{"concrete remote bind admits the bind host", "10.0.0.5:8787", serveTestToken, "10.0.0.5:8787", http.StatusOK, true},
		{"concrete remote bind refuses another Host", "10.0.0.5:8787", serveTestToken, "evil.example", http.StatusMisdirectedRequest, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newServeTestServer(t, serveOpts{bind: tc.bind, allowRemote: true}, tc.token)
			srv, stub := serveChain(t, s)
			req := serveJSONPost(t, srv.URL)
			req.Host = tc.host
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			resp, body := serveSend(t, req)
			if resp.StatusCode != tc.want {
				t.Errorf("bind %q, Host %q: status = %d, want %d; body %q", tc.bind, tc.host, resp.StatusCode, tc.want, body)
			}
			if got := stub.ran.Load(); got != tc.admit {
				t.Errorf("bind %q, Host %q: handler ran = %v, want %v", tc.bind, tc.host, got, tc.admit)
			}
		})
	}
}

func TestServeRejectsAnyOriginHeader(t *testing.T) {
	// No origin is allowed, not even a loopback one. A loopback Origin is still
	// a browser, which is the caller the operator did not choose when they
	// accepted loopback exposure for local processes. A command-line client
	// sends no Origin at all, so refusing every one costs the real caller
	// nothing.
	//
	// The header is read with Values, not Get, so an Origin sent with an empty
	// value is refused too: Get reports it as the empty string, which is what a
	// request carrying no Origin at all reports.
	for _, tc := range []struct {
		name   string
		values []string
	}{
		{"a remote origin", []string{"http://evil.example"}},
		{"a loopback origin", []string{"http://127.0.0.1:8787"}},
		{"the opaque origin", []string{"null"}},
		{"an empty value", []string{""}},
		{"two headers", []string{"http://evil.example", "http://127.0.0.1:8787"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newServeTestServer(t, serveOpts{}, "")
			srv, stub := serveChain(t, s)
			req := serveJSONPost(t, srv.URL)
			req.Header["Origin"] = tc.values
			resp, body := serveSend(t, req)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("Origin %q: status = %d, want %d; body %q", tc.values, resp.StatusCode, http.StatusForbidden, body)
			}
			if stub.ran.Load() {
				t.Errorf("Origin %q reached the handler", tc.values)
			}
		})
	}
}

func TestServeAdmitsACommandLineClient(t *testing.T) {
	// The control on the three defenses above: the request a local command-line
	// client actually sends still gets through, so none of them is a blanket
	// refusal.
	s := newServeTestServer(t, serveOpts{}, "")
	srv, stub := serveChain(t, s)
	req := serveJSONPost(t, srv.URL)
	req.Host = "127.0.0.1:8787"
	if _, ok := req.Header["Origin"]; ok {
		t.Fatal("the test built a request carrying an Origin")
	}
	resp, body := serveSend(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %q", resp.StatusCode, http.StatusOK, body)
	}
	if !stub.ran.Load() {
		t.Error("a command-line request did not reach the handler")
	}
}

func TestServeHandlerGuardsEveryRoute(t *testing.T) {
	// The tests above wrap a stub in s.guard, which says what the chain does
	// and nothing about whether the served tree applies it. This one goes
	// through s.handler() for the whole route table, so the guard coming off
	// handler() fails here rather than shipping.
	//
	// The table is serveRoutes itself rather than a list kept beside it, so a
	// route added without a guard case cannot pass. And every check is probed
	// on every route: probing one would pass a handler() that applied only that
	// check while dropping the Host rule, the token and the body bound.
	//
	// Each probe asserts the check's own refusal message as well as the status,
	// because a turn route answers 403 and 415 on its own grounds too.
	const probeID = "20260101T000000-abcdef"
	oversize := `{"message":"` + strings.Repeat("a", serveMaxBody) + `"}`
	for _, rt := range serveRoutes {
		method, pattern, ok := strings.Cut(rt.pattern, " ")
		if !ok {
			t.Fatalf("route %q is not METHOD PATTERN", rt.pattern)
		}
		path := strings.Replace(pattern, "{id}", probeID, 1)
		if strings.HasSuffix(path, "/") {
			path += probeID
		}
		for _, probe := range []struct {
			name  string
			token string
			body  string
			want  int
			says  string
			shape func(*http.Request)
			// sends is how many identical requests the probe makes, for a check
			// that refuses on what came before rather than on one request. Zero
			// means one.
			sends int
		}{
			{"an oversize body", "", oversize, http.StatusRequestEntityTooLarge, "exceeds", nil, 0},
			{"a body that is not JSON", "", `{}`, http.StatusUnsupportedMediaType, "must be application/json", func(r *http.Request) {
				r.Header.Set("Content-Type", "text/plain")
			}, 0},
			{"a Host the bind does not serve", "", `{}`, http.StatusMisdirectedRequest, "must be loopback", func(r *http.Request) {
				r.Host = "rebound.example"
			}, 0},
			{"an Origin", "", `{}`, http.StatusForbidden, "no browser origin", func(r *http.Request) {
				r.Header.Set("Origin", "http://evil.example")
			}, 0},
			{"a burst past the rate limit", "", `{}`, http.StatusTooManyRequests, "rate limit", nil, serveRateLimitBurst + 1},
			{"no bearer token", serveTestToken, `{}`, http.StatusUnauthorized, "authorization required", nil, 0},
		} {
			t.Run(method+" "+path+" with "+probe.name, func(t *testing.T) {
				// The session handlers reach the store whenever the guard admits
				// a request, so the store is a temporary directory here too.
				isolateUserDirs(t)
				s := newServeTestServer(t, serveOpts{}, probe.token)
				srv := httptest.NewServer(s.handler())
				t.Cleanup(srv.Close)

				var resp *http.Response
				var got string
				for range max(probe.sends, 1) {
					req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(probe.body))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Content-Type", "application/json")
					if probe.shape != nil {
						probe.shape(req)
					}
					resp, got = serveSend(t, req)
				}
				if resp.StatusCode != probe.want {
					t.Errorf("%s %s with %s: status = %d, want %d; body %q", method, path, probe.name, resp.StatusCode, probe.want, got)
				}
				if !strings.Contains(got, probe.says) {
					t.Errorf("%s %s with %s: body = %q, want the check's own refusal naming %q", method, path, probe.name, got, probe.says)
				}
			})
		}
	}
}

func TestServeHealthReportsVersion(t *testing.T) {
	s := newServeTestServer(t, serveOpts{}, "")
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := serveSend(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %q", resp.StatusCode, http.StatusOK, body)
	}
	var got struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	want, _, _, _ := versionInfo()
	if got.Version != want {
		t.Errorf("version = %q, want %q", got.Version, want)
	}
	if got.Status != "ok" {
		t.Errorf("status = %q, want %q", got.Status, "ok")
	}
}

func TestServeRejectsAnOversizeBody(t *testing.T) {
	s := newServeTestServer(t, serveOpts{}, "")
	srv, stub := serveChain(t, s)

	// Past the bound, not at it.
	body := bytes.Repeat([]byte("a"), serveMaxBody+1)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/sessions", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, got := serveSend(t, req)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d; body %q", resp.StatusCode, http.StatusRequestEntityTooLarge, got)
	}
	if stub.ran.Load() {
		t.Error("an oversize body reached the handler")
	}
}

// The Host rule is decided from the bind's text, and a name resolves only when
// the listener opens, so the address actually served can be wider than the text
// reads: a localhost mapped to a routable address would be served under the
// loopback rule, with no token required and the operator's reach granted to any
// peer that reaches it. serveListener re-derives the rule from the listener and
// refuses a disagreement.
func TestServeRefusesAListenerTheBindDoesNotName(t *testing.T) {
	for _, tc := range []struct {
		name string
		bind string
		addr string
		ok   bool
	}{
		{"a loopback name on a loopback address", "localhost:8787", "127.0.0.1:8787", true},
		{"a loopback name on an IPv6 loopback address", "localhost:8787", "[::1]:8787", true},
		{"a loopback name on a routable address", "localhost:8787", "192.0.2.10:8787", false},
		{"a subdomain of localhost on a routable address", "api.localhost:8787", "192.0.2.10:8787", false},
		{"a wildcard bind on the wildcard address", "0.0.0.0:8787", "0.0.0.0:8787", true},
		{"a wildcard bind on a concrete address", "0.0.0.0:8787", "192.0.2.10:8787", false},
		{"a concrete bind on its own address", "192.0.2.10:8787", "192.0.2.10:8787", true},
		{"a concrete bind on a loopback address", "192.0.2.10:8787", "127.0.0.1:8787", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := serveCheckListenerMode(tc.bind, serveHostModeFor(tc.bind), tc.addr)
			if tc.ok {
				if err != nil {
					t.Fatalf("err = %v, want the bind served", err)
				}
				return
			}
			if err == nil {
				t.Fatal("a listener the bind does not name was served")
			}
			if !strings.Contains(err.Error(), tc.addr) {
				t.Errorf("err = %v, want the address actually opened named in it", err)
			}
		})
	}

	// A loopback name whose resolved address agrees with it opens, serves, and
	// shuts down on its context.
	s := newServeTestServer(t, serveOpts{bind: "localhost:0"}, "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run on a loopback name = %v, want it served and shut down cleanly", err)
		}
	case <-time.After(serveShutdownTimeout + 10*time.Second):
		t.Fatal("run did not return after its context was cancelled")
	}

	// serveListener is the body run reaches once the listener is open, and it
	// refuses a listener whose address is not the exposure the bind names: that
	// is what puts the check on the serving path rather than only in the table
	// above. The bind names a routable address, which takes --allow-remote and a
	// token, while the listener handed over is loopback on this machine, so
	// nothing is opened off it. The context is already cancelled, so a build
	// missing the check serves and shuts down instead of blocking.
	t.Run("the serving path refuses a listener off the bind's exposure", func(t *testing.T) {
		s := newServeTestServer(t, serveOpts{bind: "192.0.2.10:8787", allowRemote: true}, "a-token")
		if s.hostMode != serveHostBind {
			t.Fatalf("hostMode = %d, want serveHostBind (%d)", s.hostMode, serveHostBind)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		addr := ln.Addr().String()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err = s.serveListener(ctx, ln)
		if err == nil {
			t.Fatalf("serveListener on %s = nil, want a listener off the bind's exposure refused", addr)
		}
		if !strings.Contains(err.Error(), addr) {
			t.Errorf("err = %v, want the address actually opened (%s) named in it", err, addr)
		}
		if _, aerr := ln.Accept(); !errors.Is(aerr, net.ErrClosed) {
			t.Errorf("Accept after the refusal = %v, want %v", aerr, net.ErrClosed)
		}
	})
}
