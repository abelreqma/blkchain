package main

import (
	"bytes"
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

// newServeTestServer builds a server value without a retrieval client or a
// catalog, neither of which the guard chain touches.
func newServeTestServer(t *testing.T, o serveOpts, tok string) *serveServer {
	t.Helper()
	if o.bind == "" {
		o.bind = serveDefaultBind
	}
	s, err := newServeServer(nil, ragconfig.Config{}, nil, o, tok)
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
	constantTime := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "subtle" && sel.Sel.Name == "ConstantTimeCompare" {
			constantTime = true
		}
		return true
	})
	if !constantTime {
		t.Error("requireBearerToken does not compare the token with subtle.ConstantTimeCompare")
	}

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

func TestServeRejectsAnyOriginHeader(t *testing.T) {
	// No origin is allowed, not even a loopback one. A loopback Origin is still
	// a browser, which is the caller the operator did not choose when they
	// accepted loopback exposure for local processes. A command-line client
	// sends no Origin at all, so refusing every one costs the real caller
	// nothing.
	for _, origin := range []string{"http://evil.example", "http://127.0.0.1:8787", "null"} {
		t.Run(origin, func(t *testing.T) {
			s := newServeTestServer(t, serveOpts{}, "")
			srv, stub := serveChain(t, s)
			req := serveJSONPost(t, srv.URL)
			req.Header.Set("Origin", origin)
			resp, body := serveSend(t, req)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("Origin %q: status = %d, want %d; body %q", origin, resp.StatusCode, http.StatusForbidden, body)
			}
			if stub.ran.Load() {
				t.Errorf("Origin %q reached the handler", origin)
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
