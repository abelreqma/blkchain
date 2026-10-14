package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/skillcat"
)

// serve.go is blkChain's HTTP transport (`blk serve`). It offers the same
// native turn the command line, the plain REPL, the TUI and the MCP server
// share, over loopback, to clients on this machine.
//
// The exposure is loopback with an optional bearer token. A browser can reach
// loopback too, and a page the operator has open is not the caller they chose,
// so three defenses close the API against it: a body must be JSON, the Host
// must be one the bind serves, and any Origin at all is refused. Each one
// stands on its own; one of the three holding is not the control.

const (
	// serveDefaultBind serves loopback only, so nothing is exposed off the
	// machine without the operator saying so twice.
	serveDefaultBind = "127.0.0.1:8787"
	// serveTokenEnv names the bearer token's variable. Secrets come from the
	// environment only.
	serveTokenEnv = "BLKCHAIN_SERVE_TOKEN"
	// serveMaxBody bounds a request body. A turn's message is the largest
	// field a caller sends and mcpChatMaxMessage is well inside this.
	serveMaxBody = 1 << 20
)

// serveReadHeaderTimeout bounds how long a connection may take to send its
// request head, so a stalled peer cannot hold one open for free.
const serveReadHeaderTimeout = 10 * time.Second

// serveIdleTimeout bounds a kept-alive connection between requests.
const serveIdleTimeout = 2 * time.Minute

// serveShutdownTimeout bounds how long a cancelled server waits for in-flight
// requests before it stops regardless.
const serveShutdownTimeout = 5 * time.Second

// errServeRemoteNeedsToken refuses a bind that is not loopback with no bearer
// token configured. Off loopback the token is the only thing between the
// operator and anyone who can route to the address.
var errServeRemoteNeedsToken = fmt.Errorf("serve: a bind that is not loopback requires a bearer token in %s", serveTokenEnv)

// serveOpts is what the command line sets.
type serveOpts struct {
	bind        string
	allowRemote bool
}

func defineServeFlags(fs *flag.FlagSet, o *serveOpts) {
	fs.StringVar(&o.bind, "bind", serveDefaultBind, "listen on `ADDR`")
	fs.BoolVar(&o.allowRemote, "allow-remote", false, "serve a bind that is not loopback; also requires a token in "+serveTokenEnv)
}

// serveToken reads the bearer token. This is the only place it is read: it is
// never logged, never written to a response or a header, and never included in
// an error.
func serveToken() string {
	return strings.TrimSpace(os.Getenv(serveTokenEnv))
}

// serveHostOnly strips the port from an authority, keeping the host as written.
// An authority with no port is returned with any address brackets removed.
func serveHostOnly(authority string) string {
	if host, _, err := net.SplitHostPort(authority); err == nil {
		return host
	}
	return strings.Trim(authority, "[]")
}

// serveIsLoopbackHost reports whether a host from a bind address or a Host
// header names the loopback interface. A literal address is decided by netip;
// the names localhost and *.localhost are loopback by RFC 6761 section 6.3.
// Any other name is not loopback, so a name this code cannot decide fails
// closed.
func serveIsLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.IsLoopback()
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	return name == "localhost" || strings.HasSuffix(name, ".localhost")
}

// serveIsWildcardHost reports whether a host from a bind address is the
// wildcard, meaning the server accepts connections on every local address. An
// empty host is the wildcard as net.Listen reads it; any unspecified literal
// address is the same thing written out.
func serveIsWildcardHost(host string) bool {
	if host == "" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsUnspecified()
}

// serveHostMode is the rule a request's Host must satisfy. It is decided from
// the bind alone, so the per-request check cannot disagree with the exposure
// the server actually opened.
type serveHostMode int

const (
	// serveHostLoopback requires a loopback Host. It is the rule for a loopback
	// bind, where it defeats DNS rebinding.
	serveHostLoopback serveHostMode = iota
	// serveHostBind requires the Host to name the bind's own host. It is the
	// rule for a concrete bind that is not loopback: a legitimate client
	// addresses the one address the operator chose to serve, so that authority
	// is predictable and remains a usable control.
	serveHostBind
	// serveHostAny admits every Host. It is the rule for a wildcard bind only,
	// where the address a legitimate client reaches this server on is not
	// predictable from the bind, so no Host value can be required of it.
	serveHostAny
)

// serveHostModeFor decides the Host rule for a bind. The bind has already
// passed serveBindCheck, so it is a HOST:PORT address here.
func serveHostModeFor(bind string) serveHostMode {
	host := serveHostOnly(bind)
	switch {
	case serveIsLoopbackHost(host):
		return serveHostLoopback
	case serveIsWildcardHost(host):
		return serveHostAny
	default:
		return serveHostBind
	}
}

// serveBindCheck is the exposure decision on its own, separate from serving, so
// a refusal is decidable without opening a listener. A bind that is not
// loopback needs the explicit flag and, in that mode, a token: loopback
// exposure for local processes is one decision and anything wider is another
// the operator has to make deliberately.
func serveBindCheck(bind string, allowRemote bool, token string) error {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return usageErr(`serve: --bind %q is not a HOST:PORT address. See "blk help serve".`, bind)
	}
	if serveIsLoopbackHost(host) {
		return nil
	}
	if !allowRemote {
		return usageErr(`serve: --bind %q is not loopback; pass --allow-remote and set %s to serve it. See "blk help serve".`, bind, serveTokenEnv)
	}
	if token == "" {
		return fmt.Errorf("%w: --bind %q", errServeRemoteNeedsToken, bind)
	}
	return nil
}

// serveServer holds one HTTP transport's state.
type serveServer struct {
	rc    *retrieval.Client
	cfg   ragconfig.Config
	cat   *skillcat.Catalog
	opts  serveOpts
	token string
	// hostMode is the Host rule, computed once from the bind so no request ever
	// gets a weaker check than the bind that was opened calls for.
	hostMode serveHostMode
	// owned is the set of session ids this server created, one set per server
	// instance as newMCPServer keeps one, so a test's server owns only its own
	// turns.
	owned *chatSessionOwner
}

// newServeServer builds the transport's state. The exposure decision is run
// here too, so no serveServer value can exist for a bind that was refused.
func newServeServer(rc *retrieval.Client, cfg ragconfig.Config, cat *skillcat.Catalog, o serveOpts, token string) (*serveServer, error) {
	if err := serveBindCheck(o.bind, o.allowRemote, token); err != nil {
		return nil, err
	}
	return &serveServer{
		rc:       rc,
		cfg:      cfg,
		cat:      cat,
		opts:     o,
		token:    token,
		hostMode: serveHostModeFor(o.bind),
		owned:    newChatSessionOwner(),
	}, nil
}

// handler is the served tree: the route table wrapped in the guard chain.
func (s *serveServer) handler() http.Handler {
	return s.guard(s.routes())
}

// routes is the route table. Every route added here is reached only through
// guard, which handler applies around the whole table rather than per route.
func (s *serveServer) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST "+serveSessionsPath, s.handleCreateSession)
	mux.HandleFunc("GET "+serveSessionsPath, s.handleListSessions)
	mux.HandleFunc("GET "+serveSessionsPath+"/", s.handleReadSession)
	mux.HandleFunc("POST "+serveSessionsPath+"/{id}"+serveTurnsSuffix, s.handleTurn)
	mux.HandleFunc("POST "+serveSessionsPath+"/{id}"+serveTurnsStreamSuffix, s.handleTurnStream)
	return mux
}

// guard wraps next in the request chain.
//
// The order is a security property, not a style choice. The body bound and the
// three browser defenses run first, so an unauthenticated caller cannot use a
// parse failure or a timing difference as an oracle, and authentication runs
// last of the checks, so no handler ever sees an unauthenticated request.
// Anything added to this chain belongs between the defenses and the
// authentication step.
func (s *serveServer) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checks := []func() (int, string){
			func() (int, string) { return boundRequestBody(w, r) },
			func() (int, string) { return requireJSONBody(r) },
			func() (int, string) { return requireBindHost(r, s.hostMode, s.opts.bind) },
			func() (int, string) { return rejectAnyOrigin(r) },
			func() (int, string) { return requireBearerToken(r, s.token) },
		}
		for _, check := range checks {
			if code, msg := check(); code != 0 {
				serveRefuse(w, code, msg)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// boundRequestBody refuses a body whose declared length is over serveMaxBody
// and caps the reader as well, so a body that declares no length or declares a
// wrong one cannot read past the bound either. 413 is the status for a payload
// the server refuses on size alone.
func boundRequestBody(w http.ResponseWriter, r *http.Request) (int, string) {
	if r.ContentLength > serveMaxBody {
		return http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %d bytes", serveMaxBody)
	}
	r.Body = http.MaxBytesReader(w, r.Body, serveMaxBody)
	return 0, ""
}

// requireJSONBody rejects a request carrying a body without a JSON content
// type. A cross-origin browser request with that header needs a preflight it
// will not receive, so this closes the API against a page the operator has
// open. A request with no body is unaffected. 415 is the status for a media
// type the server will not accept.
func requireJSONBody(r *http.Request) (int, string) {
	if r.ContentLength == 0 {
		return 0, ""
	}
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" {
		return http.StatusUnsupportedMediaType, "a request body must be application/json"
	}
	return 0, ""
}

// requireBindHost rejects a Host header the bind does not serve, which defeats
// DNS rebinding: a name that resolves to 127.0.0.1 still arrives with its own
// Host. 421 is the status for a request addressed to an authority this server
// does not serve (RFC 9110 section 15.5.22); 400 would read as a malformed
// request, which this is not.
//
// The rule comes from the bind, not from --allow-remote. The flag is also
// accepted alongside a loopback bind, where the exposure is still loopback and
// a page the operator has open can still reach it, so keying the check on the
// flag would turn the rebinding defense off on the default address.
func requireBindHost(r *http.Request, mode serveHostMode, bind string) (int, string) {
	host := serveHostOnly(r.Host)
	switch mode {
	case serveHostAny:
		return 0, ""
	case serveHostBind:
		if strings.EqualFold(host, serveHostOnly(bind)) {
			return 0, ""
		}
		return http.StatusMisdirectedRequest, "the request Host must name the bind " + bind
	default:
		if serveIsLoopbackHost(host) {
			return 0, ""
		}
		return http.StatusMisdirectedRequest, "the request Host must be loopback, matching the bind " + bind
	}
}

// rejectAnyOrigin rejects a request carrying an Origin header. No origin is
// allowed, because a command-line client sends none and a browser always does,
// and a loopback origin is still a browser. 403 is the status for a request the
// server understands and refuses on the caller's identity.
func rejectAnyOrigin(r *http.Request) (int, string) {
	if len(r.Header.Values("Origin")) == 0 {
		return 0, ""
	}
	return http.StatusForbidden, "this API serves no browser origin"
}

// requireBearerToken enforces the optional bearer token. A token that is set is
// required on every request, loopback or not: an operator who sets one wants
// authentication, and serving loopback unauthenticated while a token exists
// would make the setting a no-op nobody notices.
//
// Both sides are hashed first so the comparison runs over equal-length inputs
// and cannot leak the configured token's length, and the refusal carries
// neither token. The scheme is matched case-insensitively per RFC 9110 section
// 11.1.
//
// The refusal carries no WWW-Authenticate, which departs from RFC 9110 section
// 15.5.2 deliberately. That header makes a browser prompt the operator for the
// credential and then attach it to every later request to this origin, which
// would hand a page the operator has open the authentication this API relies
// on. A command-line client does not need the challenge to know the scheme.
func requireBearerToken(r *http.Request, token string) (int, string) {
	if token == "" {
		return 0, ""
	}
	scheme, presented, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return http.StatusUnauthorized, "authorization required"
	}
	want := sha256.Sum256([]byte(token))
	got := sha256.Sum256([]byte(strings.TrimSpace(presented)))
	if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		return http.StatusUnauthorized, "authorization required"
	}
	return 0, ""
}

// handleHealth reports the running version, so a client can tell which build
// is answering before it sends a turn.
func (s *serveServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	v, _, _, _ := versionInfo()
	serveWriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": v})
}

// serveRefuse writes one refusal. The message is a fixed string chosen by the
// caller, never caller-supplied text and never a secret.
func serveRefuse(w http.ResponseWriter, code int, msg string) {
	serveWriteJSON(w, code, map[string]string{"error": msg})
}

// serveWriteJSON writes one JSON response.
func serveWriteJSON(w http.ResponseWriter, code int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, `{"error":"response could not be encoded"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// run listens on the configured bind and serves until ctx is cancelled. No read
// or write deadline is set on the server because a streaming endpoint is long
// lived; a turn is bounded by its own wall clock instead.
func (s *serveServer) run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.opts.bind)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: serveReadHeaderTimeout,
		IdleTimeout:       serveIdleTimeout,
	}
	go func() {
		<-ctx.Done()
		stop, cancel := context.WithTimeout(context.Background(), serveShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(stop)
	}()
	fmt.Fprintf(os.Stderr, "blk serve listening on http://%s\n", ln.Addr())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// runServe starts the HTTP transport. It runs in-process against the Go
// retrieval client and turn loop, so embed_server and Qdrant must be up.
func runServe(args []string) error {
	var o serveOpts
	fs := newFlagSet("serve")
	defineServeFlags(fs, &o)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usageErr(`serve: unexpected argument %q. See "blk help serve".`, fs.Arg(0))
	}

	token := serveToken()
	// The exposure decision runs before anything is opened, so a refused bind
	// leaves no listener and no client behind.
	if err := serveBindCheck(o.bind, o.allowRemote, token); err != nil {
		return err
	}

	cfg := loadConfig()
	rc, err := newRetrievalClient(cfg)
	if err != nil {
		return err
	}
	defer rc.Close()

	cat, err := loadEngageCatalog()
	if err != nil {
		return err
	}

	s, err := newServeServer(rc, cfg, cat, o, token)
	if err != nil {
		return err
	}
	return s.run(context.Background())
}
