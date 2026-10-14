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
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
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

// serveMaxConcurrentTurns bounds the turns this transport runs at once. It is
// mcpChatMaxInFlight because a turn is the same work on either transport: one
// model call driving the whole tool registry, with a sandbox container, a
// retrieval round and web fetches behind it, each holding that work's buffers
// for as long as the turn's deadline allows. Bounding both transports with one
// number is what keeps them from drifting into two different answers about how
// much of that work one machine carries.
const serveMaxConcurrentTurns = mcpChatMaxInFlight

// errServeTurnInFlight refuses a turn on a session that already has one.
// runNativeTurn holds a session's turn lock for the whole turn, so a second
// request on that session would block on the lock while holding a connection
// and a server slot. Refusing says so at once instead.
var errServeTurnInFlight = errors.New("serve: a turn is already in flight on this session")

// errServeBusy refuses a turn because serveMaxConcurrentTurns are running.
var errServeBusy = fmt.Errorf("serve: %d turns are already in flight; retry when one finishes", serveMaxConcurrentTurns)

// serveTurnGate bounds the turns in flight: one per session, and
// serveMaxConcurrentTurns across the server. One value per server, as the MCP
// transport keeps one set of chat slots per server, so a test's server bounds
// only its own turns. sessions holds an entry per turn in flight and no more,
// because every acquire's release deletes its own.
type serveTurnGate struct {
	mu       sync.Mutex
	sessions map[string]struct{}
	slots    chan struct{}
}

func newServeTurnGate() *serveTurnGate {
	return &serveTurnGate{
		sessions: map[string]struct{}{},
		slots:    make(chan struct{}, serveMaxConcurrentTurns),
	}
}

// acquire takes the session's slot and then a server slot, and returns the
// release for both. It never queues: a session with a turn in flight and a full
// server are each refused, so no request waits holding a connection. A server
// that is full releases the session slot it just took, or that session could
// never run a turn again.
func (g *serveTurnGate) acquire(id string) (func(), error) {
	g.mu.Lock()
	if _, busy := g.sessions[id]; busy {
		g.mu.Unlock()
		return nil, errServeTurnInFlight
	}
	g.sessions[id] = struct{}{}
	g.mu.Unlock()

	select {
	case g.slots <- struct{}{}:
	default:
		g.releaseSession(id)
		return nil, errServeBusy
	}
	return func() {
		<-g.slots
		g.releaseSession(id)
	}, nil
}

func (g *serveTurnGate) releaseSession(id string) {
	g.mu.Lock()
	delete(g.sessions, id)
	g.mu.Unlock()
}

// The request rate bound. Every admitted request costs work: a session read
// walks the store, a turn runs a model, and the body bound alone lets a loop
// hand this server serveMaxBody per request to buffer and decode. The burst
// admits a client's whole opening sequence, which is a session created, read
// back, and a turn or two started, with no wait; the refill is past what an
// interactive client asks for and well inside what a loop would.
const (
	serveRateLimitPerMinute = 240
	serveRateLimitBurst     = 32
)

// serveRateLimiter is one server's token bucket. The limit is per server, not
// per IP, because every caller this server admits reached the bind the exposure
// decision allowed: on the default exposure that is loopback, so there is one
// caller to bound and a per-IP bucket would be a bucket for the single address
// 127.0.0.1. What needs bounding is this server's own work, not a peer's share
// of it.
//
// The budget is shared, and the chain spends it ahead of the token check, so an
// unauthenticated local process can spend it and leave the operator's own
// authenticated client refused with 429. A request a browser defense refuses
// costs no token, so a flood cannot deepen that through those paths, while one
// that is admitted and then answered 401 does cost one. That is the trade
// bounding an unauthenticated flood before the token comparison buys.
type serveRateLimiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newServeRateLimiter() *serveRateLimiter {
	return &serveRateLimiter{tokens: serveRateLimitBurst, last: time.Now()}
}

// allow takes one token, refilling for the time since the last call. It never
// waits: a caller past the limit is refused, so a burst cannot hold connections
// open waiting for tokens.
func (l *serveRateLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Minutes() * serveRateLimitPerMinute
	l.last = now
	if l.tokens > serveRateLimitBurst {
		l.tokens = serveRateLimitBurst
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

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

// serveCheckListenerMode compares the Host rule the bind's text produced with
// the one the opened address produces. A name resolves at listen time, so the
// address actually opened can be wider than the text reads: localhost mapped to
// a routable address opens a listener off this machine while
// serveHostModeFor's text pass calls it loopback, which would serve a remote
// peer with no token and the relaxed loopback Host rule. The two have to agree
// or the exposure the operator chose is not the one that was opened.
func serveCheckListenerMode(bind string, mode serveHostMode, addr string) error {
	if serveHostModeFor(addr) == mode {
		return nil
	}
	return fmt.Errorf("serve: --bind %q opened %s, which is not the exposure that bind names; refusing to serve it", bind, addr)
}

// serveServer holds one HTTP transport's state.
type serveServer struct {
	rc    *retrieval.Client
	cfg   ragconfig.Config
	opts  serveOpts
	token string
	// hostMode is the Host rule, computed once from the bind so no request ever
	// gets a weaker check than the bind that was opened calls for.
	hostMode serveHostMode
	// owned is the set of session ids this server created, one set per server
	// instance as newMCPServer keeps one, so a test's server owns only its own
	// turns.
	owned *chatSessionOwner
	// turns bounds the turns in flight and rate bounds the requests, both one
	// value per server, so the bounds hold across every connection this server
	// answers rather than per connection.
	turns *serveTurnGate
	rate  *serveRateLimiter
}

// newServeServer builds the transport's state. The exposure decision is run
// here too, so no serveServer value can exist for a bind that was refused.
func newServeServer(rc *retrieval.Client, cfg ragconfig.Config, o serveOpts, token string) (*serveServer, error) {
	if err := serveBindCheck(o.bind, o.allowRemote, token); err != nil {
		return nil, err
	}
	return &serveServer{
		rc:       rc,
		cfg:      cfg,
		opts:     o,
		token:    token,
		hostMode: serveHostModeFor(o.bind),
		owned:    newChatSessionOwner(),
		turns:    newServeTurnGate(),
		rate:     newServeRateLimiter(),
	}, nil
}

// handler is the served tree: the route table wrapped in the guard chain.
func (s *serveServer) handler() http.Handler {
	return s.guard(s.routes())
}

// serveRoutes is the route table as data. http.ServeMux cannot enumerate its
// own patterns, so the table is the slice and routes ranges over it: the test
// that proves every route is reached through guard ranges over this same slice,
// which makes a route added without a guard case impossible rather than a
// convention the next author has to remember. The handler is a method
// expression because every route is a method on the server.
var serveRoutes = []struct {
	pattern string
	h       func(*serveServer, http.ResponseWriter, *http.Request)
}{
	{"GET /health", (*serveServer).handleHealth},
	{"POST " + serveSessionsPath, (*serveServer).handleCreateSession},
	{"GET " + serveSessionsPath, (*serveServer).handleListSessions},
	{"GET " + serveSessionsPath + "/", (*serveServer).handleReadSession},
	{"POST " + serveSessionsPath + "/{id}" + serveTurnsSuffix, (*serveServer).handleTurn},
	{"POST " + serveSessionsPath + "/{id}" + serveTurnsStreamSuffix, (*serveServer).handleTurnStream},
}

// routes is the route table bound to this server. Every route in it is reached
// only through guard, which handler applies around the whole table rather than
// per route.
func (s *serveServer) routes() *http.ServeMux {
	mux := http.NewServeMux()
	for _, rt := range serveRoutes {
		mux.HandleFunc(rt.pattern, func(w http.ResponseWriter, r *http.Request) { rt.h(s, w, r) })
	}
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
//
// The rate bound sits at that point. After the defenses, so a request a defense
// refuses does not spend the budget a legitimate client is left with; before
// authentication, so an unauthenticated flood is bounded before it reaches the
// token comparison, which hashes two values on every request.
func (s *serveServer) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checks := []func() (int, string){
			func() (int, string) { return boundRequestBody(w, r) },
			func() (int, string) { return requireJSONBody(r) },
			func() (int, string) { return requireBindHost(r, s.hostMode, s.opts.bind) },
			func() (int, string) { return rejectAnyOrigin(r) },
			func() (int, string) { return limitRequestRate(s.rate) },
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
// allowed: a command-line client sends none, while a browser sends one on every
// request it makes in CORS mode and on every request whose method is not GET or
// HEAD, which is what makes this refusal close the mutating paths. A loopback
// origin is still a browser. A no-cors GET a page issues as a subresource
// carries no Origin and passes this control, which is why the Host rule and the
// JSON content type each have to stand on their own. 403 is the status for a
// request the server understands and refuses on the caller's identity.
func rejectAnyOrigin(r *http.Request) (int, string) {
	if len(r.Header.Values("Origin")) == 0 {
		return 0, ""
	}
	return http.StatusForbidden, "this API serves no browser origin"
}

// limitRequestRate refuses a request past the server's token bucket. 429 is the
// status for a request refused on rate alone, and the refusal carries no
// Retry-After: the bucket refills continuously, so there is no one time at
// which the next request is admitted.
func limitRequestRate(l *serveRateLimiter) (int, string) {
	if l.allow() {
		return 0, ""
	}
	return http.StatusTooManyRequests, fmt.Sprintf("the request rate limit of %d per minute was reached", serveRateLimitPerMinute)
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
	if err := serveCheckListenerMode(s.opts.bind, s.hostMode, ln.Addr().String()); err != nil {
		_ = ln.Close()
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

	s, err := newServeServer(rc, cfg, o, token)
	if err != nil {
		return err
	}
	// An interrupt cancels the context the server watches, so in-flight turns
	// get serveShutdownTimeout to finish instead of ending with the process.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return s.run(ctx)
}
