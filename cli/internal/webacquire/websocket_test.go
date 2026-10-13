package webacquire

import (
	"bufio"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func wsBroker() *Broker {
	return &Broker{Policy: Policy{Authorize: func(context.Context, Request) error { return nil }, IPAllowed: func(_ string, ip net.IP) bool { return ip.IsLoopback() }}}
}
func TestWebSocketPinnedMessagesPoliciesAndCancellation(t *testing.T) {
	var headers http.Header
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = r.Header.Clone()
		conn, err := (&websocket.Upgrader{Subprotocols: []string{"fixture"}, CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			kind, body, err := conn.ReadMessage()
			if err != nil {
				return
			}
			writes.Add(1)
			if err = conn.WriteMessage(kind, body); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	target := "ws" + strings.TrimPrefix(server.URL, "http") + "/stream"
	broker := wsBroker()
	broker.Policy.Resolve = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("127.0.0.1")}, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	socket, response, err := broker.OpenWebSocket(ctx, target, http.Header{"Cookie": []string{"session=fixture"}, "Origin": []string{server.URL}}, []string{"fixture"})
	if err != nil || response.Status != 101 || socket.Conn.Subprotocol() != "fixture" {
		t.Fatal(response, err)
	}
	defer socket.Close()
	received := make(chan error, 1)
	go func() {
		kind, body, err := socket.Receive()
		if err == nil && (kind != websocket.BinaryMessage || string(body) != "\x00\xfffixture") {
			err = ErrLimit
		}
		received <- err
	}()
	if err = socket.Send(ctx, websocket.BinaryMessage, []byte("\x00\xfffixture")); err != nil {
		t.Fatal(err)
	}
	if err = <-received; err != nil {
		t.Fatal(err)
	}
	if headers.Get("Cookie") != "session=fixture" {
		t.Fatal("credentials lost")
	}
	broker.Policy.Authorize = func(_ context.Context, r Request) error {
		if r.Method == "WEBSOCKET" {
			return ErrLimit
		}
		return nil
	}
	if err = socket.Send(ctx, websocket.TextMessage, []byte("denied")); err == nil {
		t.Fatal("message policy bypass")
	}
	if writes.Load() != 1 {
		t.Fatal("denied message reached target")
	}
	cancel()
	if _, _, err = socket.Receive(); err == nil {
		t.Fatal("cancellation did not close socket")
	}
	broker = wsBroker()
	broker.Policy.Resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.0.2.1")}, nil
	}
	if _, _, err = broker.OpenWebSocket(context.Background(), target, nil, nil); err == nil {
		t.Fatal("mixed DNS scope bypass")
	}
}

func TestWebSocketPinnedAddressChecksHostname(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Scheme = "ws"
	u.Host = net.JoinHostPort("socket.example.test", u.Port())
	broker := wsBroker()
	broker.Policy.Resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	broker.Policy.IPAllowed = func(host string, ip net.IP) bool {
		return host == "socket.example.test" && ip.IsLoopback()
	}
	socket, _, err := broker.OpenWebSocket(context.Background(), u.String(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	u.Host = net.JoinHostPort("evil.example.test", u.Port())
	if _, _, err := broker.OpenWebSocket(context.Background(), u.String(), nil, nil); err == nil {
		t.Fatal("WebSocket accepted another hostname at the same IP")
	}
}

func TestWebSocketCustomDialHonorsScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer server.Close()
	target := "ws" + strings.TrimPrefix(server.URL, "http") + "/stream"
	broker := wsBroker()
	broker.Policy.Resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	var dials atomic.Int32
	broker.Policy.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	broker.Policy.IPAllowed = func(string, net.IP) bool { return false }
	if _, _, err := broker.OpenWebSocket(context.Background(), target, nil, nil); err == nil || dials.Load() != 0 {
		t.Fatalf("out-of-scope socket reached custom dial: dials=%d err=%v", dials.Load(), err)
	}
	broker.Policy.IPAllowed = func(string, net.IP) bool { return true }
	socket, response, err := broker.OpenWebSocket(context.Background(), target, nil, nil)
	if err != nil || response.Status != http.StatusSwitchingProtocols || dials.Load() != 1 {
		t.Fatalf("scoped socket dial failed: response=%+v dials=%d err=%v", response, dials.Load(), err)
	}
	socket.Close()
}
func TestWebSocketLimitsRedirectsAndTLSVerification(t *testing.T) {
	var reached atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer source.Close()
	broker := wsBroker()
	_, response, err := broker.OpenWebSocket(context.Background(), "ws"+strings.TrimPrefix(source.URL, "http"), nil, nil)
	if err == nil || response.Status != 302 || reached.Load() != 0 {
		t.Fatal("WebSocket redirect followed", response, err)
	}
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer secure.Close()
	if _, _, err = broker.OpenWebSocket(context.Background(), "wss"+strings.TrimPrefix(secure.URL, "https"), nil, nil); err == nil {
		t.Fatal("untrusted target TLS accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, e := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.BinaryMessage, make([]byte, MaxWSMessage+1))
	}))
	defer server.Close()
	socket, _, err := broker.OpenWebSocket(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if _, _, err = socket.Receive(); err == nil {
		t.Fatal("message limit ignored")
	}
	if err = socket.Send(context.Background(), websocket.TextMessage, make([]byte, MaxWSMessage+1)); err == nil {
		t.Fatal("outbound message limit ignored")
	}
	if _, _, err = WebSocketURL("ws://fixture.test/stream#x"); err == nil {
		t.Fatal("fragment accepted")
	}
	if _, _, err = broker.OpenWebSocket(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), http.Header{"X-Note": []string{"x\r\nCookie: stolen"}}, nil); err == nil {
		t.Fatal("header injection accepted")
	}
}

// tunnelProxy stands in for an intercepting proxy on loopback. It answers
// CONNECT, relays the tunnel to the destination it was asked for, and records
// that destination so a test can tell a proxied handshake from a direct one.
type tunnelProxy struct {
	address string
	mu      sync.Mutex
	targets []string
	extra   []string
}

func newTunnelProxy(t *testing.T) *tunnelProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	p := &tunnelProxy{address: listener.Addr().String()}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go p.serve(conn)
		}
	}()
	return p
}

func (p *tunnelProxy) serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, 4096)
	request, err := http.ReadRequest(reader)
	if err != nil || request.Method != http.MethodConnect || reader.Buffered() > 0 {
		return
	}
	p.mu.Lock()
	p.targets = append(p.targets, request.Host)
	for name := range request.Header {
		p.extra = append(p.extra, name)
	}
	p.mu.Unlock()
	destination, err := net.DialTimeout("tcp", request.Host, 5*time.Second)
	if err != nil {
		return
	}
	defer destination.Close()
	if _, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(destination, conn)
		close(done)
	}()
	_, _ = io.Copy(conn, destination)
	<-done
}

func (p *tunnelProxy) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string{}, p.targets...)
}

// addedHeaders names every header the tunnel request carried beyond the
// destination, so a test can refuse a tracer, a correlation value or a
// user-agent on the way to the proxy.
func (p *tunnelProxy) addedHeaders() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string{}, p.extra...)
}

func wsEchoServer(secure bool) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			kind, body, err := conn.ReadMessage()
			if err != nil || conn.WriteMessage(kind, body) != nil {
				return
			}
		}
	})
	if secure {
		return httptest.NewTLSServer(handler)
	}
	return httptest.NewServer(handler)
}

func wsLoopback(context.Context, string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("127.0.0.1")}, nil
}

// TestWebSocketCarriesTheUpgradeThroughTheProxy pins that WebSocket acquisition
// reaches the proxy rather than dialling the target, that frames flow over the
// tunnel, and that the scope check still runs first so an out-of-scope host
// never reaches the proxy. Burp's WebSocket history stays empty without this.
func TestWebSocketCarriesTheUpgradeThroughTheProxy(t *testing.T) {
	server := wsEchoServer(false)
	defer server.Close()
	proxy := newTunnelProxy(t)
	host := strings.TrimPrefix(server.URL, "http://")
	target := "ws://" + host + "/stream"
	broker := wsBroker()
	broker.Policy.Resolve = wsLoopback
	broker.Policy.Upstream = &Upstream{Address: proxy.address, RootCAs: x509.NewCertPool()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	socket, response, err := broker.OpenWebSocket(ctx, target, nil, nil)
	if err != nil || response.Status != http.StatusSwitchingProtocols {
		t.Fatalf("the proxied handshake failed: %+v %v", response, err)
	}
	defer socket.Close()
	if err = socket.Send(ctx, websocket.TextMessage, []byte("tunnelled")); err != nil {
		t.Fatal(err)
	}
	kind, body, err := socket.Receive()
	if err != nil || kind != websocket.TextMessage || string(body) != "tunnelled" {
		t.Fatalf("the tunnel did not carry frames: %d %q %v", kind, body, err)
	}
	if seen := proxy.seen(); len(seen) != 1 || seen[0] != host {
		t.Fatalf("the proxy was asked to reach %v, want one tunnel to %q", seen, host)
	}
	if added := proxy.addedHeaders(); len(added) != 0 {
		t.Fatalf("the tunnel request carried %v beyond the destination", added)
	}
	outside := wsBroker()
	outside.Policy.Resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.7")}, nil
	}
	outside.Policy.Upstream = &Upstream{Address: proxy.address, RootCAs: x509.NewCertPool()}
	if _, _, err = outside.OpenWebSocket(ctx, target, nil, nil); err == nil {
		t.Fatal("an out-of-scope host was accepted under a proxy")
	}
	if seen := proxy.seen(); len(seen) != 1 {
		t.Fatalf("the proxy saw an out-of-scope tunnel: %v", seen)
	}
}

// TestWebSocketProxyKeepsTLSVerification pins that a wss handshake through the
// tunnel verifies the certificate against the upstream's pool and nothing else.
// Dropping that pool, or relaxing verification, makes the second half succeed.
func TestWebSocketProxyKeepsTLSVerification(t *testing.T) {
	server := wsEchoServer(true)
	defer server.Close()
	proxy := newTunnelProxy(t)
	target := "wss" + strings.TrimPrefix(server.URL, "https") + "/stream"
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	trusting := wsBroker()
	trusting.Policy.Resolve = wsLoopback
	trusting.Policy.Upstream = &Upstream{Address: proxy.address, RootCAs: pool}
	socket, response, err := trusting.OpenWebSocket(ctx, target, nil, nil)
	if err != nil || response.Status != http.StatusSwitchingProtocols {
		t.Fatalf("a certificate in the upstream pool was refused: %+v %v", response, err)
	}
	socket.Close()
	unknowing := wsBroker()
	unknowing.Policy.Resolve = wsLoopback
	unknowing.Policy.Upstream = &Upstream{Address: proxy.address, RootCAs: x509.NewCertPool()}
	if _, _, err = unknowing.OpenWebSocket(ctx, target, nil, nil); err == nil {
		t.Fatal("a certificate outside the upstream pool was accepted")
	}
	if seen := proxy.seen(); len(seen) != 2 {
		t.Fatalf("the proxy tunnelled %v, so a half never reached a handshake", seen)
	}
}

// TestWebSocketWithoutProxyCAStaysDirect pins the no-skip-verify rule on the
// WebSocket path: an upstream with no CA pool is ignored and the pinned direct
// dial is used, the same fallback the HTTP path takes.
func TestWebSocketWithoutProxyCAStaysDirect(t *testing.T) {
	server := wsEchoServer(false)
	defer server.Close()
	proxy := newTunnelProxy(t)
	broker := wsBroker()
	broker.Policy.Resolve = wsLoopback
	broker.Policy.Upstream = &Upstream{Address: proxy.address}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	socket, response, err := broker.OpenWebSocket(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/stream", nil, nil)
	if err != nil || response.Status != http.StatusSwitchingProtocols {
		t.Fatalf("a CA-less upstream did not fall back to the direct path: %+v %v", response, err)
	}
	socket.Close()
	if seen := proxy.seen(); len(seen) != 0 {
		t.Fatalf("a CA-less upstream tunnelled %v", seen)
	}
}
