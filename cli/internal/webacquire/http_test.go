package webacquire

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixtureBroker() *Broker {
	return &Broker{Policy: Policy{Authorize: func(context.Context, Request) error { return nil }, IPAllowed: func(_ string, ip net.IP) bool { return ip.IsLoopback() }}}
}
func TestPinnedResolutionAndRedirectCredentials(t *testing.T) {
	leaked := false
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") != ""
		w.Write([]byte("body"))
	}))
	defer dst.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, dst.URL, http.StatusFound) }))
	defer src.Close()
	b := fixtureBroker()
	out, e := b.Fetch(context.Background(), Request{Method: "GET", URL: src.URL, Headers: http.Header{"Authorization": []string{"test-only"}}})
	if e != nil || string(out.Body) != "body" || leaked {
		t.Fatalf("redirect policy: %v complete=%v leaked=%v", e, out.Complete, leaked)
	}
	b.Policy.Resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("8.8.8.8")}, nil
	}
	if _, e = b.Fetch(context.Background(), Request{Method: "GET", URL: src.URL}); e == nil {
		t.Fatal("mixed DNS accepted")
	}
}

func TestPinnedRequestChecksHostnameWithAddress(t *testing.T) {
	var reached atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://evil.example.test"+r.URL.RequestURI(), http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("authorized"))
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Host = net.JoinHostPort("api.example.test", u.Port())
	broker := fixtureBroker()
	broker.Policy.Resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	broker.Policy.IPAllowed = func(host string, ip net.IP) bool {
		return host == "api.example.test" && ip.IsLoopback()
	}
	if out, err := broker.Fetch(context.Background(), Request{URL: u.String() + "/ok"}); err != nil || string(out.Body) != "authorized" {
		t.Fatalf("authorized hostname failed: %+v %v", out, err)
	}
	if _, err := broker.Fetch(context.Background(), Request{URL: u.String() + "/redirect"}); err == nil || reached.Load() != 2 {
		t.Fatalf("redirect to another hostname at the same IP was accepted: requests=%d err=%v", reached.Load(), err)
	}
}

func TestCustomDialRunsOnlyAfterScopeCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("pivoted"))
	}))
	defer server.Close()
	broker := fixtureBroker()
	broker.Policy.Resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	var dials atomic.Int32
	broker.Policy.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	broker.Policy.IPAllowed = func(string, net.IP) bool { return false }
	if _, err := broker.Fetch(context.Background(), Request{URL: server.URL}); err == nil || dials.Load() != 0 {
		t.Fatalf("out-of-scope request reached custom dial: dials=%d err=%v", dials.Load(), err)
	}
	broker.Policy.IPAllowed = func(string, net.IP) bool { return true }
	response, err := broker.Fetch(context.Background(), Request{URL: server.URL})
	if err != nil || !response.Complete || string(response.Body) != "pivoted" || dials.Load() != 1 {
		t.Fatalf("scoped custom dial failed: response=%+v dials=%d err=%v", response, dials.Load(), err)
	}
}
func TestCompressedBombCancellationAndBudget(t *testing.T) {
	var z bytes.Buffer
	gz := gzip.NewWriter(&z)
	gz.Write(bytes.Repeat([]byte("x"), MaxBody+1))
	gz.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(z.Bytes())
	}))
	defer s.Close()
	b := fixtureBroker()
	o, e := b.Fetch(context.Background(), Request{Method: "GET", URL: s.URL})
	if e == nil || o.Complete || !strings.Contains(o.Gap, "decompressed") {
		t.Fatal("bomb accepted")
	}
	ctx, c := context.WithCancel(context.Background())
	c()
	if _, e = b.Fetch(ctx, Request{Method: "GET", URL: s.URL}); e == nil {
		t.Fatal("cancellation ignored")
	}
	b.requests = MaxRequests
	if _, e = b.Fetch(context.Background(), Request{Method: "GET", URL: s.URL}); e == nil {
		t.Fatal("budget ignored")
	}
}
func TestURLBoundary(t *testing.T) {
	for _, s := range []string{"file:///tmp/a", "http://a@127.0.0.1/", "http://host\n/x", "http://host%2f.evil/"} {
		if _, e := URL(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}

func TestDiscardedTransfersConsumeAggregateBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "unsupported")
		w.Write([]byte("discarded"))
	}))
	defer server.Close()
	b := fixtureBroker()
	b.wireBytes = MaxTotal - 3
	if _, e := b.Fetch(context.Background(), Request{URL: server.URL}); e == nil {
		t.Fatal("oversized aggregate transfer accepted")
	}
	if b.wireBytes != MaxTotal {
		t.Fatal(b.wireBytes)
	}
	if _, e := b.Fetch(context.Background(), Request{URL: server.URL}); e == nil {
		t.Fatal("discarded transfer did not exhaust budget")
	}
}

func TestPolicySpecificWebBodyAndRequestCaps(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("123456789"))
	}))
	defer server.Close()
	broker := fixtureBroker()
	broker.Policy.MaxBodyBytes = 8
	broker.Policy.MaxTotalBytes = 8
	if _, err := broker.Fetch(context.Background(), Request{Method: "POST", URL: server.URL, Body: []byte("123456789")}); err == nil || requests.Load() != 0 {
		t.Fatalf("oversized request reached target: requests=%d err=%v", requests.Load(), err)
	}
	if response, err := broker.Fetch(context.Background(), Request{URL: server.URL}); err == nil || response.Complete || requests.Load() != 1 {
		t.Fatalf("oversized response accepted: %+v requests=%d err=%v", response, requests.Load(), err)
	}
}

// upstreamFixture stands in for an intercepting proxy on loopback. It answers
// absolute-form requests itself and records what it was handed, so a test can
// tell a proxied request from a direct one and compare the exact headers that
// crossed the wire.
type upstreamFixture struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests []http.Header
	hosts    []string
}

func newUpstreamFixture(t *testing.T) *upstreamFixture {
	t.Helper()
	f := &upstreamFixture{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Header.Clone())
		f.hosts = append(f.hosts, r.Host)
		f.mu.Unlock()
		_, _ = w.Write([]byte("through the proxy"))
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *upstreamFixture) address() string { return strings.TrimPrefix(f.server.URL, "http://") }
func (f *upstreamFixture) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// TestUpstreamProxyKeepsTheScopeCheck pins that the resolved-address check runs
// before any byte leaves, whether or not a proxy carries the request. Removing
// the IPAllowed loop in Once lets the proxy see the request and fails this.
func TestUpstreamProxyKeepsTheScopeCheck(t *testing.T) {
	proxy := newUpstreamFixture(t)
	broker := fixtureBroker()
	broker.Policy.Upstream = &Upstream{Address: proxy.address(), RootCAs: x509.NewCertPool()}
	broker.Policy.Resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.7")}, nil
	}
	out, err := broker.Fetch(context.Background(), Request{URL: "http://app.example.test/"})
	if err == nil || !strings.Contains(err.Error(), "outside scope") {
		t.Fatalf("out-of-scope host accepted under a proxy: %+v %v", out, err)
	}
	if proxy.count() != 0 {
		t.Fatalf("the proxy saw %d out-of-scope requests", proxy.count())
	}
}

// TestUpstreamProxyCarriesRequestsUnaltered pins that a proxied request reaches
// the proxy in absolute form with the target host, and that its headers are the
// ones the direct path sends. No correlation header, tracer value or altered
// user-agent is added, because that would make the measurement describe the
// instrument instead of the target.
func TestUpstreamProxyCarriesRequestsUnaltered(t *testing.T) {
	var direct http.Header
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		direct = r.Header.Clone()
		_, _ = w.Write([]byte("direct"))
	}))
	defer target.Close()
	broker := fixtureBroker()
	if out, err := broker.Fetch(context.Background(), Request{URL: target.URL + "/page"}); err != nil || string(out.Body) != "direct" {
		t.Fatalf("direct fetch failed: %+v %v", out, err)
	}
	proxy := newUpstreamFixture(t)
	broker = fixtureBroker()
	broker.Policy.Upstream = &Upstream{Address: proxy.address(), RootCAs: x509.NewCertPool()}
	out, err := broker.Fetch(context.Background(), Request{URL: target.URL + "/page"})
	if err != nil || string(out.Body) != "through the proxy" {
		t.Fatalf("proxied fetch failed: %+v %v", out, err)
	}
	if proxy.count() != 1 {
		t.Fatalf("the proxy saw %d requests", proxy.count())
	}
	host := strings.TrimPrefix(target.URL, "http://")
	if proxy.hosts[0] != host {
		t.Fatalf("the proxy was handed host %q, want %q", proxy.hosts[0], host)
	}
	// Connection and Proxy-Connection are per-hop, so they differ by design.
	hop := map[string]bool{"Connection": true, "Proxy-Connection": true}
	for name, values := range proxy.requests[0] {
		if hop[name] {
			continue
		}
		if got := strings.Join(direct.Values(name), ","); got != strings.Join(values, ",") {
			t.Errorf("proxied header %s is %q, direct sends %q", name, strings.Join(values, ","), got)
		}
	}
	for name := range direct {
		if !hop[name] && proxy.requests[0].Get(name) == "" {
			t.Errorf("proxied request dropped header %s", name)
		}
	}
}

// TestUpstreamProxyWithoutRootCAsStaysDirect pins the no-skip-verify rule: an
// upstream with no CA pool cannot have its re-signed leaves verified, so the
// broker takes the direct path instead of relaxing verification. Dropping the
// RootCAs condition in Once routes the request to the proxy and fails this.
func TestUpstreamProxyWithoutRootCAsStaysDirect(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		_, _ = w.Write([]byte("direct"))
	}))
	defer target.Close()
	proxy := newUpstreamFixture(t)
	broker := fixtureBroker()
	broker.Policy.Upstream = &Upstream{Address: proxy.address()}
	out, err := broker.Fetch(context.Background(), Request{URL: target.URL})
	if err != nil || string(out.Body) != "direct" || reached.Load() != 1 {
		t.Fatalf("a CA-less upstream did not fall back to the direct path: %+v %v", out, err)
	}
	if proxy.count() != 0 {
		t.Fatalf("a CA-less upstream carried %d requests", proxy.count())
	}
}

// resigningProxy stands in for an intercepting proxy that re-signs leaves. It
// answers CONNECT, completes the TLS handshake with a leaf its own CA issued for
// the tunnelled host, and serves one plain response over the tunnel.
type resigningProxy struct {
	address  string
	pool     *x509.CertPool
	connects atomic.Int32
}

func newResigningProxy(t *testing.T, host string) *resigningProxy {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "resigning proxy CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf := tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	p := &resigningProxy{address: listener.Addr().String(), pool: pool}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go p.serve(conn, leaf)
		}
	}()
	return p
}

func (p *resigningProxy) serve(conn net.Conn, leaf tls.Certificate) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	request, err := http.ReadRequest(bufio.NewReaderSize(conn, 4096))
	if err != nil || request.Method != http.MethodConnect {
		return
	}
	p.connects.Add(1)
	if _, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	tunnel := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{leaf}})
	if err = tunnel.Handshake(); err != nil {
		return
	}
	defer tunnel.Close()
	if _, err = http.ReadRequest(bufio.NewReaderSize(tunnel, 4096)); err != nil {
		return
	}
	_, _ = io.WriteString(tunnel, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 17\r\n\r\nthrough the proxy")
}

// TestUpstreamProxyVerifiesTheResignedLeaf pins that TLS verification stays on
// under a proxy. The stand-in answers CONNECT and hands back a leaf its own CA
// signed, so both halves reach a real handshake: the fetch succeeds when the
// configured pool holds that CA and fails when it does not. Relaxing
// verification in the upstream branch makes the second half succeed and fails
// this test.
func TestUpstreamProxyVerifiesTheResignedLeaf(t *testing.T) {
	const host = "app.example.test"
	proxy := newResigningProxy(t, host)
	loopback := func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	trusting := fixtureBroker()
	trusting.Policy.Resolve = loopback
	trusting.Policy.Upstream = &Upstream{Address: proxy.address, RootCAs: proxy.pool}
	out, err := trusting.Fetch(context.Background(), Request{URL: "https://" + host + "/"})
	if err != nil || string(out.Body) != "through the proxy" {
		t.Fatalf("a leaf the configured CA signed was refused: %+v %v", out, err)
	}
	unknowing := fixtureBroker()
	unknowing.Policy.Resolve = loopback
	unknowing.Policy.Upstream = &Upstream{Address: proxy.address, RootCAs: x509.NewCertPool()}
	if out, err := unknowing.Fetch(context.Background(), Request{URL: "https://" + host + "/"}); err == nil {
		t.Fatalf("a leaf signed outside the configured pool was accepted: %+v", out)
	}
	if proxy.connects.Load() != 2 {
		t.Fatalf("the proxy tunnelled %d requests, so a half never reached a handshake", proxy.connects.Load())
	}
}
