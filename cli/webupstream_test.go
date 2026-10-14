package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/webacquire"
)

// proxyStandIn is a loopback stand-in for an intercepting proxy. It answers
// absolute-form requests itself and records what it was handed. It also counts
// requests to the endpoint Burp serves its CA on, which blk never fetches.
type proxyStandIn struct {
	server    *httptest.Server
	ca        []byte
	caFetches atomic.Int32
	mu        sync.Mutex
	requests  []string
}

func newProxyStandIn(t *testing.T) *proxyStandIn {
	t.Helper()
	p := &proxyStandIn{ca: testCACertificate(t)}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "burp" && r.URL.Path == "/cert" {
			p.caFetches.Add(1)
			_, _ = w.Write(p.ca)
			return
		}
		p.mu.Lock()
		p.requests = append(p.requests, r.Method+" "+r.Host+r.URL.Path)
		p.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>through the proxy</body></html>"))
	}))
	t.Cleanup(p.server.Close)
	return p
}

func (p *proxyStandIn) address() string { return strings.TrimPrefix(p.server.URL, "http://") }
func (p *proxyStandIn) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string{}, p.requests...)
}

// useProxyStandIn points the web stack at the stand-in and clears the per-address
// resolution so the test sees its own probe. A non-nil ca is written to a file
// named by webProxyCAEnv, the only source of the proxy's trust anchor.
func useProxyStandIn(t *testing.T, address string, ca []byte) {
	t.Helper()
	t.Setenv(webProxyEnv, address)
	if ca != nil {
		path := filepath.Join(t.TempDir(), "proxy-ca.der")
		if err := os.WriteFile(path, ca, 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(webProxyCAEnv, path)
	}
	forgetWebProxy(address)
	t.Cleanup(func() { forgetWebProxy(address) })
}

func forgetWebProxy(address string) {
	webProxyMu.Lock()
	delete(webProxyCache, address)
	webProxyMu.Unlock()
}

// captureProxyNotices redirects the fallback notices away from stderr.
func captureProxyNotices(t *testing.T) *[]string {
	t.Helper()
	var lines []string
	previous := webProxyNotice
	webProxyNotice = func(line string) { lines = append(lines, line) }
	t.Cleanup(func() { webProxyNotice = previous })
	return &lines
}

func testCACertificate(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "proxy stand-in CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(72 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestWebProxyAddressMustBeLoopback(t *testing.T) {
	for _, address := range []string{"", "127.0.0.1", "burp:8080", "0.0.0.0:8080", "203.0.113.7:8080", "127.0.0.1:0", "127.0.0.1:70000"} {
		if err := webProxyAddressAllowed(address); err == nil {
			t.Errorf("%q was accepted as a web proxy address", address)
		}
	}
	for _, address := range []string{"127.0.0.1:8080", "[::1]:9090"} {
		if err := webProxyAddressAllowed(address); err != nil {
			t.Errorf("%q was refused as a web proxy address: %v", address, err)
		}
	}
}

func TestWebProxyOffUsesTheDirectPath(t *testing.T) {
	proxy := newProxyStandIn(t)
	captureProxyNotices(t)
	t.Setenv(webProxyEnv, webProxyDisabledSetting)
	forgetWebProxy(proxy.address())
	if upstream := webUpstreamProxy(); upstream != nil {
		t.Fatalf("the opt-out still resolved a proxy: %+v", upstream)
	}
	if proxy.caFetches.Load() != 0 {
		t.Fatalf("the opt-out fetched the certificate %d times", proxy.caFetches.Load())
	}
}

func TestWebProxyUnreachableFallsBackToDirect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	notices := captureProxyNotices(t)
	useProxyStandIn(t, address, testCACertificate(t))
	if upstream := webUpstreamProxy(); upstream != nil {
		t.Fatalf("a closed port resolved a proxy: %+v", upstream)
	}
	if len(*notices) != 1 || !strings.Contains((*notices)[0], webProxyUnreachableLabel) {
		t.Fatalf("the fallback was not reported: %v", *notices)
	}
}

// TestWebProxyIsOffUnlessConfigured pins that no proxy is used, and none is
// probed, until the operator names one. A default address would hand engagement
// traffic to whatever local process listens on it, another account's included.
func TestWebProxyIsOffUnlessConfigured(t *testing.T) {
	notices := captureProxyNotices(t)
	t.Setenv(webProxyEnv, "")
	t.Setenv(webProxyCAEnv, "")
	if upstream := webUpstreamProxy(); upstream != nil {
		t.Fatalf("an unset proxy setting resolved a proxy: %+v", upstream)
	}
	if len(*notices) != 0 {
		t.Fatalf("an unset proxy setting produced notices: %v", *notices)
	}
	if probeLoopbackProxy(context.Background(), net.ParseIP("127.0.0.1"), 9) {
		t.Fatal("the service probe used a proxy the operator did not name")
	}
}

// TestWebProxyRequiresAnOperatorCertificate pins that a configured proxy is
// used only with a CA the operator supplied. The certificate is never fetched
// from the listener, because whatever is listening would then choose the trust
// anchor for every leaf it re-signs.
func TestWebProxyRequiresAnOperatorCertificate(t *testing.T) {
	proxy := newProxyStandIn(t)
	notices := captureProxyNotices(t)
	t.Setenv(webProxyCAEnv, "")
	useProxyStandIn(t, proxy.address(), nil)
	if upstream := webUpstreamProxy(); upstream != nil {
		t.Fatalf("a proxy with no operator CA resolved anyway: %+v", upstream)
	}
	if proxy.caFetches.Load() != 0 {
		t.Fatalf("the certificate endpoint was asked %d times", proxy.caFetches.Load())
	}
	if len(*notices) != 1 || !strings.Contains((*notices)[0], webProxyCAEnv) {
		t.Fatalf("the fallback did not name %s: %v", webProxyCAEnv, *notices)
	}
}

// TestWebProxyResolvesOncePerProcess pins the cache: the proxy is probed and
// its CA read on the first resolution and reused afterwards.
func TestWebProxyResolvesOncePerProcess(t *testing.T) {
	proxy := newProxyStandIn(t)
	captureProxyNotices(t)
	useProxyStandIn(t, proxy.address(), proxy.ca)
	upstream := webUpstreamProxy()
	if upstream == nil || upstream.Address != proxy.address() || upstream.RootCAs == nil {
		t.Fatalf("a reachable proxy did not resolve: %+v", upstream)
	}
	if again := webUpstreamProxy(); again != upstream {
		t.Fatalf("the resolution was repeated: %+v then %+v", upstream, again)
	}
	if proxy.caFetches.Load() != 0 {
		t.Fatalf("the certificate endpoint was asked %d times", proxy.caFetches.Load())
	}
}

// TestWebProxyReportsTheAddressAndCAItAccepted pins that the decision to proxy
// is visible. Without the notice blk proxies or goes direct in silence, and the
// trust anchor it took from an unauthenticated listener is never named.
func TestWebProxyReportsTheAddressAndCAItAccepted(t *testing.T) {
	proxy := newProxyStandIn(t)
	notices := captureProxyNotices(t)
	useProxyStandIn(t, proxy.address(), proxy.ca)
	if upstream := webUpstreamProxy(); upstream == nil {
		t.Fatal("a reachable proxy did not resolve")
	}
	if len(*notices) != 1 {
		t.Fatalf("the proxy decision produced %d notices: %v", len(*notices), *notices)
	}
	line := (*notices)[0]
	if !strings.Contains(line, proxy.address()) || !strings.Contains(line, webProxyInUseLabel) || !strings.Contains(line, "proxy stand-in CA") {
		t.Fatalf("the notice names neither the address nor the CA subject: %q", line)
	}
	_ = webUpstreamProxy()
	if len(*notices) != 1 {
		t.Fatalf("the notice repeated per resolution: %v", *notices)
	}
}

// TestWebProxySubjectStaysOneBoundedLine pins that a subject from the listening
// process cannot break the notice into more lines or grow without bound.
func TestWebProxySubjectStaysOneBoundedLine(t *testing.T) {
	got := webProxySubject("CN=proxy\r\nblk: web proxy 127.0.0.1:1 carrying\x07" + strings.Repeat("x", 400))
	if strings.ContainsAny(got, "\r\n\x07") || len(got) > webProxySubjectMaxRunes {
		t.Fatalf("the subject was not clamped: %q", got)
	}
	if subject := webProxySubject("   "); subject != "unnamed" {
		t.Fatalf("an empty subject rendered as %q", subject)
	}
}

func TestWebProxyReadsAnOperatorSuppliedCertificate(t *testing.T) {
	proxy := newProxyStandIn(t)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.ca}), 0600); err != nil {
		t.Fatal(err)
	}
	captureProxyNotices(t)
	t.Setenv(webProxyCAEnv, path)
	useProxyStandIn(t, proxy.address(), nil)
	upstream := webUpstreamProxy()
	if upstream == nil || upstream.RootCAs == nil {
		t.Fatalf("an operator-supplied CA did not resolve: %+v", upstream)
	}
	if proxy.caFetches.Load() != 0 {
		t.Fatalf("the certificate endpoint was asked %d times despite %s", proxy.caFetches.Load(), webProxyCAEnv)
	}
}

// TestWebBrokerCarriesEngagementRequestsThroughTheProxy pins that the broker the
// engage web stack builds routes an in-scope request through the proxy, and that
// an out-of-scope target is refused before the proxy sees anything.
func TestWebBrokerCarriesEngagementRequestsThroughTheProxy(t *testing.T) {
	var direct atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		direct.Add(1)
		_, _ = w.Write([]byte("direct"))
	}))
	defer target.Close()
	proxy := newProxyStandIn(t)
	captureProxyNotices(t)
	useProxyStandIn(t, proxy.address(), proxy.ca)
	scope, err := secgate.ParseScope(strings.NewReader("127.0.0.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	gate := &secgate.Gate{Mode: secgate.Auto, Scope: scope, Policy: secgate.DefaultPolicy()}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	broker := newWebBroker(gate, nil)
	if broker.Policy.Upstream == nil {
		t.Fatal("the engagement broker did not pick up the proxy")
	}
	out, err := broker.Fetch(context.Background(), webacquire.Request{URL: target.URL + "/page"})
	if err != nil || !strings.Contains(string(out.Body), "through the proxy") {
		t.Fatalf("the in-scope request did not traverse the proxy: %+v %v", out, err)
	}
	if direct.Load() != 0 {
		t.Fatalf("%d requests bypassed the proxy", direct.Load())
	}
	if seen := proxy.seen(); len(seen) != 1 || !strings.HasSuffix(seen[0], "/page") {
		t.Fatalf("the proxy recorded %v", seen)
	}
	if _, err := broker.Fetch(context.Background(), webacquire.Request{URL: "http://203.0.113.7/page"}); err == nil {
		t.Fatal("an out-of-scope target was accepted under a proxy")
	}
	if seen := proxy.seen(); len(seen) != 1 {
		t.Fatalf("the proxy recorded an out-of-scope request: %v", seen)
	}
}

// TestWebBrokerKeepsTheDirectPathWhenProxyingIsOff pins that the opt-out leaves
// the pinned direct dial in place.
func TestWebBrokerKeepsTheDirectPathWhenProxyingIsOff(t *testing.T) {
	var direct atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		direct.Add(1)
		_, _ = w.Write([]byte("direct"))
	}))
	defer target.Close()
	proxy := newProxyStandIn(t)
	captureProxyNotices(t)
	t.Setenv(webProxyEnv, webProxyDisabledSetting)
	scope, err := secgate.ParseScope(strings.NewReader("127.0.0.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	gate := &secgate.Gate{Mode: secgate.Auto, Scope: scope, Policy: secgate.DefaultPolicy()}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	broker := newWebBroker(gate, nil)
	if broker.Policy.Upstream != nil {
		t.Fatalf("the opt-out left a proxy on the engagement broker: %+v", broker.Policy.Upstream)
	}
	out, err := broker.Fetch(context.Background(), webacquire.Request{URL: target.URL})
	if err != nil || string(out.Body) != "direct" || direct.Load() != 1 {
		t.Fatalf("the direct path changed: %+v %v", out, err)
	}
	if seen := proxy.seen(); len(seen) != 0 {
		t.Fatalf("the proxy recorded %v with proxying off", seen)
	}
}

// TestEngageWebCollectTraversesTheProxy drives the engage web collect entry
// point so the proxy decision is proven where the stack actually runs, not only
// on a broker built by hand.
func TestEngageWebCollectTraversesTheProxy(t *testing.T) {
	proxy := newProxyStandIn(t)
	captureProxyNotices(t)
	useProxyStandIn(t, proxy.address(), proxy.ca)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>never reached directly</body></html>"))
	}))
	defer target.Close()
	roePath := filepath.Join(t.TempDir(), "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := webExecute(context.Background(), []string{"collect", target.URL, "--workspace", t.TempDir(), "--roe", roePath, "--transcript", "off", "--no-rdns"}, secgate.Auto, nil, false, 90); err != nil {
		t.Fatal(err)
	}
	seen := proxy.seen()
	if len(seen) == 0 {
		t.Fatal("engage web collect sent nothing through the proxy")
	}
	host := strings.TrimPrefix(target.URL, "http://")
	for _, request := range seen {
		if !strings.Contains(request, host) {
			t.Errorf("the proxy was handed %q, which is not the collected host %q", request, host)
		}
	}
}
