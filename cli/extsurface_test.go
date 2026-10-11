package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/webacquire"
)

// surfaceTestServer is a TLS origin that offers a legacy protocol, presents a certificate naming several hosts, reflects any origin it is given, admits TRACE, and serves one metadata path. It is the origin an external-surface sweep is meant to describe.
func surfaceTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "localhost", Organization: []string{"surface test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(72 * time.Hour),
		DNSNames:     []string{"localhost", "api.localhost", "*.staging.localhost", "cdn.other.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(surfaceTestHandler))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	return srv, port
}

// surfaceHTTPServer is the same origin over plain HTTP. The broker verifies certificates and offers no way to trust a test one, so the HTTP stages are exercised without TLS.
func surfaceHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(surfaceTestHandler))
	t.Cleanup(srv.Close)
	return srv
}

func surfaceTestHandler(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == "OPTIONS":
		w.Header().Set("Allow", "GET, HEAD, OPTIONS, TRACE")
		w.WriteHeader(204)
	case r.Method == "TRACE":
		w.Header().Set("Content-Type", "message/http")
		w.WriteHeader(200)
		fmt.Fprintf(w, "TRACE %s HTTP/1.1\r\nHost: %s\r\n\r\n", r.URL.Path, r.Host)
	case r.URL.Path == "/robots.txt":
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte("User-agent: *\n"))
	case r.URL.Path == "/":
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Server", "test-origin/1.0")
		h.Set("Content-Security-Policy", "default-src 'self' https://cdn.localhost")
		h.Add("Set-Cookie", "session=abc; Path=/")
		if o := r.Header.Get("Origin"); o != "" {
			h.Set("Access-Control-Allow-Origin", o)
			h.Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	default:
		w.WriteHeader(404)
	}
}

// surfaceDeps returns a sweep wired to a workspace and a broker that may reach only the loopback address.
func surfaceDeps(t *testing.T) (surfaceSweepDeps, *eng.Workspace) {
	t.Helper()
	ws, err := eng.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Close() })
	if _, err := ws.Store.Apply(eng.Delta{Kind: "fixture", Upserts: []eng.Task{
		{ID: "t1", Status: eng.StatusActive, Surface: eng.SurfaceWeb},
	}}); err != nil {
		t.Fatal(err)
	}
	broker := &webacquire.Broker{Policy: webacquire.Policy{
		Authorize: func(context.Context, webacquire.Request) error { return nil },
		IPAllowed: func(_ string, ip net.IP) bool { return ip.IsLoopback() },
		Resolve: func(_ context.Context, host string) ([]net.IP, error) {
			if strings.HasSuffix(host, "localhost") || host == "127.0.0.1" {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			return nil, errors.New("unknown host")
		},
	}}
	return surfaceSweepDeps{Broker: broker, Store: ws.Store}, ws
}

// Every HTTP observation class is recorded from one sweep of a plain-HTTP origin. The TLS classes need a TLS origin and have their own test, because the broker verifies certificates and a test certificate cannot be trusted.
func TestSweepExternalSurfaceRecordsEveryHTTPClass(t *testing.T) {
	srv := surfaceHTTPServer(t)
	d, ws := surfaceDeps(t)
	got, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: srv.URL, TaskID: "t1", Surface: eng.SurfaceWeb, Root: "localhost",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Stored == 0 {
		t.Fatalf("the sweep stored nothing: %+v", got)
	}
	if len(got.Ran) != len(allSurfaceProbes()) {
		t.Errorf("ran %v, want every probe", got.Ran)
	}
	ctx := context.Background()
	stats, err := ws.Store.SurfaceStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{
		"http-header", "http-cookie", "http-cors", "http-method", "http-path", "dns-name",
	} {
		if stats[kind] == 0 {
			t.Errorf("no %s record was stored: %v", kind, stats)
		}
	}
	// Every record cites its own persisted observation and the stage output it came from.
	all, err := ws.Store.Surfaces(ctx, eng.SurfaceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range all {
		if r.EvidenceID <= 0 {
			t.Errorf("%s/%s cites no evidence row", r.Kind, r.Name)
		}
		if r.TaskID != "t1" || r.Surface != eng.SurfaceWeb {
			t.Errorf("%s/%s is not attributed to the task: %+v", r.Kind, r.Name, r)
		}
		if r.Asset != "127.0.0.1" {
			t.Errorf("%s/%s names asset %q", r.Kind, r.Name, r.Asset)
		}
	}
	// The cited row contains the stored value even when the stage's larger quote was truncated.
	evidence, err := ws.Store.EvidenceRowsFor("t1")
	if err != nil {
		t.Fatal(err)
	}
	quotes := map[int64]string{}
	for _, row := range evidence {
		quotes[row.ID] = row.Quote
	}
	for _, r := range all {
		quote, ok := quotes[r.EvidenceID]
		if !ok {
			t.Errorf("%s/%s cites row %d, which does not exist", r.Kind, r.Name, r.EvidenceID)
			continue
		}
		// The label names what the stage probed: the asset, or the root for the derivation stage, which reads material from several origins.
		label, _, _ := strings.Cut(quote, "\n")
		if !strings.Contains(label, "127.0.0.1") && !strings.Contains(label, "localhost") {
			t.Errorf("%s/%s cites a row whose label names neither the asset nor the root: %q", r.Kind, r.Name, label)
		}
		if !strings.Contains(quote, "name="+r.Name) || !strings.Contains(quote, "value="+r.Value) ||
			!strings.Contains(quote, "source_evidence=") {
			t.Errorf("%s/%s cites a row without its observation or source: %q", r.Kind, r.Name, quote)
		}
	}
}

func TestSweepExternalSurfaceRecordsTheLegacyProtocol(t *testing.T) {
	_, port := surfaceTestServer(t)
	d, ws := surfaceDeps(t)
	if _, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: "https://localhost:" + port, TaskID: "t1", Surface: eng.SurfaceWeb,
		Probes: []surfaceProbe{probeTLS},
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	protocols, err := ws.Store.Surfaces(ctx, eng.SurfaceFilter{Kind: "tls-protocol"})
	if err != nil {
		t.Fatal(err)
	}
	if len(protocols) != 4 {
		t.Fatalf("stored %d protocol records, want one per probed version", len(protocols))
	}
	by := map[string]string{}
	for _, p := range protocols {
		by[p.Name] = p.Value
		if p.Gap == "" {
			t.Errorf("%s records no gap, but SSLv2 and SSLv3 were not probed", p.Name)
		}
	}
	for _, version := range []string{"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"} {
		if by[version] != "negotiated" {
			t.Errorf("%s = %q, want negotiated by a server offering 1.0 through 1.3", version, by[version])
		}
	}
	// The certificate is self-signed, so the record says so rather than valid.
	certs, err := ws.Store.Surfaces(ctx, eng.SurfaceFilter{Kind: "tls-certificate"})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("stored %d certificate records, want 1", len(certs))
	}
	if certs[0].Value != "self-signed" {
		t.Errorf("certificate value = %q, want self-signed", certs[0].Value)
	}
	if !strings.Contains(certs[0].Name, "surface test") {
		t.Errorf("certificate name = %q, want the subject", certs[0].Name)
	}
}

func TestSweepExternalSurfaceDerivesNamesOnlyFromCapturedMaterial(t *testing.T) {
	_, port := surfaceTestServer(t)
	d, ws := surfaceDeps(t)
	if _, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: "https://localhost:" + port, TaskID: "t1", Surface: eng.SurfaceWeb,
		Root: "localhost",
	}); err != nil {
		t.Fatal(err)
	}
	names, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{Kind: "dns-name"})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, n := range names {
		found[n.Name] = n.Value
	}
	// From the certificate's subject-alternative names.
	if found["api.localhost"] == "" {
		t.Errorf("api.localhost was not derived: %v", found)
	}
	if !strings.Contains(found["staging.localhost"], "wildcard") {
		t.Errorf("the wildcard name is not marked as one: %q", found["staging.localhost"])
	}
	// A certificate name outside the root is not attributed to it.
	if _, present := found["cdn.other.test"]; present {
		t.Error("a name outside the root was stored")
	}
	for name, source := range found {
		if !strings.HasPrefix(source, "certificate") {
			t.Errorf("%s names source %q, but only the TLS stage ran on this origin", name, source)
		}
	}
}

// A name a header disclosed is derived from the header, with the header named as its source.
func TestSweepExternalSurfaceDerivesNamesFromHeaders(t *testing.T) {
	srv := surfaceHTTPServer(t)
	d, ws := surfaceDeps(t)
	if _, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: srv.URL, TaskID: "t1", Surface: eng.SurfaceWeb, Root: "localhost",
	}); err != nil {
		t.Fatal(err)
	}
	names, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{Kind: "dns-name"})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, n := range names {
		found[n.Name] = n.Value
	}
	// The origin's Content-Security-Policy names it.
	if found["cdn.localhost"] != "header" {
		t.Errorf("cdn.localhost = %q, want it derived from the header: %v", found["cdn.localhost"], found)
	}
}

// An https origin whose certificate does not validate is still described: the TLS stage reports what it observed, and every HTTP stage records that it could not run rather than reporting an absence.
func TestSweepExternalSurfaceOnAnUntrustedCertificate(t *testing.T) {
	_, port := surfaceTestServer(t)
	d, ws := surfaceDeps(t)
	got, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: "https://localhost:" + port, TaskID: "t1", Surface: eng.SurfaceWeb,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	stats, err := ws.Store.SurfaceStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats["tls-protocol"] == 0 || stats["tls-certificate"] == 0 {
		t.Errorf("the TLS stage stored nothing: %v", stats)
	}
	for _, kind := range []string{"http-header", "http-cookie", "http-cors", "http-path"} {
		if stats[kind] != 0 {
			t.Errorf("%s records were stored though the origin's certificate does not validate", kind)
		}
	}
	joined := strings.Join(got.Gaps, " | ")
	for _, stage := range []string{"headers:", "cookies:", "cors:", "metadata:"} {
		if !strings.Contains(joined, stage) {
			t.Errorf("gaps %q do not report that %s could not run", joined, stage)
		}
	}
	certs, err := ws.Store.Surfaces(ctx, eng.SurfaceFilter{Kind: "tls-certificate"})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || certs[0].Gap == "" {
		t.Errorf("the certificate record does not carry the validation error: %+v", certs)
	}
}

func TestSweepExternalSurfaceRecordsTheCORSReflection(t *testing.T) {
	srv := surfaceHTTPServer(t)
	d, ws := surfaceDeps(t)
	if _, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: srv.URL, TaskID: "t1", Surface: eng.SurfaceWeb,
		Probes: []surfaceProbe{probeCORS},
	}); err != nil {
		t.Fatal(err)
	}
	cors, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{Kind: "http-cors"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cors) != 1 {
		t.Fatalf("stored %d CORS records, want 1", len(cors))
	}
	if cors[0].Value != "reflects a foreign origin with credentials" {
		t.Errorf("CORS value = %q, want the credentialed reflection", cors[0].Value)
	}
}

func TestSurfaceRecordsCiteTheirOwnObservationPastQuoteCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for i, name := range []string{
			"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
			"X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
			"Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
			"Cross-Origin-Resource-Policy", "Cache-Control",
		} {
			w.Header().Set(name, fmt.Sprintf("header-%d-%s", i, strings.Repeat("x", 480)))
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d, ws := surfaceDeps(t)
	if _, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: srv.URL, TaskID: "t1", Surface: eng.SurfaceWeb,
		Probes: []surfaceProbe{probeHeaders},
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{Kind: "http-header"})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ws.Store.EvidenceRowsFor("t1")
	if err != nil {
		t.Fatal(err)
	}
	quotes := map[int64]string{}
	for _, row := range evidence {
		quotes[row.ID] = row.Quote
	}
	for _, row := range rows {
		if row.Value == "absent" {
			continue
		}
		quote := quotes[row.EvidenceID]
		if !strings.Contains(quote, row.Name) || !strings.Contains(quote, row.Value) {
			t.Errorf("header %s cites evidence without its name and value", row.Name)
		}
	}
}

func TestSweepExternalSurfaceLabelsCredentialedNullOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d, ws := surfaceDeps(t)
	if _, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: srv.URL, TaskID: "t1", Surface: eng.SurfaceWeb,
		Probes: []surfaceProbe{probeCORS},
	}); err != nil {
		t.Fatal(err)
	}
	cors, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{Kind: "http-cors"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cors) != 1 || cors[0].Value != "allows the null origin with credentials" {
		t.Errorf("CORS records = %+v, want credentialed null-origin access", cors)
	}
}

func TestSweepExternalSurfaceRecordsTheMethodSurface(t *testing.T) {
	srv := surfaceHTTPServer(t)
	d, ws := surfaceDeps(t)
	if _, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: srv.URL, TaskID: "t1", Surface: eng.SurfaceWeb,
		Probes: []surfaceProbe{probeMethods},
	}); err != nil {
		t.Fatal(err)
	}
	methods, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{Kind: "http-method"})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]string{}
	for _, m := range methods {
		by[m.Name] = m.Value
	}
	if !strings.Contains(by["OPTIONS"], "TRACE") {
		t.Errorf("the Allow header was not recorded: %q", by["OPTIONS"])
	}
	if by["TRACE"] != "echoes the request" {
		t.Errorf("TRACE = %q, want the echo", by["TRACE"])
	}
}

func TestSweepExternalSurfaceRecordsTheMetadataCensus(t *testing.T) {
	srv := surfaceHTTPServer(t)
	d, ws := surfaceDeps(t)
	if _, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: srv.URL, TaskID: "t1", Surface: eng.SurfaceWeb,
		Probes: []surfaceProbe{probeMetadata},
	}); err != nil {
		t.Fatal(err)
	}
	paths, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{Kind: "http-path"})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != len(webacquire.MetadataPaths()) {
		t.Fatalf("stored %d path records, want one per swept path (%d)", len(paths), len(webacquire.MetadataPaths()))
	}
	by := map[string]string{}
	for _, p := range paths {
		by[p.Name] = p.Value
		if p.Gap != "" {
			t.Errorf("%s records a gap on an origin that answers 404 for a control: %q", p.Name, p.Gap)
		}
	}
	if !strings.Contains(by["/robots.txt"], "status 200") {
		t.Errorf("/robots.txt = %q, want status 200", by["/robots.txt"])
	}
	if !strings.Contains(by["/openapi.json"], "status 404") {
		t.Errorf("/openapi.json = %q, want status 404", by["/openapi.json"])
	}
}

// An origin that answers for every path cannot establish that a path exists, and every path record has to say so.
func TestSweepExternalSurfaceMarksASoftNotFoundOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d, ws := surfaceDeps(t)
	if _, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: srv.URL, TaskID: "t1", Surface: eng.SurfaceWeb,
		Probes: []surfaceProbe{probeMetadata},
	}); err != nil {
		t.Fatal(err)
	}
	paths, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{Kind: "http-path"})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no path record stored")
	}
	for _, p := range paths {
		if !strings.Contains(p.Gap, "does not establish that a path exists") {
			t.Errorf("%s does not state the soft-not-found result: %q", p.Name, p.Gap)
		}
	}
}

func TestSweepExternalSurfaceRecordsCookieWeakness(t *testing.T) {
	srv := surfaceHTTPServer(t)
	d, ws := surfaceDeps(t)
	if _, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: srv.URL, TaskID: "t1", Surface: eng.SurfaceWeb,
		Probes: []surfaceProbe{probeCookies},
	}); err != nil {
		t.Fatal(err)
	}
	cookies, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{Kind: "http-cookie"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 1 || cookies[0].Name != "session" {
		t.Fatalf("stored %+v, want the one session cookie", cookies)
	}
	for _, attr := range []string{"Secure", "HttpOnly", "SameSite"} {
		if !strings.Contains(cookies[0].Value, attr) {
			t.Errorf("value %q does not name the missing %s", cookies[0].Value, attr)
		}
	}
	// A cookie's value is a credential and must not be stored.
	if strings.Contains(cookies[0].Value, "abc") || strings.Contains(string(cookies[0].Detail), "abc") {
		t.Errorf("the cookie value was stored: %+v", cookies[0])
	}
}

func TestSweepExternalSurfaceRecordsBothSetAndAbsentHeaders(t *testing.T) {
	srv := surfaceHTTPServer(t)
	d, ws := surfaceDeps(t)
	if _, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: srv.URL, TaskID: "t1", Surface: eng.SurfaceWeb,
		Probes: []surfaceProbe{probeHeaders},
	}); err != nil {
		t.Fatal(err)
	}
	headers, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{Kind: "http-header"})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]string{}
	for _, h := range headers {
		by[h.Name] = h.Value
	}
	if by["Strict-Transport-Security"] != "max-age=31536000" {
		t.Errorf("HSTS = %q, want the value the origin set", by["Strict-Transport-Security"])
	}
	if by["X-Frame-Options"] != "absent" {
		t.Errorf("X-Frame-Options = %q, want absent", by["X-Frame-Options"])
	}
	if by["Server"] != "test-origin/1.0" {
		t.Errorf("Server = %q, want the disclosed software", by["Server"])
	}
}

// Re-sweeping the same origin updates the records in place, so an engagement's surface does not grow a duplicate set per pass.
func TestSweepExternalSurfaceIsIdempotent(t *testing.T) {
	_, port := surfaceTestServer(t)
	d, ws := surfaceDeps(t)
	req := surfaceSweepRequest{
		Origin: "https://localhost:" + port, TaskID: "t1", Surface: eng.SurfaceWeb, Root: "localhost",
	}
	first, err := sweepExternalSurface(context.Background(), d, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sweepExternalSurface(context.Background(), d, req); err != nil {
		t.Fatal(err)
	}
	all, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range all {
		if seen[r.ID] {
			t.Errorf("record %s appears twice", r.ID)
		}
		seen[r.ID] = true
	}
	if len(all) != len(seen) {
		t.Errorf("stored %d records with %d distinct ids", len(all), len(seen))
	}
	if first.Stored == 0 {
		t.Error("the first sweep stored nothing")
	}
}

// A stage that cannot run records its gap and the sweep continues, so one unreachable probe does not discard the rest.
func TestSweepExternalSurfaceContinuesPastAFailedProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "plain-http/1.0")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d, ws := surfaceDeps(t)
	got, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: srv.URL, TaskID: "t1", Surface: eng.SurfaceWeb,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The origin is plain HTTP, so the TLS stage has nothing to probe and says so.
	var tlsGap string
	for _, g := range got.Gaps {
		if strings.HasPrefix(g, "tls:") {
			tlsGap = g
		}
	}
	if !strings.Contains(tlsGap, "not https") {
		t.Errorf("gaps = %v, want the TLS stage to report the scheme", got.Gaps)
	}
	// The later stages still ran and stored records.
	headers, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{Kind: "http-header"})
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) == 0 {
		t.Error("the header stage did not run after the TLS stage reported a gap")
	}
	protocols, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{Kind: "tls-protocol"})
	if err != nil {
		t.Fatal(err)
	}
	if len(protocols) != 0 {
		t.Errorf("a TLS record was invented for a plain-HTTP origin: %+v", protocols)
	}
}

func TestSweepExternalSurfaceValidatesItsRequest(t *testing.T) {
	_, port := surfaceTestServer(t)
	d, _ := surfaceDeps(t)
	ctx := context.Background()
	for name, req := range map[string]surfaceSweepRequest{
		"no origin":      {TaskID: "t1", Surface: eng.SurfaceWeb},
		"bad origin":     {Origin: "not a url", TaskID: "t1", Surface: eng.SurfaceWeb},
		"ftp origin":     {Origin: "ftp://localhost/x", TaskID: "t1", Surface: eng.SurfaceWeb},
		"no task":        {Origin: "https://localhost:" + port, Surface: eng.SurfaceWeb},
		"unknown probe":  {Origin: "https://localhost:" + port, TaskID: "t1", Surface: eng.SurfaceWeb, Probes: []surfaceProbe{"made-up"}},
		"unknown surf":   {Origin: "https://localhost:" + port, TaskID: "t1", Surface: eng.Surface("nowhere")},
		"unknown taskid": {Origin: "https://localhost:" + port, TaskID: "absent", Surface: eng.SurfaceWeb},
	} {
		_, err := sweepExternalSurface(ctx, d, req)
		if err == nil {
			t.Errorf("%s was accepted", name)
			continue
		}
		if name == "no task" && !strings.Contains(err.Error(), "needs a task") {
			t.Errorf("a request with no task failed with %v, want the missing-task message", err)
		}
	}
	if _, err := sweepExternalSurface(ctx, surfaceSweepDeps{}, surfaceSweepRequest{
		Origin: "https://localhost:" + port, TaskID: "t1", Surface: eng.SurfaceWeb,
	}); err == nil {
		t.Error("a sweep ran with no broker or store")
	}
}

func TestSweepExternalSurfaceRunsOnlyTheSelectedProbes(t *testing.T) {
	_, port := surfaceTestServer(t)
	d, ws := surfaceDeps(t)
	got, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: "https://localhost:" + port, TaskID: "t1", Surface: eng.SurfaceWeb,
		Probes: []surfaceProbe{probeHeaders},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Ran) != 1 || got.Ran[0] != probeHeaders {
		t.Errorf("ran %v, want only the header probe", got.Ran)
	}
	stats, err := ws.Store.SurfaceStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for kind, n := range stats {
		if kind != "http-header" && n > 0 {
			t.Errorf("%s records were stored by a header-only sweep", kind)
		}
	}
}

// The subdomain stage reads only material the earlier stages captured, so running it alone derives nothing rather than querying for names.
func TestSweepExternalSurfaceSubdomainStageNeedsCapturedMaterial(t *testing.T) {
	_, port := surfaceTestServer(t)
	d, ws := surfaceDeps(t)
	got, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: "https://localhost:" + port, TaskID: "t1", Surface: eng.SurfaceWeb,
		Probes: []surfaceProbe{probeSubdomain},
	})
	if err != nil {
		t.Fatal(err)
	}
	names, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{Kind: "dns-name"})
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Errorf("names were derived with no captured material: %+v", names)
	}
	joined := strings.Join(got.Gaps, " ")
	if !strings.Contains(joined, "no captured material") {
		t.Errorf("gaps = %v, want the missing-material gap", got.Gaps)
	}
}

func TestSweepExternalSurfaceHonoursCancellation(t *testing.T) {
	_, port := surfaceTestServer(t)
	d, ws := surfaceDeps(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sweepExternalSurface(ctx, d, surfaceSweepRequest{
		Origin: "https://localhost:" + port, TaskID: "t1", Surface: eng.SurfaceWeb,
	}); err == nil {
		t.Error("a sweep ran under a cancelled context")
	}
	// No stage starts, so nothing is stored and no evidence row is written.
	all, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Errorf("a cancelled sweep stored %d records", len(all))
	}
	rows, err := ws.Store.EvidenceRowsFor("t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("a cancelled sweep wrote %d evidence rows", len(rows))
	}
}

func TestSurfaceRecordIDIsStableAndDistinguishing(t *testing.T) {
	a := surfaceRecordID("host", "http-header", "Server")
	if a != surfaceRecordID("host", "http-header", "Server") {
		t.Error("the id is not stable across calls")
	}
	for _, other := range []string{
		surfaceRecordID("other", "http-header", "Server"),
		surfaceRecordID("host", "http-path", "Server"),
		surfaceRecordID("host", "http-header", "Other"),
	} {
		if other == a {
			t.Errorf("two different observations share the id %q", a)
		}
	}
	if len(a) > 48 || !strings.HasPrefix(a, "surf:") {
		t.Errorf("id %q is not a bounded surf: id", a)
	}
}

func TestSurfaceOriginForReadsATarget(t *testing.T) {
	for target, want := range map[string]string{
		"example.com":                 "https://example.com",
		"https://example.com":         "https://example.com",
		"http://example.com:8080/app": "http://example.com:8080",
		"https://example.com/a/b?q=1": "https://example.com",
		"  example.com  ":             "https://example.com",
		"10.0.0.5":                    "https://10.0.0.5",
		"":                            "",
		"   ":                         "",
		"ftp://example.com":           "",
		"https://user:pw@example.com": "",
		"https://exa mple.com":        "",
		"https://example.com\r\nX: y": "",
	} {
		if got := surfaceOriginFor(target); got != want {
			t.Errorf("surfaceOriginFor(%q) = %q, want %q", target, got, want)
		}
	}
}

// A recon task naming a web origin is swept whoever created it.
func TestSweepQueueSweepsOnlyReconTasksNamingAnOrigin(t *testing.T) {
	srv := surfaceHTTPServer(t)
	for _, tc := range []struct {
		name  string
		task  eng.Task
		sweep bool
	}{
		{"web recon", eng.Task{ID: "t1", Surface: eng.SurfaceWeb, Phase: eng.PhaseRecon, Target: srv.URL}, true},
		{"web recon bare host", eng.Task{ID: "t1", Surface: eng.SurfaceWeb, Phase: eng.PhaseRecon, Target: "example.com"}, true},
		{"network recon with a url", eng.Task{ID: "t1", Surface: eng.SurfaceNetwork, Phase: eng.PhaseRecon, Target: srv.URL}, true},
		{"network recon host and port", eng.Task{ID: "t1", Surface: eng.SurfaceNetwork, Phase: eng.PhaseRecon, Target: "10.0.0.5:8080"}, false},
		{"web exploit", eng.Task{ID: "t1", Surface: eng.SurfaceWeb, Phase: eng.PhaseExploit, Target: srv.URL}, false},
		{"no target", eng.Task{ID: "t1", Surface: eng.SurfaceWeb, Phase: eng.PhaseRecon}, false},
		{"ftp target", eng.Task{ID: "t1", Surface: eng.SurfaceWeb, Phase: eng.PhaseRecon, Target: "ftp://example.com"}, false},
	} {
		if got := sweepableTask(tc.task) != ""; got != tc.sweep {
			t.Errorf("%s: sweepable = %v, want %v", tc.name, got, tc.sweep)
		}
	}
}

// The queue enqueues each task once and drains it once, so a reapplied state does not sweep again.
func TestSweepQueueEnqueuesEachTaskOnce(t *testing.T) {
	q := newSurfaceSweepQueue()
	state := eng.Engagement{Tasks: []eng.Task{
		{ID: "t1", Surface: eng.SurfaceWeb, Phase: eng.PhaseRecon, Target: "https://a.example.com"},
		{ID: "t2", Surface: eng.SurfaceWeb, Phase: eng.PhaseRecon, Target: "https://b.example.com"},
		{ID: "t3", Surface: eng.SurfaceNetwork, Phase: eng.PhaseRecon, Target: "10.0.0.5"},
	}}
	q.observe(1, state)
	q.observe(2, state)
	first := q.drain()
	if len(first) != 2 {
		t.Fatalf("drained %d sweeps, want one per web task: %+v", len(first), first)
	}
	seen := map[string]bool{}
	for _, r := range first {
		if seen[r.TaskID] {
			t.Errorf("task %s was enqueued twice", r.TaskID)
		}
		seen[r.TaskID] = true
		if r.Surface != eng.SurfaceWeb {
			t.Errorf("task %s carries surface %q", r.TaskID, r.Surface)
		}
	}
	q.observe(3, state)
	if again := q.drain(); len(again) != 0 {
		t.Errorf("a reapplied state re-enqueued %+v", again)
	}
}

// The per-round hook performs the queued sweeps and stores their records.
func TestRunPendingSurfaceSweepsStoresRecords(t *testing.T) {
	srv := surfaceHTTPServer(t)
	d, ws := surfaceDeps(t)
	q := newSurfaceSweepQueue()
	q.observe(1, eng.Engagement{Tasks: []eng.Task{
		{ID: "t1", Surface: eng.SurfaceWeb, Phase: eng.PhaseRecon, Target: srv.URL},
	}})
	if swept := runPendingSurfaceSweeps(context.Background(), d, q); swept != 1 {
		t.Fatalf("the hook performed %d sweeps, want 1", swept)
	}
	records, err := ws.Store.Surfaces(context.Background(), eng.SurfaceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) == 0 {
		t.Fatal("the hook stored nothing")
	}
	// The sweep is audited, so an engagement transcript records that it ran.
	page, err := ws.Store.Records(context.Background(), "audit", "", 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	var trail string
	for _, r := range page.Records {
		trail += string(r.Document)
	}
	if !strings.Contains(trail, "swept") || !strings.Contains(trail, "observations") {
		t.Errorf("the sweep was not audited:\n%s", trail)
	}
	if again := runPendingSurfaceSweeps(context.Background(), d, q); again != 0 {
		t.Errorf("the second round performed %d sweeps", again)
	}
}

// The hook is inert without its dependencies, so an engagement with no gate runs unchanged.
func TestRunPendingSurfaceSweepsIsInertWithoutDependencies(t *testing.T) {
	q := newSurfaceSweepQueue()
	q.observe(1, eng.Engagement{Tasks: []eng.Task{
		{ID: "t1", Surface: eng.SurfaceWeb, Phase: eng.PhaseRecon, Target: "https://example.com"},
	}})
	if n := runPendingSurfaceSweeps(context.Background(), surfaceSweepDeps{}, q); n != 0 {
		t.Errorf("the hook performed %d sweeps with no dependencies", n)
	}
	if n := runPendingSurfaceSweeps(context.Background(), surfaceSweepDeps{}, nil); n != 0 {
		t.Errorf("the hook performed %d sweeps with no queue", n)
	}
}

// A bare-host target yields a guessed https origin. When no TLS version is reachable there, the HTTP stages fall back to http so a plain-http service is described rather than reported as entirely unreachable.
func TestSweepFallsBackToHTTPWhenTheAssumedSchemeFails(t *testing.T) {
	srv := surfaceHTTPServer(t)
	host, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	d, ws := surfaceDeps(t)
	got, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: "https://" + net.JoinHostPort(host, port), TaskID: "t1",
		Surface: eng.SurfaceWeb, SchemeAssumed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Origin != "http://"+net.JoinHostPort(host, port) {
		t.Errorf("Origin = %q, want the http fallback", got.Origin)
	}
	if !strings.Contains(strings.Join(got.Gaps, " "), "the remaining stages used http://") {
		t.Errorf("gaps do not record the fallback: %v", got.Gaps)
	}
	stats, err := ws.Store.SurfaceStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"http-header", "http-cookie", "http-cors", "http-method", "http-path"} {
		if stats[kind] == 0 {
			t.Errorf("no %s record after the fallback: %v", kind, stats)
		}
	}
}

// An origin whose scheme the task named is not retried, so an https target that is simply down is reported as down rather than silently probed over http.
func TestSweepDoesNotFallBackForAnExplicitScheme(t *testing.T) {
	srv := surfaceHTTPServer(t)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	d, ws := surfaceDeps(t)
	got, err := sweepExternalSurface(context.Background(), d, surfaceSweepRequest{
		Origin: "https://" + net.JoinHostPort(host, port), TaskID: "t1", Surface: eng.SurfaceWeb,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Origin != "https://"+net.JoinHostPort(host, port) {
		t.Errorf("Origin = %q, want the origin as given", got.Origin)
	}
	stats, err := ws.Store.SurfaceStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats["http-header"] != 0 {
		t.Errorf("an explicit https origin was probed over http: %v", stats)
	}
}

// The queue marks a bare-host target as scheme-assumed and leaves an explicit one alone.
func TestSweepQueueMarksAnAssumedScheme(t *testing.T) {
	q := newSurfaceSweepQueue()
	q.observe(1, eng.Engagement{Tasks: []eng.Task{
		{ID: "bare", Surface: eng.SurfaceWeb, Phase: eng.PhaseRecon, Target: "example.com"},
		{ID: "explicit", Surface: eng.SurfaceWeb, Phase: eng.PhaseRecon, Target: "https://example.com"},
	}})
	for _, r := range q.drain() {
		if r.TaskID == "bare" && !r.SchemeAssumed {
			t.Error("a bare-host target was not marked scheme-assumed")
		}
		if r.TaskID == "explicit" && r.SchemeAssumed {
			t.Error("an explicit origin was marked scheme-assumed")
		}
	}
}
