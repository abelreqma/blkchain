package webacquire

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// testCert issues a self-signed leaf for names, valid over the given window.
func testCert(t *testing.T, names []string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: names[0], Organization: []string{"blkChain test"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     names,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsServer starts a TLS listener that accepts only the given version range and returns its port.
func tlsServer(t *testing.T, cert tls.Certificate, minVer, maxVer uint16) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: minVer, MaxVersion: maxVer,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = conn.(*tls.Conn).Handshake()
				conn.Close()
			}()
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// probeBroker returns a broker whose policy allows only 127.0.0.1.
func probeBroker() *Broker {
	return &Broker{Policy: Policy{
		Authorize: func(context.Context, Request) error { return nil },
		IPAllowed: func(_ string, ip net.IP) bool { return ip.IsLoopback() },
		Resolve: func(_ context.Context, host string) ([]net.IP, error) {
			if host == "localhost" {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			return nil, errors.New("unknown host")
		},
	}}
}

func TestProbeTLSReportsALegacyOnlyServer(t *testing.T) {
	cert := testCert(t, []string{"localhost"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	port := tlsServer(t, cert, tls.VersionTLS10, tls.VersionTLS11)
	got, err := probeBroker().ProbeTLS(context.Background(), "localhost", port)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Negotiated("TLSv1.0") || !got.Negotiated("TLSv1.1") {
		t.Errorf("legacy versions not observed: %+v", got.Protocols)
	}
	if got.Negotiated("TLSv1.2") || got.Negotiated("TLSv1.3") {
		t.Errorf("a version the server does not offer was reported: %v", got.Protocols)
	}
	legacy := got.LegacyProtocols()
	if len(legacy) != 2 {
		t.Errorf("LegacyProtocols = %v, want both legacy versions", legacy)
	}
	if len(got.Refused) != 2 {
		t.Errorf("Refused = %v, want the two modern versions", got.Refused)
	}
	if got.Ciphers["TLSv1.0"] == "" {
		t.Error("no cipher recorded for the negotiated TLSv1.0 handshake")
	}
}

func TestProbeTLSReportsAModernOnlyServer(t *testing.T) {
	cert := testCert(t, []string{"localhost"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	port := tlsServer(t, cert, tls.VersionTLS12, tls.VersionTLS13)
	got, err := probeBroker().ProbeTLS(context.Background(), "localhost", port)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.LegacyProtocols()) != 0 {
		t.Errorf("a modern-only server reported legacy versions: %v", got.LegacyProtocols())
	}
	if !got.Negotiated("TLSv1.2") || !got.Negotiated("TLSv1.3") {
		t.Errorf("modern versions not observed: %v", got.Protocols)
	}
	// The absence of SSLv2 and SSLv3 is a limit of the probe, not a result, so it has to be stated.
	if !strings.Contains(got.Gap, "SSLv2 and SSLv3 were not probed") {
		t.Errorf("Gap does not state the unprobed versions: %q", got.Gap)
	}
}

func TestProbeTLSValidatesTheCertificate(t *testing.T) {
	now := time.Now()
	for name, tc := range map[string]struct {
		names               []string
		notBefore, notAfter time.Time
		host                string
		wantHostname        bool
		wantExpired         bool
		wantNotYetValid     bool
	}{
		"matching name": {[]string{"localhost"}, now.Add(-time.Hour), now.Add(time.Hour), "localhost", true, false, false},
		"wrong name":    {[]string{"other.example"}, now.Add(-time.Hour), now.Add(time.Hour), "localhost", false, false, false},
		"expired":       {[]string{"localhost"}, now.Add(-48 * time.Hour), now.Add(-time.Hour), "localhost", true, true, false},
		"not yet valid": {[]string{"localhost"}, now.Add(time.Hour), now.Add(48 * time.Hour), "localhost", true, false, true},
	} {
		cert := testCert(t, tc.names, tc.notBefore, tc.notAfter)
		port := tlsServer(t, cert, tls.VersionTLS12, tls.VersionTLS13)
		got, err := probeBroker().ProbeTLS(context.Background(), tc.host, port)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.HostnameMatches != tc.wantHostname {
			t.Errorf("%s: HostnameMatches = %v, want %v", name, got.HostnameMatches, tc.wantHostname)
		}
		if got.Expired != tc.wantExpired {
			t.Errorf("%s: Expired = %v, want %v", name, got.Expired, tc.wantExpired)
		}
		if got.NotYetValid != tc.wantNotYetValid {
			t.Errorf("%s: NotYetValid = %v, want %v", name, got.NotYetValid, tc.wantNotYetValid)
		}
		// Every certificate here is self-signed, so none can be chain-trusted and every one must say why.
		if !got.SelfSigned {
			t.Errorf("%s: a self-signed leaf was not reported as one", name)
		}
		if got.ChainTrusted {
			t.Errorf("%s: an untrusted chain was reported as trusted", name)
		}
		if got.ValidationError == "" {
			t.Errorf("%s: no validation error recorded for an untrusted chain", name)
		}
	}
}

func TestProbeTLSRecordsTheCertificateFacts(t *testing.T) {
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	cert := testCert(t, []string{"localhost", "alt.localhost"}, notBefore, notAfter)
	port := tlsServer(t, cert, tls.VersionTLS12, tls.VersionTLS13)
	got, err := probeBroker().ProbeTLS(context.Background(), "localhost", port)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.DNSNames) != 2 || got.DNSNames[0] != "alt.localhost" || got.DNSNames[1] != "localhost" {
		t.Errorf("DNSNames = %v, want both names sorted", got.DNSNames)
	}
	if len(got.IPAddresses) != 1 || got.IPAddresses[0] != "127.0.0.1" {
		t.Errorf("IPAddresses = %v, want the certificate's address", got.IPAddresses)
	}
	if got.NotAfter != notAfter.UTC().Format(time.RFC3339) {
		t.Errorf("NotAfter = %q, want %q", got.NotAfter, notAfter.UTC().Format(time.RFC3339))
	}
	if got.NotBefore != notBefore.UTC().Format(time.RFC3339) {
		t.Errorf("NotBefore = %q, want %q", got.NotBefore, notBefore.UTC().Format(time.RFC3339))
	}
	if got.KeyAlgorithm != "RSA" || got.KeyBits != 2048 {
		t.Errorf("key = %s/%d, want RSA/2048", got.KeyAlgorithm, got.KeyBits)
	}
	if got.SerialNumber != "4242" {
		t.Errorf("SerialNumber = %q, want 4242", got.SerialNumber)
	}
	if !strings.Contains(got.Subject, "blkChain test") {
		t.Errorf("Subject = %q, want the certificate's organization", got.Subject)
	}
	if got.SignatureAlgorithm == "" {
		t.Error("no signature algorithm recorded")
	}
	if got.ChainLength != 1 {
		t.Errorf("ChainLength = %d, want 1", got.ChainLength)
	}
}

func TestProbeTLSRecordsAnECDSAKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	port := tlsServer(t, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		tls.VersionTLS12, tls.VersionTLS13)
	got, err := probeBroker().ProbeTLS(context.Background(), "localhost", port)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyAlgorithm != "ECDSA" || got.KeyBits != 384 {
		t.Errorf("key = %s/%d, want ECDSA/384", got.KeyAlgorithm, got.KeyBits)
	}
}

// The probe is a network action, so it goes through the same scope controls as a fetch and must fail closed when any of them refuses.
func TestProbeTLSEnforcesTheScopeControls(t *testing.T) {
	cert := testCert(t, []string{"localhost"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	port := tlsServer(t, cert, tls.VersionTLS12, tls.VersionTLS13)

	denied := probeBroker()
	denied.Policy.Authorize = func(context.Context, Request) error { return errors.New("out of scope") }
	if _, err := denied.ProbeTLS(context.Background(), "localhost", port); err == nil {
		t.Error("a probe the policy refused was performed")
	}

	offScope := probeBroker()
	offScope.Policy.IPAllowed = func(string, net.IP) bool { return false }
	if _, err := offScope.ProbeTLS(context.Background(), "localhost", port); err == nil {
		t.Error("a probe of an out-of-scope address was performed")
	}

	unresolvable := probeBroker()
	if _, err := unresolvable.ProbeTLS(context.Background(), "nowhere.invalid", port); err == nil {
		t.Error("a probe of an unresolvable host was performed")
	}

	noPolicy := &Broker{}
	if _, err := noPolicy.ProbeTLS(context.Background(), "localhost", port); err == nil {
		t.Error("a probe ran with no policy at all")
	}
}

// The probe must authorize the host and port it will actually connect to, so an operator policy that reads the URL sees the real destination.
func TestProbeTLSAuthorizesTheRealDestination(t *testing.T) {
	cert := testCert(t, []string{"localhost"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	port := tlsServer(t, cert, tls.VersionTLS12, tls.VersionTLS13)
	var seen string
	b := probeBroker()
	b.Policy.Authorize = func(_ context.Context, r Request) error {
		seen = r.URL
		return nil
	}
	if _, err := b.ProbeTLS(context.Background(), "localhost", port); err != nil {
		t.Fatal(err)
	}
	if want := "https://localhost:" + port; seen != want {
		t.Errorf("authorized %q, want %q", seen, want)
	}
}

// A malformed host or port must be refused before anything is authorized or dialed. The policy is a counter here as well as a gate: a host carrying a CRLF would otherwise reach Authorize inside the URL it builds.
func TestProbeTLSRejectsABadHostOrPort(t *testing.T) {
	for _, tc := range []struct{ host, port string }{
		{"", "443"},
		{"localhost\r\nX: y", "443"},
		{"local host", "443"},
		{"local/host", "443"},
		{"local\\host", "443"},
		{"local%2Fhost", "443"},
		{"localhost:443", "443"},
		{"localhost\x00", "443"},
		{"localhost", "0"},
		{"localhost", "65536"},
		{"localhost", "not-a-port"},
		{"localhost", "-1"},
		{strings.Repeat("a", 254), "443"},
	} {
		authorized := ""
		calls := 0
		b := probeBroker()
		b.Policy.Authorize = func(_ context.Context, r Request) error {
			calls++
			authorized = r.URL
			return nil
		}
		if _, err := b.ProbeTLS(context.Background(), tc.host, tc.port); err == nil {
			t.Errorf("accepted host=%q port=%q", tc.host, tc.port)
		}
		if calls != 0 {
			t.Errorf("host=%q port=%q was authorized as %q before validation", tc.host, tc.port, authorized)
		}
	}
}

// Every handshake claims a request, so the engagement's request cap bounds a TLS probe as it bounds a fetch.
func TestProbeTLSClaimsTheRequestBudget(t *testing.T) {
	cert := testCert(t, []string{"localhost"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	port := tlsServer(t, cert, tls.VersionTLS10, tls.VersionTLS13)
	b := probeBroker()
	if _, err := b.ProbeTLS(context.Background(), "localhost", port); err != nil {
		t.Fatal(err)
	}
	requests, _ := b.Usage()
	if requests != len(tlsProbeVersions) {
		t.Errorf("claimed %d requests, want one per probed version (%d)", requests, len(tlsProbeVersions))
	}

	capped := probeBroker()
	capped.Policy.MaxRequests = 2
	got, err := capped.ProbeTLS(context.Background(), "localhost", port)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(got.Protocols) + len(got.Refused); n > 2 {
		t.Errorf("probed %d versions past a 2-request cap", n)
	}
	if !strings.Contains(got.Gap, "request budget exhausted") {
		t.Errorf("Gap does not state the exhausted budget: %q", got.Gap)
	}
}

// A port that nothing is listening on is a gap, not a refusal: reporting it as "the server does not offer this version" would be a false negative.
func TestProbeTLSSeparatesUnreachableFromRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	got, err := probeBroker().ProbeTLS(context.Background(), "localhost", port)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Refused) != 0 {
		t.Errorf("a closed port was reported as refusing versions: %v", got.Refused)
	}
	if !strings.Contains(got.Gap, "not reached") {
		t.Errorf("Gap does not report the unreachable port: %q", got.Gap)
	}
	if !strings.Contains(got.Gap, "no certificate observed") {
		t.Errorf("Gap does not state that no certificate was seen: %q", got.Gap)
	}
}

// A plain HTTP server on the probed port refuses every TLS version; that is a result about the port, and no certificate facts may be invented for it.
func TestProbeTLSHandlesANonTLSPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	got, err := probeBroker().ProbeTLS(context.Background(), "localhost", port)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Protocols) != 0 {
		t.Errorf("a non-TLS port negotiated %v", got.Protocols)
	}
	if got.Subject != "" || got.NotAfter != "" || got.ChainTrusted {
		t.Errorf("certificate facts were recorded with no certificate: %+v", got)
	}
	if !strings.Contains(got.Gap, "no certificate observed") {
		t.Errorf("Gap does not state that no certificate was seen: %q", got.Gap)
	}
}

func TestProbeTLSDefaultsToPort443(t *testing.T) {
	var seen string
	b := probeBroker()
	b.Policy.Authorize = func(_ context.Context, r Request) error {
		seen = r.URL
		return errors.New("stop here")
	}
	if _, err := b.ProbeTLS(context.Background(), "localhost", ""); err == nil {
		t.Fatal("the probe continued past the policy refusal")
	}
	if seen != "https://localhost:443" {
		t.Errorf("authorized %q, want the default https port", seen)
	}
}

func TestProbeTLSHonoursContextCancellation(t *testing.T) {
	cert := testCert(t, []string{"localhost"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	port := tlsServer(t, cert, tls.VersionTLS12, tls.VersionTLS13)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := probeBroker().ProbeTLS(ctx, "localhost", port); err == nil {
		t.Error("a probe ran under a cancelled context")
	}
}
