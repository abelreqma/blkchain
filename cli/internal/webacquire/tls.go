package webacquire

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// tls.go probes which TLS versions a host negotiates and whether its certificate validates, under the same scope controls and request budget as a fetch.

// tlsProbeVersions are the versions probed, weakest first; crypto/tls cannot offer SSLv2 or SSLv3.
var tlsProbeVersions = []struct {
	Name string
	ID   uint16
}{
	{"TLSv1.0", tls.VersionTLS10},
	{"TLSv1.1", tls.VersionTLS11},
	{"TLSv1.2", tls.VersionTLS12},
	{"TLSv1.3", tls.VersionTLS13},
}

// LegacyTLSVersions are the probed versions whose availability is itself a finding.
func LegacyTLSVersions() []string { return []string{"TLSv1.0", "TLSv1.1"} }

// TLSObservation is what one probe read from the handshake and the presented chain, with Gap naming what stayed unknown.
type TLSObservation struct {
	Host string `json:"host"`
	Port string `json:"port"`
	// Protocols are the versions handshaked, Refused those declined; a version in neither was not reached.
	Protocols []string          `json:"protocols,omitempty"`
	Refused   []string          `json:"refused,omitempty"`
	Ciphers   map[string]string `json:"ciphers,omitempty"`

	Subject            string   `json:"subject,omitempty"`
	Issuer             string   `json:"issuer,omitempty"`
	SerialNumber       string   `json:"serial_number,omitempty"`
	NotBefore          string   `json:"not_before,omitempty"`
	NotAfter           string   `json:"not_after,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty"`
	IPAddresses        []string `json:"ip_addresses,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty"`
	KeyAlgorithm       string   `json:"key_algorithm,omitempty"`
	KeyBits            int      `json:"key_bits,omitempty"`
	ChainLength        int      `json:"chain_length,omitempty"`

	SelfSigned      bool   `json:"self_signed"`
	HostnameMatches bool   `json:"hostname_matches"`
	ChainTrusted    bool   `json:"chain_trusted"`
	Expired         bool   `json:"expired"`
	NotYetValid     bool   `json:"not_yet_valid"`
	ValidationError string `json:"validation_error,omitempty"`
	Gap             string `json:"gap,omitempty"`
}

// Negotiated reports whether the server completed a handshake at version.
func (o TLSObservation) Negotiated(version string) bool {
	for _, v := range o.Protocols {
		if v == version {
			return true
		}
	}
	return false
}

// LegacyProtocols lists the legacy versions the server negotiated.
func (o TLSObservation) LegacyProtocols() []string {
	var out []string
	for _, v := range LegacyTLSVersions() {
		if o.Negotiated(v) {
			out = append(out, v)
		}
	}
	return out
}

// tlsPort returns the port to probe, defaulting to 443.
func tlsPort(port string) (string, error) {
	if port == "" {
		return "443", nil
	}
	n, err := net.LookupPort("tcp", port)
	if err != nil || n <= 0 || n > 65535 {
		return "", errors.New("invalid TLS port")
	}
	return port, nil
}

// tlsDestination applies the scope controls to one host and returns the address every handshake is pinned to.
func (b *Broker) tlsDestination(ctx context.Context, host, port string) (string, error) {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \\%/\r\n\x00:") {
		return "", errors.New("invalid TLS host")
	}
	if b.Policy.Authorize == nil || b.Policy.IPAllowed == nil {
		return "", errors.New("web request policy missing")
	}
	if err := b.Policy.Authorize(ctx, Request{Method: "GET", URL: "https://" + net.JoinHostPort(host, port)}); err != nil {
		return "", err
	}
	resolver := b.Policy.Resolve
	if resolver == nil {
		resolver = func(ctx context.Context, h string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", h)
		}
	}
	ips, err := resolver(ctx, host)
	if err != nil || len(ips) == 0 {
		return "", errors.New("web destination resolution failed")
	}
	for _, ip := range ips {
		if !b.Policy.IPAllowed(host, ip) {
			return "", errors.New("web destination resolves outside scope")
		}
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

// ProbeTLS negotiates each probed version against host:port and validates the certificate presented for host.
func (b *Broker) ProbeTLS(ctx context.Context, host, port string) (TLSObservation, error) {
	port, err := tlsPort(port)
	if err != nil {
		return TLSObservation{}, err
	}
	addr, err := b.tlsDestination(ctx, host, port)
	if err != nil {
		return TLSObservation{}, err
	}
	out := TLSObservation{Host: host, Port: port, Ciphers: map[string]string{}}
	var chain []*x509.Certificate
	var gaps []string
	for _, v := range tlsProbeVersions {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		// Each handshake is one request against the budget.
		if err := b.claim(0); err != nil {
			gaps = append(gaps, "request budget exhausted before "+v.Name)
			break
		}
		state, err := tlsHandshake(ctx, addr, host, v.ID)
		if err != nil {
			// A handshake that started and failed counts as a refusal, which under-reports rather than over-reports.
			if errors.Is(err, errUnreachable) {
				gaps = append(gaps, v.Name+" not reached: "+err.Error())
			} else {
				out.Refused = append(out.Refused, v.Name)
			}
			continue
		}
		out.Protocols = append(out.Protocols, v.Name)
		out.Ciphers[v.Name] = tls.CipherSuiteName(state.CipherSuite)
		if len(state.PeerCertificates) > len(chain) {
			chain = state.PeerCertificates
		}
	}
	if len(chain) == 0 {
		if len(out.Refused) == len(tlsProbeVersions) {
			gaps = append(gaps, "the server completed no handshake at any probed version")
		}
		gaps = append(gaps, "no certificate observed")
	} else {
		out.describeChain(chain, host)
	}
	// crypto/tls offers no SSLv2 or SSLv3 client, so their absence is not a result about the server.
	gaps = append(gaps, "SSLv2 and SSLv3 were not probed")
	out.Gap = strings.Join(gaps, "; ")
	return out, nil
}

// describeChain records the presented chain's facts and validates it for host, which the handshake itself does not do.
func (o *TLSObservation) describeChain(chain []*x509.Certificate, host string) {
	leaf := chain[0]
	o.ChainLength = len(chain)
	o.Subject = boundedName(leaf.Subject.String())
	o.Issuer = boundedName(leaf.Issuer.String())
	o.SerialNumber = leaf.SerialNumber.String()
	o.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	o.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	o.SignatureAlgorithm = leaf.SignatureAlgorithm.String()
	o.KeyAlgorithm, o.KeyBits = keyFacts(leaf)
	for _, n := range leaf.DNSNames {
		o.DNSNames = append(o.DNSNames, boundedName(n))
	}
	sort.Strings(o.DNSNames)
	for _, ip := range leaf.IPAddresses {
		o.IPAddresses = append(o.IPAddresses, ip.String())
	}
	sort.Strings(o.IPAddresses)
	// CheckSignatureFrom requires a CA parent, so a self-signed leaf is tested by its own issuer name and signature.
	o.SelfSigned = bytes.Equal(leaf.RawIssuer, leaf.RawSubject) &&
		leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil

	now := time.Now()
	o.Expired = now.After(leaf.NotAfter)
	o.NotYetValid = now.Before(leaf.NotBefore)
	o.HostnameMatches = leaf.VerifyHostname(host) == nil

	pool := x509.NewCertPool()
	for _, c := range chain[1:] {
		pool.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Intermediates: pool,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		o.ValidationError = boundedName(err.Error())
		return
	}
	o.ChainTrusted = true
}

// keyFacts names the leaf's public-key algorithm and its size in bits, or 0 where there is none.
func keyFacts(leaf *x509.Certificate) (string, int) {
	switch k := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", len(k) * 8
	}
	return leaf.PublicKeyAlgorithm.String(), 0
}

// boundedName caps a certificate-supplied string and strips the control characters a record cannot carry.
func boundedName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\x00' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
	if len(s) > 512 {
		return s[:512]
	}
	return s
}

// errUnreachable marks a failure to reach the port at all, as against the server declining a version.
var errUnreachable = errors.New("port not reachable")

// tlsHandshake completes one handshake at exactly version, without verification, so describeChain can validate it.
func tlsHandshake(ctx context.Context, addr, serverName string, version uint16) (tls.ConnectionState, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return tls.ConnectionState{}, fmt.Errorf("%w: %v", errUnreachable, err)
	}
	defer conn.Close()
	deadline, ok := dialCtx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return tls.ConnectionState{}, err
	}
	tc := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true,
	})
	if err := tc.HandshakeContext(dialCtx); err != nil {
		return tls.ConnectionState{}, err
	}
	state := tc.ConnectionState()
	_ = tc.Close()
	return state, nil
}
