package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"blkchain/cli/internal/webacquire"
)

// The engagement web stack sends its traffic through a local intercepting proxy
// when one is listening, so Burp Suite and equivalents see every request the
// stack makes. The proxy is on by default at webProxyDefaultAddress and off when
// webProxyEnv is "off" or when nothing is listening. The address must be
// loopback: a remote proxy would carry engagement traffic to a host outside the
// operator's machine, which no scope entry authorizes.
const (
	webProxyEnv              = "BLKCHAIN_WEB_PROXY"
	webProxyCAEnv            = "BLKCHAIN_WEB_PROXY_CA"
	webProxyDefaultAddress   = "127.0.0.1:8080"
	webProxyCAURL            = "http://burp/cert"
	webProxyProbeTimeout     = 750 * time.Millisecond
	webProxyCATimeout        = 5 * time.Second
	webProxyCAMaxBytes       = 64 << 10
	webProxyDisabledSetting  = "off"
	webProxyUnreachableLabel = "not listening"
	webProxyInUseLabel       = "carrying engagement web traffic"
	webProxySubjectMaxRunes  = 120
)

var webProxyNotice = func(line string) { fmt.Fprintln(os.Stderr, line) }

// webProxyCache holds one resolution per proxy address for the life of the
// process, so the probe and the certificate fetch happen once rather than per
// request. A nil entry records an address that resolved to the direct path.
var (
	webProxyMu    sync.Mutex
	webProxyCache = map[string]*webacquire.Upstream{}
)

// webUpstreamProxy returns the upstream proxy the web stack sends requests
// through, or nil for the direct path. Probing and certificate retrieval are
// bounded, so a missing proxy costs one short dial once per address.
func webUpstreamProxy() *webacquire.Upstream {
	setting := strings.TrimSpace(os.Getenv(webProxyEnv))
	if strings.EqualFold(setting, webProxyDisabledSetting) {
		return nil
	}
	address := webProxyDefaultAddress
	if setting != "" {
		address = setting
	}
	webProxyMu.Lock()
	defer webProxyMu.Unlock()
	if upstream, ok := webProxyCache[address]; ok {
		return upstream
	}
	upstream := resolveWebUpstreamProxy(address, setting != "")
	webProxyCache[address] = upstream
	return upstream
}

// resolveWebUpstreamProxy probes the address and sources the CA. configured
// reports whether the operator named the address, which decides whether an
// absent proxy is worth a notice.
func resolveWebUpstreamProxy(address string, configured bool) *webacquire.Upstream {
	if err := webProxyAddressAllowed(address); err != nil {
		webProxyNotice(fmt.Sprintf("blk: %s=%s ignored, using direct requests: %v", webProxyEnv, address, err))
		return nil
	}
	conn, err := net.DialTimeout("tcp", address, webProxyProbeTimeout)
	if err != nil {
		if configured {
			webProxyNotice(fmt.Sprintf("blk: web proxy %s %s, using direct requests", address, webProxyUnreachableLabel))
		}
		return nil
	}
	_ = conn.Close()
	pool, subject, err := webProxyRootCAs(address)
	if err != nil {
		webProxyNotice(fmt.Sprintf("blk: web proxy %s has no usable CA certificate, using direct requests: %v", address, err))
		return nil
	}
	// The trust anchor comes from whatever is listening on the address, which
	// is not authenticated, so the notice names the subject it accepted. An
	// operator proxying through the wrong local process can see it there.
	webProxyNotice(fmt.Sprintf("blk: web proxy %s %s, CA subject %s", address, webProxyInUseLabel, subject))
	return &webacquire.Upstream{Address: address, RootCAs: pool}
}

// webProxySubject renders a CA subject for one notice line. The subject is
// whatever the listening process issued itself, so it is reduced to printable
// ASCII on a single line and bounded before it reaches stderr.
func webProxySubject(name string) string {
	var out strings.Builder
	for _, r := range name {
		if out.Len() >= webProxySubjectMaxRunes {
			break
		}
		if r < 32 || r > 126 {
			r = ' '
		}
		out.WriteRune(r)
	}
	text := strings.Join(strings.Fields(out.String()), " ")
	if text == "" {
		return "unnamed"
	}
	return text
}

// webProxyAddressAllowed accepts only a loopback IP literal and a port. A
// hostname is refused because the address it resolves to is not checked again
// before the proxy carries engagement traffic.
func webProxyAddressAllowed(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("expected host:port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("expected a loopback IP address")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("expected a TCP port")
	}
	return nil
}

// webProxyRootCAs returns the system roots plus the proxy's issuing CA, read
// from webProxyCAEnv when the operator sets it and otherwise fetched through the
// proxy from webProxyCAURL, the endpoint Burp serves its CA on. The second
// return value is that CA's certificate subject, which the notice reports.
func webProxyRootCAs(address string) (*x509.CertPool, string, error) {
	data, err := webProxyCABytes(address)
	if err != nil {
		return nil, "", err
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if block, _ := pem.Decode(data); block != nil {
		if !pool.AppendCertsFromPEM(data) {
			return nil, "", errors.New("certificate is not a usable PEM chain")
		}
		anchor, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", errors.New("certificate PEM holds no readable certificate")
		}
		return pool, webProxySubject(anchor.Subject.String()), nil
	}
	certificate, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, "", errors.New("certificate is neither PEM nor DER")
	}
	pool.AddCert(certificate)
	return pool, webProxySubject(certificate.Subject.String()), nil
}

func webProxyCABytes(address string) ([]byte, error) {
	if path := strings.TrimSpace(os.Getenv(webProxyCAEnv)); path != "" {
		return webReadFile(path, webProxyCAMaxBytes)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: address}),
		DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: webProxyCATimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(webProxyCAURL)
	if err != nil {
		return nil, errors.New("certificate endpoint unreachable through the proxy")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certificate endpoint returned status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, webProxyCAMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > webProxyCAMaxBytes {
		return nil, errors.New("certificate endpoint returned an unusable body")
	}
	return data, nil
}
