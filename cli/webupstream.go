package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"blkchain/cli/internal/webacquire"
)

// The engagement web stack sends its traffic through a local intercepting proxy
// when the operator names one in webProxyEnv, so Burp Suite and equivalents see
// every request the stack makes. There is no default address: a default would
// hand engagement traffic to whatever local process listens on it. The address
// must be loopback, because a remote proxy would carry engagement traffic to a
// host outside the operator's machine, which no scope entry authorizes. The
// proxy's CA comes only from the file webProxyCAEnv names; it is never fetched
// from the listener, which would let whatever is listening choose the anchor.
const (
	webProxyEnv              = "BLKCHAIN_WEB_PROXY"
	webProxyCAEnv            = "BLKCHAIN_WEB_PROXY_CA"
	webProxyProbeTimeout     = 750 * time.Millisecond
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

// webProxyAddress returns the proxy address the operator named, or "" when no
// proxy is configured or proxying is turned off.
func webProxyAddress() string {
	setting := strings.TrimSpace(os.Getenv(webProxyEnv))
	if strings.EqualFold(setting, webProxyDisabledSetting) {
		return ""
	}
	return setting
}

// webUpstreamProxy returns the upstream proxy the web stack sends requests
// through, or nil for the direct path. Probing is bounded, so a missing proxy
// costs one short dial once per address.
func webUpstreamProxy() *webacquire.Upstream {
	address := webProxyAddress()
	if address == "" {
		return nil
	}
	webProxyMu.Lock()
	defer webProxyMu.Unlock()
	if upstream, ok := webProxyCache[address]; ok {
		return upstream
	}
	upstream := resolveWebUpstreamProxy(address)
	webProxyCache[address] = upstream
	return upstream
}

// resolveWebUpstreamProxy checks the address, reads the operator's CA, and
// probes the listener. Each refusal is reported, because the operator named the
// proxy and expects traffic to reach it.
func resolveWebUpstreamProxy(address string) *webacquire.Upstream {
	if err := webProxyAddressAllowed(address); err != nil {
		webProxyNotice(fmt.Sprintf("blk: %s=%s ignored, using direct requests: %v", webProxyEnv, address, err))
		return nil
	}
	pool, subject, err := webProxyRootCAs()
	if err != nil {
		webProxyNotice(fmt.Sprintf("blk: web proxy %s has no usable CA certificate, using direct requests: %v", address, err))
		return nil
	}
	conn, err := net.DialTimeout("tcp", address, webProxyProbeTimeout)
	if err != nil {
		webProxyNotice(fmt.Sprintf("blk: web proxy %s %s, using direct requests", address, webProxyUnreachableLabel))
		return nil
	}
	_ = conn.Close()
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
// from the file webProxyCAEnv names. The second return value is that CA's
// certificate subject, which the notice reports.
func webProxyRootCAs() (*x509.CertPool, string, error) {
	path := strings.TrimSpace(os.Getenv(webProxyCAEnv))
	if path == "" {
		return nil, "", fmt.Errorf("set %s to the proxy's exported CA certificate", webProxyCAEnv)
	}
	data, err := webReadFile(path, webProxyCAMaxBytes)
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
