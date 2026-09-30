package secgate

import (
	"net"
	"strings"
	"testing"
)

func withStubLookup(t *testing.T, m map[string][]net.IP, errHosts map[string]bool) {
	t.Helper()
	prev := lookupIPFn
	lookupIPFn = func(host string) ([]net.IP, error) {
		if errHosts[host] {
			return nil, &net.DNSError{Err: "no such host", Name: host}
		}
		if ips, ok := m[host]; ok {
			return ips, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	t.Cleanup(func() { lookupIPFn = prev })
}

func TestResolveScopeViolationRebind(t *testing.T) {
	s, _ := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	withStubLookup(t, map[string][]net.IP{
		"in.example.com":    {net.ParseIP("10.0.0.9")},
		"evil.example.com":  {net.ParseIP("8.8.8.8")},
		"mixed.example.com": {net.ParseIP("10.0.0.5"), net.ParseIP("8.8.8.8")},
	}, nil)
	// in-scope hostname: no violation.
	if _, _, v := ResolveScopeViolation(s, Command{Binary: "curl", Args: []string{"http://in.example.com/"}}); v {
		t.Error("in-scope hostname should not violate")
	}
	// out-of-scope resolution: violation.
	if h, ip, v := ResolveScopeViolation(s, Command{Binary: "curl", Args: []string{"http://evil.example.com/"}}); !v || h != "evil.example.com" || ip != "8.8.8.8" {
		t.Errorf("want violation evil.example.com/8.8.8.8, got %q/%q v=%v", h, ip, v)
	}
	// ANY resolved IP out of scope: violation (mixed).
	if h, ip, v := ResolveScopeViolation(s, Command{Binary: "curl", Args: []string{"http://mixed.example.com/"}}); !v || h != "mixed.example.com" || ip != "8.8.8.8" {
		t.Errorf("a host resolving to any out-of-scope IP must violate, got %q/%q v=%v", h, ip, v)
	}
}

func TestResolveScopeViolationLookupErrorFailsClosed(t *testing.T) {
	s, _ := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	withStubLookup(t, nil, map[string]bool{"broken.example.com": true})
	if _, _, v := ResolveScopeViolation(s, Command{Binary: "curl", Args: []string{"http://broken.example.com/"}}); !v {
		t.Error("a resolver error must fail closed (violation)")
	}
}

func TestResolveScopeViolationEmptyResultFailsClosed(t *testing.T) {
	s, _ := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	withStubLookup(t, map[string][]net.IP{"empty.example.com": {}}, nil)
	if _, _, v := ResolveScopeViolation(s, Command{Binary: "curl", Args: []string{"http://empty.example.com/"}}); !v {
		t.Error("an empty resolution must fail closed (violation)")
	}
}

func TestResolveScopeViolationIgnoresBareIP(t *testing.T) {
	s, _ := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	withStubLookup(t, nil, nil) // no lookups should happen
	if _, _, v := ResolveScopeViolation(s, Command{Binary: "nmap", Args: []string{"10.0.0.9"}}); v {
		t.Error("a bare in-scope IP is not resolved and not a violation")
	}
}

func TestResolveScopeViolationNilScope(t *testing.T) {
	withStubLookup(t, nil, nil)
	if h, ip, v := ResolveScopeViolation(nil, Command{Binary: "curl", Args: []string{"http://x.example.com/"}}); v || h != "" || ip != "" {
		t.Error("a nil scope must not violate")
	}
}
