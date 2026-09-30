package secgate

import (
	"strings"
	"testing"
)

func TestCanonicalIP(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1":        "127.0.0.1",
		"127.1":            "127.0.0.1", // inet_aton short form
		"2130706433":       "127.0.0.1", // decimal 32-bit
		"0x7f000001":       "127.0.0.1", // hex
		"0x7f.0x0.0x0.0x1": "127.0.0.1",
		"010.0.0.1":        "8.0.0.1", // leading-zero octal first octet (010 = 8)
		"192.168.1":        "192.168.0.1",
		"017700000001":     "127.0.0.1", // octal 32-bit
	}
	for in, want := range cases {
		got, ok := CanonicalIP(in)
		if !ok || got != want {
			t.Errorf("CanonicalIP(%q) = %q,%v; want %q,true", in, got, ok, want)
		}
	}
	for _, in := range []string{"host.example.com", "localhost", "notanip", "1.2.3.4.5", "256.0.0.1", "", "-p", "1..2", "0x", "08.0.0.1"} {
		if got, ok := CanonicalIP(in); ok {
			t.Errorf("CanonicalIP(%q) = %q,true; want false", in, got)
		}
	}
}

func TestScopeViolationCatchesNumericBypass(t *testing.T) {
	s, err := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	// A packed/short loopback bundled with an in-scope target: the gate's
	// ExtractTargets misses 127.1, but the exec-time re-check must catch it.
	viol, ok := ScopeViolation(s, Command{Binary: "curl", Args: []string{"10.0.0.5", "127.1"}})
	if !ok {
		t.Fatal("expected a scope violation for 127.1")
	}
	if viol != "127.0.0.1" {
		t.Errorf("violation = %q, want 127.0.0.1", viol)
	}
	// Decimal and hex forms too, including flag=value.
	for _, arg := range []string{"2130706433", "0x7f000001", "--data=127.1", "010.0.0.1"} {
		if _, ok := ScopeViolation(s, Command{Binary: "curl", Args: []string{"10.0.0.5", arg}}); !ok {
			t.Errorf("expected a violation for %q", arg)
		}
	}
	// An in-scope numeric form is not a violation.
	if _, ok := ScopeViolation(s, Command{Binary: "nmap", Args: []string{"10.0.0.9"}}); ok {
		t.Error("10.0.0.9 is in scope; not a violation")
	}
	// A non-numeric arg is not canonicalizable and not a violation here (the gate
	// handles hostnames; this re-check is only for numeric forms).
	if _, ok := ScopeViolation(s, Command{Binary: "nmap", Args: []string{"host.example.com"}}); ok {
		t.Error("hostname is not a numeric violation")
	}
}

func TestScopeViolationIgnoresBarePorts(t *testing.T) {
	s, err := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-p", "80", "10.0.0.9"},
		{"--top-ports", "1000", "10.0.0.9"},
		{"-p", "1234567", "10.0.0.9"}, // 7 digits: below the packed-IP threshold
		{"--max-rate=500", "10.0.0.9"},
		{"-p", "0x50", "10.0.0.9"}, // short hex literal is a number, not an address
	} {
		if v, ok := ScopeViolation(s, Command{Binary: "nmap", Args: args}); ok {
			t.Errorf("args %v: unexpected violation %q", args, v)
		}
	}
	// A nil scope never reports a violation.
	if _, ok := ScopeViolation(nil, Command{Binary: "curl", Args: []string{"127.1"}}); ok {
		t.Error("nil scope must not report a violation")
	}
}

func TestScopeViolationSplitsPackedArgs(t *testing.T) {
	s, err := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range []string{
		"10.0.0.5,127.1",      // comma list in one arg
		"10.0.0.5 127.1",      // space list in one arg
		"--x=a=127.1",         // nested key=value
		"127.1:80",            // host:port
		"http://127.1/x",      // URL
		"user@127.1",          // userinfo
		"10.0.0.5,0x7f000001", // packed hex in a list
	} {
		v, ok := ScopeViolation(s, Command{Binary: "naabu", Args: []string{arg}})
		if !ok || v != "127.0.0.1" {
			t.Errorf("arg %q: got %q,%v; want 127.0.0.1,true", arg, v, ok)
		}
	}
	// In-scope lists are not violations.
	if v, ok := ScopeViolation(s, Command{Binary: "naabu", Args: []string{"10.0.0.5,10.0.0.6"}}); ok {
		t.Errorf("in-scope list flagged: %q", v)
	}
}

func TestScopeViolationZeroNet(t *testing.T) {
	s, err := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--tls-max", "0.5", "10.0.0.9"},
		{"-i", "0.25", "10.0.0.9"},
	} {
		if v, ok := ScopeViolation(s, Command{Binary: "curl", Args: args}); ok {
			t.Errorf("args %v: unexpected violation %q", args, v)
		}
	}
	if v, ok := ScopeViolation(s, Command{Binary: "curl", Args: []string{"10.0.0.9", "0.0.0.0"}}); !ok || v != "0.0.0.0" {
		t.Errorf("0.0.0.0 must be flagged, got %q,%v", v, ok)
	}
}

func TestScopeViolationIgnoresPathsAndVersions(t *testing.T) {
	s, err := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"http://10.0.0.5/path/2.0/x"},
		{"-H", "User-Agent: Mozilla/5.0", "10.0.0.5"},
		{"-H", "User-Agent: curl/7.68.0", "10.0.0.5"},
		{"curl/7.68.0", "10.0.0.5"},
		{"HTTP/1.1", "10.0.0.5"},
		{"http://10.0.0.5/?v=2.0#3.0"},
	} {
		if v, ok := ScopeViolation(s, Command{Binary: "curl", Args: args}); ok {
			t.Errorf("args %v: unexpected violation %q", args, v)
		}
	}
	// A host with a mask or path still resolves the host before the cut.
	if v, ok := ScopeViolation(s, Command{Binary: "nmap", Args: []string{"127.1/24"}}); !ok || v != "127.0.0.1" {
		t.Errorf("127.1/24: got %q,%v; want 127.0.0.1,true", v, ok)
	}
}

func TestScopeViolationNestedURLInQuery(t *testing.T) {
	s, err := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range []string{"http://10.0.0.5/?u=http://127.1/", "--data=http://127.1/x", "url:http://127.1/x"} {
		if v, ok := ScopeViolation(s, Command{Binary: "curl", Args: []string{arg}}); !ok || v != "127.0.0.1" {
			t.Errorf("arg %q: got %q,%v; want 127.0.0.1,true", arg, v, ok)
		}
	}
}

func TestScopeViolationSchemelessHostBeforeNestedURL(t *testing.T) {
	s, err := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range []string{"127.1/redir?u=http://10.0.0.5/", "127.1:8080/x?next=http://10.0.0.5/"} {
		if v, ok := ScopeViolation(s, Command{Binary: "curl", Args: []string{arg}}); !ok || v != "127.0.0.1" {
			t.Errorf("arg %q: got %q,%v; want 127.0.0.1,true", arg, v, ok)
		}
	}
}
