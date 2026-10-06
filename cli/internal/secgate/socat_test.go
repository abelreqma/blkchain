package secgate

import (
	"slices"
	"strings"
	"testing"
)

// TestSocatRejectsEveryNonConnectAddress is the allowlist's reason for existing:
// socat's danger is in its addresses, not its options, and an unknown or new
// keyword must fail closed rather than be assumed harmless.
func TestSocatRejectsEveryNonConnectAddress(t *testing.T) {
	for _, address := range []string{
		"EXEC:/bin/sh", "exec:/bin/sh", "EXEC:/bin/sh,pty,stderr",
		"SYSTEM:id", "system:id", "SHELL:id",
		"OPEN:/etc/shadow", "CREATE:/etc/evil", "GOPEN:/etc/shadow",
		"FILE:/etc/shadow", "PTY", "PIPE",
		"UNIX-CONNECT:/var/run/docker.sock", "UNIX_CONNECT:/var/run/docker.sock",
		"ABSTRACT-CONNECT:x", "SOCKS4:proxy:host:80", "SOCKS5:proxy:host:80",
		"PROXY:proxy:host:80", "TCP-LISTEN:4444", "tcp_listen:4444",
		"UDP-LISTEN:4444", "TUN:10.0.0.1/24", "IP-SENDTO:host:255",
		"SCTP-CONNECT:host:80", "INTERFACE:eth0", "DTLS:host:443",
		"192.0.2.10:445", // a bare host:port is not a socat address
		"NEWFANGLED:host:80",
	} {
		d := Classify(Command{Binary: "socat", Args: []string{"-", address}})
		if d.Allowed {
			t.Errorf("socat - %s was allowed", address)
		}
	}
	// No address at all is also refused.
	denied(t, "socat with no address", Classify(Command{Binary: "socat", Args: []string{"-d", "-d"}}))
}

// TestSocatConnectAddressesAllowed keeps the relay usable for the forms whose
// destination the scope check can read.
func TestSocatConnectAddressesAllowed(t *testing.T) {
	for _, args := range [][]string{
		{"-", "TCP:192.0.2.10:445"},
		{"-", "tcp:192.0.2.10:445"},
		{"-", "TCP4:192.0.2.10:445"},
		{"-", "TCP-CONNECT:192.0.2.10:445"},
		{"-", "TCP:192.0.2.10:445,connect-timeout=5"},
		{"STDIO", "OPENSSL:192.0.2.10:443,verify=0"},
		{"-", "UDP:192.0.2.10:161"},
		{"-d", "-", "TCP:dc01.corp.example:445"},
		{"-", "TCP6:[2001:db8::1]:445"},
	} {
		allowed(t, "socat "+join(args), Classify(Command{Binary: "socat", Args: args}))
	}
}

// TestSocatTargetsReachTheScopeCheck proves the host inside an address is what
// gets scope-checked, rather than the address being waved through.
func TestSocatTargetsReachTheScopeCheck(t *testing.T) {
	cases := []struct {
		args []string
		want []string
		ok   bool
	}{
		{[]string{"-", "TCP:192.0.2.10:445"}, []string{"192.0.2.10"}, true},
		{[]string{"-", "TCP:192.0.2.10:445,connect-timeout=5"}, []string{"192.0.2.10"}, true},
		{[]string{"STDIO", "OPENSSL:dc01.corp.example:443"}, []string{"dc01.corp.example"}, true},
		{[]string{"-", "TCP6:[2001:db8::1]:445"}, []string{"2001:db8::1"}, true},
		// Both ends named: both hosts are checked.
		{[]string{"TCP:192.0.2.10:445", "TCP:192.0.2.11:445"}, []string{"192.0.2.10", "192.0.2.11"}, true},
		// Fail closed on a permitted type with no usable host, and on a denied type.
		{[]string{"-", "TCP:"}, nil, false},
		{[]string{"-", "TCP:not a host:445"}, nil, false},
		{[]string{"-", "EXEC:/bin/sh"}, nil, false},
	}
	for _, c := range cases {
		got, ok := ExtractTargets(Command{Binary: "socat", Args: c.args})
		if ok != c.ok {
			t.Errorf("ExtractTargets(socat %v) ok = %t, want %t (%v)", c.args, ok, c.ok, got)
			continue
		}
		if c.ok && !slices.Equal(got, c.want) {
			t.Errorf("ExtractTargets(socat %v) = %v, want %v", c.args, got, c.want)
		}
	}
	// An out-of-scope relay end is refused by the scope, not merely extracted.
	s := mustScope(t, "192.0.2.0/24\n")
	out, ok := ExtractTargets(Command{Binary: "socat", Args: []string{"-", "TCP:198.51.100.9:445"}})
	if !ok || len(out) != 1 || s.InScope(out[0]) {
		t.Fatalf("out-of-scope socat end not refused: %v %t", out, ok)
	}
}

// TestSocatTypeNormalization pins the keyword comparison, including the dashed
// and underscored spellings socat accepts for one type.
func TestSocatTypeNormalization(t *testing.T) {
	for address, want := range map[string]string{
		"TCP:host:80":      "TCP",
		"tcp-connect:h:80": "TCPCONNECT",
		"TCP_CONNECT:h:80": "TCPCONNECT",
		"openssl:h:443":    "OPENSSL",
		"-":                "-",
		"STDIO":            "STDIO",
		"EXEC:/bin/sh,pty": "EXEC",
		"UNIX-CONNECT:/s":  "UNIXCONNECT",
	} {
		if got := socatType(address); got != want {
			t.Errorf("socatType(%q) = %q, want %q", address, got, want)
		}
	}
	if !strings.Contains(socatViolationReason(t, "EXEC:/bin/sh"), "EXEC") {
		t.Error("the denial should name the refused address type")
	}
}

func socatViolationReason(t *testing.T, address string) string {
	t.Helper()
	d := Classify(Command{Binary: "socat", Args: []string{"-", address}})
	return d.Reason
}
