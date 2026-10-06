package secgate

import "strings"

// socat.go audits socat by its address specs rather than its flags. socat's
// danger is not in its options but in its addresses: EXEC, SYSTEM and SHELL run
// a program, OPEN, CREATE and GOPEN open a file, a LISTEN or SOCKS address puts
// the far end outside anything the scope check can read, and a bare host:port is
// not a socat address at all.
//
// The policy is an allowlist of address types, so an unknown or new keyword
// fails closed, and the host of each permitted address is extracted for the
// scope check.

// socatConnectTypes are the address types socat may use, normalized the way
// socatType normalizes a keyword. Each one connects to a host named in the
// address, which is what makes it scope-checkable.
var socatConnectTypes = map[string]bool{
	"TCP": true, "TCP4": true, "TCP6": true,
	"TCPCONNECT": true, "TCP4CONNECT": true, "TCP6CONNECT": true,
	"UDP": true, "UDP4": true, "UDP6": true,
	"UDPCONNECT": true, "UDP4CONNECT": true, "UDP6CONNECT": true,
	"UDPSENDTO": true, "UDP4SENDTO": true, "UDP6SENDTO": true,
	"OPENSSL": true, "OPENSSLCONNECT": true,
}

// socatLocalTypes are the address types socat may use that name no host. They
// carry the operator's own end of the relay.
var socatLocalTypes = map[string]bool{
	"STDIO": true, "STDIN": true, "STDOUT": true, "STDERR": true, "-": true,
}

// socatType renders an address keyword the way the audit compares it: the part
// before the first ':' or ',', uppercased, with '-' and '_' removed, because
// socat accepts TCP-CONNECT, tcp_connect and TCPCONNECT alike.
func socatType(address string) string {
	head := address
	if i := strings.IndexAny(head, ":,"); i >= 0 {
		head = head[:i]
	}
	if head == "-" {
		return "-"
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(head) {
		if r == '-' || r == '_' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// socatHost returns the host of a connect address, which is the first
// colon-separated field after the type. It returns ok=false when the address
// names no usable host, so the command fails closed.
func socatHost(address string) (string, bool) {
	spec, _, _ := strings.Cut(address, ",") // drop the address options
	parts := strings.Split(spec, ":")
	if len(parts) < 2 {
		return "", false
	}
	host := strings.TrimSpace(parts[1])
	// A bracketed IPv6 literal keeps its colons, so rejoin what Split took apart.
	if strings.HasPrefix(host, "[") {
		rest := strings.Join(parts[1:], ":")
		if j := strings.Index(rest, "]"); j > 1 {
			host = rest[1:j]
		}
	}
	if host == "" || !validHost(host) {
		return "", false
	}
	return strings.ToLower(host), true
}

// socatArgs reports the non-flag arguments of a socat command, which are its
// addresses. socat's own options are single-dash and never positional.
func socatArgs(args []string) []string {
	var out []string
	for _, a := range args {
		if a == "" {
			continue
		}
		if a == "-" || a[0] != '-' {
			out = append(out, a)
		}
	}
	return out
}

// socatViolation denies a socat command that uses any address type outside the
// allowlist. The reason names the address, so an operator sees which end was
// refused.
func socatViolation(name string, args []string) (Decision, bool) {
	if name != "socat" {
		return Decision{}, false
	}
	addresses := socatArgs(args)
	if len(addresses) == 0 {
		return Decision{
			Allowed: false,
			Reason:  "socat with no address does nothing the gate can check",
		}, true
	}
	for _, a := range addresses {
		kind := socatType(a)
		if socatLocalTypes[kind] || socatConnectTypes[kind] {
			continue
		}
		return Decision{
			Allowed:    false,
			Reason:     "socat address " + a + " uses the " + kind + " type, which is not one of the connect types the scope check can read",
			Suggestion: "use TCP, TCP4, TCP6, UDP, OPENSSL or STDIO, e.g. socat - TCP:192.0.2.10:445",
		}, true
	}
	return Decision{}, false
}

// socatTargets extracts the host of every connect address. ok is false when a
// permitted connect address names no usable host.
func socatTargets(args []string) (hosts []string, ok bool) {
	ok = true
	for _, a := range socatArgs(args) {
		kind := socatType(a)
		if socatLocalTypes[kind] {
			continue
		}
		if !socatConnectTypes[kind] {
			// socatViolation denies this command; report it unverifiable too so a
			// caller that only extracts targets cannot treat it as targetless.
			ok = false
			continue
		}
		h, good := socatHost(a)
		if !good {
			ok = false
			continue
		}
		hosts = append(hosts, h)
	}
	return hosts, ok
}
