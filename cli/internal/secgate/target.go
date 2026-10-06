package secgate

import (
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

var (
	// urlRe finds every scheme://... substring inside an argument.
	urlRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s'",]+`)
	// cidrSuffix matches a bare /NN mask left after a host is cut from a token.
	cidrSuffix = regexp.MustCompile(`^/[0-9]{1,3}$`)
	// ipv4Shape matches digit/dot/dash/bracket tokens (IPs, ranges, malformed IPs).
	ipv4Shape = regexp.MustCompile(`^[0-9.\[\]-]+$`)
	// packedIP matches a bare 0x hex literal or a decimal of 8+ digits (a packed
	// 32-bit IP is at least 16777216). Ports and counts are far shorter.
	packedIP = regexp.MustCompile(`^(0[xX][0-9a-fA-F]+|[0-9]{8,})$`)
)

// ExtractTargets returns every distinct host/IP the command references,
// lowercased, in first-seen order. It is best-effort extraction paired with a
// fail-closed signal.
//
// ok is true only when every host-like token in the command was resolved to a
// concrete host present in targets. ok is false when a host-like token could
// not be resolved: a scheme:// with no usable host, a CIDR or range argument, or
// a user@, host:, or dotted-with-path token whose host part is not a valid host
// or IP. Callers must deny when ok is false. A command with no host-like tokens
// returns (nil, true); the caller decides separately whether that is allowed.
//
// It looks at: scheme:// URLs anywhere in an argument (host from net/url
// Hostname, so userinfo and port never count), the value after the first '=' of
// any argument, comma lists, user@host, host:port, [ipv6]:port, bare IPs, bare
// dotted hostnames, and schemeless host/path, host?query, host#fragment forms.
// A trailing dot on a hostname is normalized away. A flag with no '=' value is
// not a target.
func ExtractTargets(c Command) ([]string, bool) {
	hosts, nets, ok := ExtractTargetSet(c)
	if len(nets) > 0 {
		// A caller on this contract expects one host per target and cannot judge a
		// whole network, so a network argument stays unverifiable for it. Only the
		// layers that opted in through ExtractTargetSet decide a network.
		return hosts, false
	}
	return hosts, ok
}

// ExtractTargetSet is ExtractTargets with networks separated out rather than
// treated as unverifiable. hosts carries every single-host target and nets every
// CIDR argument; ok has the same fail-closed meaning. A caller that uses this
// must check nets with Scope.NetworkInScope, which authorizes a network only
// when one in-scope CIDR covers all of it and nothing excluded overlaps it.
func ExtractTargetSet(c Command) (hosts []string, nets []*net.IPNet, ok bool) {
	name := baseName(strings.TrimSpace(c.Binary))
	if impacketBinaries[name] {
		// impacket's [domain/]user[:password]@host operand needs its own grammar:
		// the generic token reader cuts at the first '/' and loses the host, and a
		// -hashes LM:NT value reads as host:port.
		h, good := impacketTargets(c.Args)
		return h, nil, good
	}
	if strings.EqualFold(name, "socat") {
		// socat addresses its destination as TYPE:host:port, which the generic
		// token reader cannot separate from an address option.
		h, good := socatTargets(c.Args)
		return h, nil, good
	}
	e := &extractor{seen: map[string]bool{}, ok: true}
	switch strings.ToLower(name) {
	case "smbclient", "rpcclient":
		e.unc = true
	case "dig":
		// With an explicit @server, the queried name (and -t/-x/-q values) is data
		// sent to that resolver, not a connection target.
		e.skipNames = hasAtServer(c.Args)
	}
	for _, a := range c.Args {
		e.arg(a)
	}
	return e.out, e.nets, e.ok
}

type extractor struct {
	seen map[string]bool
	out  []string
	nets []*net.IPNet
	ok   bool
	unc  bool // extract the host of a //host or \\host token (smbclient, rpcclient)
	// skipNames drops positional tokens (not led by '-', '+', or '@') so a dig
	// query name is not scope-checked when an @server names the resolver.
	skipNames bool
}

// hasAtServer reports whether any whitespace field of args is an '@'-led token.
func hasAtServer(args []string) bool {
	for _, a := range args {
		for _, f := range strings.Fields(a) {
			if f[0] == '@' {
				return true
			}
		}
	}
	return false
}

func (e *extractor) add(h string) {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" || e.seen[h] {
		return
	}
	e.seen[h] = true
	e.out = append(e.out, h)
}

// seenNet records a network and reports whether it was already recorded.
func (e *extractor) seenNet(n *net.IPNet) bool {
	key := "cidr:" + n.String()
	if e.seen[key] {
		return true
	}
	e.seen[key] = true
	return false
}

func validHost(h string) bool {
	return isHostname(h) || net.ParseIP(h) != nil
}

// arg processes one argument: embedded URLs first, then each whitespace field.
func (e *extractor) arg(a string) {
	a = strings.TrimSpace(a)
	if a == "" {
		return
	}
	if strings.Count(a, "://") > e.scan(a) {
		e.ok = false
	}
	for _, f := range strings.Fields(a) {
		if e.skipNames && !strings.Contains(f, "://") && f[0] != '-' && f[0] != '+' && f[0] != '@' {
			continue
		}
		e.token(f)
	}
}

// scan extracts the host of every scheme:// substring in s, recursing into each
// match so a URL nested in a query is seen too. It returns the number of
// matches found so the caller can detect a "://" no match accounted for.
func (e *extractor) scan(s string) int {
	n := 0
	for _, loc := range urlRe.FindAllStringIndex(s, -1) {
		n++
		m := s[loc[0]:loc[1]]
		i := strings.Index(m, "://")
		auth := s[loc[0]+i+3:]
		if j := strings.IndexAny(auth, "/?#'\""); j >= 0 {
			auth = auth[:j]
		}
		if strings.IndexFunc(auth, unicode.IsSpace) >= 0 {
			e.ok = false
		}
		u, err := url.Parse(m)
		if err != nil {
			e.ok = false
		} else if h := strings.TrimSuffix(u.Hostname(), "."); h != "" && validHost(h) {
			e.add(h)
		} else {
			e.ok = false
		}
		n += e.scan(m[i+3:])
	}
	return n
}

// token processes one whitespace-free token that is not part of a URL.
func (e *extractor) token(t string) {
	t = strings.TrimSpace(t)
	if t == "" {
		return
	}
	if strings.Contains(t, ",") {
		for _, p := range strings.Split(t, ",") {
			e.token(p)
		}
		return
	}
	if strings.Contains(t, "://") {
		return // scan already handled it
	}
	if h, ok := uncHost(t); ok && e.unc {
		// A UNC host is unambiguous, so a single-label name counts too (host()
		// would skip it as an ordinary word).
		h = strings.TrimSuffix(h, ".")
		if len(h) > 2 && h[0] == '[' && h[len(h)-1] == ']' {
			h = h[1 : len(h)-1]
		}
		if validHost(h) {
			e.add(h)
		} else {
			e.ok = false
		}
		return
	}
	if i := strings.Index(t, "="); i >= 0 {
		e.token(t[i+1:])
	}
	if strings.HasPrefix(t, "-") {
		return
	}
	e.host(t)
}

// uncHost returns the host of a UNC-style token such as //host/share or
// \\host\share (smbclient and rpcclient accept any mix of '/' and '\' for the
// leading and the following separators, and extra leading separators are
// harmless to them). Without this the host would fall through host() as a
// filesystem path and escape the scope check. It reports ok=false when t starts
// with fewer than two separators. A token of three or more separators and no
// host returns ("", true), which the caller treats as unverifiable. The
// extractor applies this to smbclient and rpcclient only; for other tools a
// //x token is a path or payload.
func uncHost(t string) (string, bool) {
	rest := strings.TrimLeft(t, "/\\")
	n := len(t) - len(rest)
	if n < 2 {
		return "", false
	}
	if rest == "" {
		return "", n >= 3 // "///" carries no host: unverifiable, not a path
	}
	if i := strings.IndexAny(rest, "/\\"); i >= 0 {
		rest = rest[:i]
	}
	return rest, true
}

// host resolves a token as CIDR/range, [user@]host[:port|:path][/path|?q|#f],
// bare IP, or bare dotted hostname, and flags it unresolved when host-like but
// not valid. localhost is always a target; packed-IP tokens are unresolved.
func (e *extractor) host(t string) {
	if _, n, err := net.ParseCIDR(t); err == nil {
		// A whole network is recorded separately: it cannot be checked as one
		// host, but it is a legitimate target when one in-scope CIDR covers it.
		// The normalized network form is kept, so 10.0.0.5/24 is judged as
		// 10.0.0.0/24, which is the range a scanner actually sweeps.
		if !e.seenNet(n) {
			e.nets = append(e.nets, n)
		}
		return
	}
	h := t
	cut, maskOnly := false, false
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		maskOnly = cidrSuffix.MatchString(h[i:])
		h = h[:i]
		cut = true
	}
	if h == "" || h == "~" || h[0] == '.' {
		return // a filesystem path, not a host
	}
	hasAt := false
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
		hasAt = true
	}
	hasColon := false
	if len(h) > 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	} else if net.ParseIP(h) == nil {
		if hh, _, err := net.SplitHostPort(h); err == nil {
			h, hasColon = hh, true
		} else if strings.Count(h, ":") == 1 && strings.HasSuffix(h, ":") {
			h, hasColon = strings.TrimSuffix(h, ":"), true
		} else if strings.Contains(h, ":") {
			hasColon = true // left as-is, fails the host check below
		}
	}
	h = strings.TrimSuffix(h, ".")
	ip := net.ParseIP(h)
	if ip != nil || isHostname(h) {
		if strings.EqualFold(h, "localhost") {
			e.add(h) // loopback services make localhost a real target
			if maskOnly {
				e.ok = false
			}
			return
		}
		if ip == nil && !hasAt && !hasColon && !strings.Contains(h, ".") {
			return // ordinary word
		}
		e.add(h)
		if maskOnly {
			e.ok = false // host/NN is a network, not one host
		}
		return
	}
	if hasAt || hasColon || (cut && strings.Contains(h, ".")) ||
		(ipv4Shape.MatchString(h) && strings.Count(h, ".") >= 3) ||
		packedIP.MatchString(h) {
		e.ok = false
	}
}
