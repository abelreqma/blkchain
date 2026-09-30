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
	e := &extractor{seen: map[string]bool{}, ok: true}
	for _, a := range c.Args {
		e.arg(a)
	}
	return e.out, e.ok
}

type extractor struct {
	seen map[string]bool
	out  []string
	ok   bool
}

func (e *extractor) add(h string) {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" || e.seen[h] {
		return
	}
	e.seen[h] = true
	e.out = append(e.out, h)
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
	if i := strings.Index(t, "="); i >= 0 {
		e.token(t[i+1:])
	}
	if strings.HasPrefix(t, "-") {
		return
	}
	e.host(t)
}

// host resolves a token as CIDR/range, [user@]host[:port|:path][/path|?q|#f],
// bare IP, or bare dotted hostname, and flags it unresolved when host-like but
// not valid. localhost is always a target; packed-IP tokens are unresolved.
func (e *extractor) host(t string) {
	if _, _, err := net.ParseCIDR(t); err == nil {
		e.ok = false // a whole network cannot be checked as one host
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
