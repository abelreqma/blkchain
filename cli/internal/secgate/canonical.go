package secgate

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// CanonicalIP returns the dotted-quad IPv4 string a host token resolves to
// under inet_aton rules (decimal 32-bit, 0x hex, 0-octal, and short forms a.b
// / a.b.c / a.b.c.d), or ("", false) when the token is not a numeric IPv4
// form. It does NOT do DNS (single-label names are not numeric and return
// false). This is the offline canonicalizer for the exec-time scope re-check.
//
// A bare integer such as "80" IS a valid inet_aton address (0.0.0.80), so this
// function accepts it. Callers that scan arbitrary arguments must first decide
// whether a token is plausibly a host; see ScopeViolation.
func CanonicalIP(token string) (string, bool) {
	t := strings.TrimSpace(token)
	if t == "" {
		return "", false
	}
	parts := strings.Split(t, ".")
	if len(parts) > 4 {
		return "", false
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		v, ok := parseIntPart(p)
		if !ok {
			return "", false
		}
		vals[i] = v
	}
	var addr uint32
	switch len(parts) {
	case 1:
		if vals[0] > 0xffffffff {
			return "", false
		}
		addr = uint32(vals[0])
	case 2: // a.b: a(8) . b(24)
		if vals[0] > 0xff || vals[1] > 0xffffff {
			return "", false
		}
		addr = uint32(vals[0])<<24 | uint32(vals[1])
	case 3: // a.b.c: a(8) . b(8) . c(16)
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xffff {
			return "", false
		}
		addr = uint32(vals[0])<<24 | uint32(vals[1])<<16 | uint32(vals[2])
	case 4:
		for _, v := range vals {
			if v > 0xff {
				return "", false
			}
		}
		addr = uint32(vals[0])<<24 | uint32(vals[1])<<16 | uint32(vals[2])<<8 | uint32(vals[3])
	}
	return fmt.Sprintf("%d.%d.%d.%d", addr>>24&0xff, addr>>16&0xff, addr>>8&0xff, addr&0xff), true
}

// parseIntPart parses one dotted part as decimal, 0x hex, or 0-octal.
func parseIntPart(p string) (uint64, bool) {
	if p == "" {
		return 0, false
	}
	base := 10
	s := p
	switch {
	case len(p) >= 2 && (p[0:2] == "0x" || p[0:2] == "0X"):
		base, s = 16, p[2:]
	case len(p) >= 2 && p[0] == '0':
		base, s = 8, p[1:]
	}
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// ScopeViolation canonicalizes every argument of c and returns the first
// resolved IP that is out of scope, or ("", false) when none is. It is the
// exec-time backstop for the numeric scope-bypass class: a token like 127.1 or
// 2130706433 that ExtractTargets could not resolve is canonicalized here and
// checked against the scope. Only tokens plausibly a host are checked, so a
// bare port or count (80, 1000) is never flagged. Hostnames are not resolved
// here; they are the gate's and the allowlist's concern.
func ScopeViolation(s *Scope, c Command) (string, bool) {
	if s == nil {
		return "", false
	}
	for _, a := range c.Args {
		for _, cand := range candidateTokens(a) {
			if !plausibleNumericHost(cand) {
				continue
			}
			ip, ok := CanonicalIP(cand)
			if !ok || skipZeroNet(ip) {
				continue
			}
			if !s.InScope(ip) {
				return ip, true
			}
		}
	}
	return "", false
}

// candidateTokens returns the host candidates in an arg, mirroring the gate's
// extractor. It splits on whitespace, commas, and quotes. In each piece it
// strips leading key= prefixes (a key with no '/', '?' or '#', so nested
// --x=a=127.1 works while a URL query like ?v=2.0 is left alone). Then, for
// every segment of the piece split on "://", it cuts at the first '/', '?'
// or '#' so path, query, and fragment segments (2.0 in /path/2.0/x, 5.0 in
// Mozilla/5.0) never become candidates, and splits the authority on '@', ':',
// '[' and ']' to recover user@host, host:port, and [ipv6]:port hosts.
func candidateTokens(arg string) []string {
	var out []string
	pieces := strings.FieldsFunc(arg, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(",'\"", r)
	})
	for _, p := range pieces {
		for {
			i := strings.IndexByte(p, '=')
			if i < 0 || strings.ContainsAny(p[:i], "/?#") {
				break
			}
			p = p[i+1:]
		}
		// Every segment is processed alike: segment 0 may be a scheme-less
		// host with a path (127.1/x?u=http://...). A bare scheme is not numeric
		// and is rejected by plausibleNumericHost.
		segs := strings.Split(p, "://")
		for _, seg := range segs {
			if j := strings.IndexAny(seg, "/?#"); j >= 0 {
				seg = seg[:j]
			}
			out = append(out, strings.FieldsFunc(seg, func(r rune) bool {
				return strings.ContainsRune("@:[]", r)
			})...)
		}
	}
	return out
}

// skipZeroNet reports whether ip is in 0.0.0.0/8 other than exactly 0.0.0.0.
// Version-like args (--tls-max 0.5) canonicalize there; 0.0.0.0 itself is kept
// because it reaches loopback on Linux and macOS.
func skipZeroNet(ip string) bool {
	return strings.HasPrefix(ip, "0.") && ip != "0.0.0.0"
}

// plausibleNumericHost reports whether tok looks like a numeric host rather
// than a port or count: it has a dot (127.1), is an all-digit string of at
// least 8 characters (packed decimal 2130706433), or is a 0x hex literal with
// at least 3 hex digits (0x7f000001).
func plausibleNumericHost(tok string) bool {
	switch {
	case strings.Contains(tok, "."):
		return true
	case len(tok) >= 8 && allDigits(tok):
		return true
	case len(tok) >= 5 && isHexLiteral(tok):
		return true
	}
	return false
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
