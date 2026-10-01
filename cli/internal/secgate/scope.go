package secgate

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// scopeMatcher matches a target string (hostname or IP text) against one scope
// entry.
type scopeMatcher struct {
	host string     // set for an exact hostname (lowercased) match
	ip   net.IP     // set for an exact IP match
	cidr *net.IPNet // set for a CIDR match
}

func (m scopeMatcher) matches(target string) bool {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return false
	}
	if m.cidr != nil {
		if ip := net.ParseIP(t); ip != nil {
			return m.cidr.Contains(ip)
		}
		return false
	}
	if m.ip != nil {
		if ip := net.ParseIP(t); ip != nil {
			return m.ip.Equal(ip)
		}
		return false
	}
	return m.host != "" && m.host == t
}

// parseMatcher parses one scope entry into a matcher, or errors.
func parseMatcher(entry string) (scopeMatcher, error) {
	e := strings.TrimSpace(entry)
	if _, cidr, err := net.ParseCIDR(e); err == nil {
		return scopeMatcher{cidr: cidr}, nil
	}
	if ip := net.ParseIP(e); ip != nil {
		return scopeMatcher{ip: ip}, nil
	}
	if isHostname(e) {
		return scopeMatcher{host: strings.ToLower(e)}, nil
	}
	return scopeMatcher{}, fmt.Errorf("secgate: malformed scope entry %q", entry)
}

// isHostname reports whether s is a plausible DNS hostname (labels of
// alphanumerics and hyphens, dots between). It is deliberately strict so a
// malformed scope line is rejected rather than silently accepted.
func isHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	// No valid DNS TLD is all-numeric. Requiring a letter in the last label
	// rejects tokens that are malformed IPs or that inet_aton-style parsers
	// would reinterpret as IPs (10.0.0.256, 2130706433, 010.0.0.5, 10.0.0.5-9).
	last := labels[len(labels)-1]
	// A 0x-prefixed hex literal (0x7f000001, 127.0.0.0x1) is also reinterpreted
	// as an IP by inet_aton-style parsers, so reject it even though it has letters.
	return hasASCIILetter(last) && !isHexLiteral(last) // single-label hosts allowed
}

// isHexLiteral reports whether s is "0x" or "0X" followed by one or more hex digits.
func isHexLiteral(s string) bool {
	if len(s) < 3 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return false
	}
	for i := 2; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func hasASCIILetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// Scope is a parsed engagement scope: in-scope and out-of-scope target matchers.
type Scope struct {
	in        []scopeMatcher
	out       []scopeMatcher
	local     bool
	allowBins []string

	targets []string
	rate    *RateLimit
}

// RateLimit is a parsed "## Rate" policy: at most N admitted commands per Per
// window. The gate enforces it over every gated command.
type RateLimit struct {
	N   int
	Per time.Duration
}

// ScopeSpec is the structured input a parsed ROE.md hands to BuildScope: the
// In Scope / Out of Scope / Targets entries and the optional Rate string. The
// ROE.md markdown parser (cli/roe.go) owns sectioning; BuildScope owns matcher
// and rate parsing and the fail-closed validation.
type ScopeSpec struct {
	In      []string
	Out     []string
	Targets []string
	Rate    string // "" means no rate limit
}

// BuildScope parses a ScopeSpec into a Scope. Every In and Out entry is parsed
// by parseMatcher, so a malformed entry fails closed (returns an error and a nil
// Scope - a broken RoE never yields a permissive scope). Targets are stored
// verbatim. An empty Rate string means no rate limit; a non-empty malformed Rate
// is an error.
func BuildScope(spec ScopeSpec) (*Scope, error) {
	s := &Scope{}
	for _, e := range spec.In {
		if strings.TrimSpace(e) == "" {
			continue
		}
		m, err := parseMatcher(e)
		if err != nil {
			return nil, fmt.Errorf("in-scope: %w", err)
		}
		s.in = append(s.in, m)
	}
	for _, e := range spec.Out {
		if strings.TrimSpace(e) == "" {
			continue
		}
		m, err := parseMatcher(e)
		if err != nil {
			return nil, fmt.Errorf("out-of-scope: %w", err)
		}
		s.out = append(s.out, m)
	}
	for _, tg := range spec.Targets {
		if t := strings.TrimSpace(tg); t != "" {
			s.targets = append(s.targets, t)
		}
	}
	if strings.TrimSpace(spec.Rate) != "" {
		r, err := parseRate(spec.Rate)
		if err != nil {
			return nil, err
		}
		s.rate = &r
	}
	return s, nil
}

// parseRate parses a "N/unit" rate string. unit is one of s, m, h (also the
// spellings sec/second, min/minute, hr/hour). N must be a positive integer. An
// empty or malformed string is an error (fail closed).
func parseRate(s string) (RateLimit, error) {
	t := strings.TrimSpace(s)
	i := strings.IndexByte(t, '/')
	if i < 0 {
		return RateLimit{}, fmt.Errorf("secgate: malformed rate %q (want N/s, N/m, or N/h)", s)
	}
	nStr := strings.TrimSpace(t[:i])
	unit := strings.TrimSpace(t[i+1:])
	n, err := strconv.Atoi(nStr)
	if err != nil || n < 1 {
		return RateLimit{}, fmt.Errorf("secgate: rate count must be a positive integer in %q", s)
	}
	var per time.Duration
	switch strings.ToLower(unit) {
	case "s", "sec", "second":
		per = time.Second
	case "m", "min", "minute":
		per = time.Minute
	case "h", "hr", "hour":
		per = time.Hour
	default:
		return RateLimit{}, fmt.Errorf("secgate: unknown rate unit %q (want s, m, or h)", unit)
	}
	return RateLimit{N: n, Per: per}, nil
}

// Targets returns the informational engagement targets from "## Targets".
func (s *Scope) Targets() []string { return append([]string(nil), s.targets...) }

// Rate returns the scope's rate limit and whether one is set.
func (s *Scope) Rate() (RateLimit, bool) {
	if s.rate == nil {
		return RateLimit{}, false
	}
	return *s.rate, true
}

// ParseScope reads a line-based scope file. Blank lines and lines beginning with
// '#' are ignored. A line beginning '!' is an out-of-scope exclusion; any other
// non-blank line is an in-scope entry. The line "local" (case-insensitive)
// authorizes local commands, and "allow <binary>" adds a binary to the scope's
// allow-list. A malformed entry is an error (fail
// closed: a broken scope file never yields a permissive scope).
func ParseScope(r io.Reader) (*Scope, error) {
	s := &Scope{}
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if strings.EqualFold(raw, "local") {
			s.local = true
			continue
		}
		if f := strings.Fields(raw); len(f) == 2 && strings.EqualFold(f[0], "allow") {
			b := baseName(f[1])
			if b == "" {
				return nil, fmt.Errorf("scope line %d: allow needs a binary name", line)
			}
			s.allowBins = append(s.allowBins, b)
			continue
		}
		out := false
		if strings.HasPrefix(raw, "!") {
			out = true
			raw = strings.TrimSpace(raw[1:])
		}
		m, err := parseMatcher(raw)
		if err != nil {
			return nil, fmt.Errorf("scope line %d: %w", line, err)
		}
		if out {
			s.out = append(s.out, m)
		} else {
			s.in = append(s.in, m)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return s, nil
}

// InScope reports whether target is in scope. Out-of-scope matches win; an empty
// in-scope list matches nothing.
func (s *Scope) InScope(target string) bool {
	for _, m := range s.out {
		if m.matches(target) {
			return false
		}
	}
	for _, m := range s.in {
		if m.matches(target) {
			return true
		}
	}
	return false
}

// Empty reports whether the scope has no in-scope entries.
func (s *Scope) Empty() bool { return len(s.in) == 0 }

// Local reports whether the scope authorizes running commands on the local host
// (a local engagement), which permits commands with no network target.
func (s *Scope) Local() bool { return s.local }

// AllowedBins returns the base names from `allow <binary>` scope lines.
func (s *Scope) AllowedBins() []string { return append([]string(nil), s.allowBins...) }
