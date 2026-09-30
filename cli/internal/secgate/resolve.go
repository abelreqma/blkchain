package secgate

import "net"

// lookupIPFn resolves a host to IPs; a var so tests can stub it.
var lookupIPFn = net.LookupIP

// ResolveScopeViolation resolves every hostname target of c (bare IPs are
// skipped, InScope already checked them) and reports the first host whose
// resolution fails or contains any IP outside the scope. A resolver error or an
// empty result fails closed with an empty ip. A nil scope never violates.
//
// This closes the check-time DNS gap only. A tool that re-resolves the name
// itself at exec time can still see a different answer; the harness cannot
// intercept an external resolver, so that residual TOCTOU is not closed here.
func ResolveScopeViolation(s *Scope, c Command) (host string, ip string, violation bool) {
	if s == nil {
		return "", "", false
	}
	targets, _ := ExtractTargets(c)
	for _, t := range targets {
		if net.ParseIP(t) != nil {
			continue
		}
		ips, err := lookupIPFn(t)
		if err != nil || len(ips) == 0 {
			return t, "", true
		}
		for _, resolved := range ips {
			if !s.InScope(resolved.String()) {
				return t, resolved.String(), true
			}
		}
	}
	return "", "", false
}
