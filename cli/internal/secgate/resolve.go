package secgate

import "net"

// lookupIPFn resolves a host to IPs; a var so tests can stub it.
var lookupIPFn = net.LookupIP

// resolveScopeViolationWith rejects hostname resolutions outside the active scope.
func resolveScopeViolationWith(s *Scope, c Command, lookup func(string) ([]net.IP, error), webAllowed func(string, net.IP) bool) (host string, ip string, violation bool) {
	if s == nil {
		return "", "", false
	}
	targets, _ := ExtractTargets(c)
	for _, t := range targets {
		if net.ParseIP(t) != nil {
			continue
		}
		if lookup == nil {
			return t, "", true
		}
		ips, err := lookup(t)
		if err != nil || len(ips) == 0 {
			return t, "", true
		}
		for _, resolved := range ips {
			allowed := s.InScope(resolved.String())
			if c.Surface == SurfaceWeb {
				allowed = webAllowed(t, resolved)
			}
			if !allowed {
				return t, resolved.String(), true
			}
		}
	}
	return "", "", false
}
