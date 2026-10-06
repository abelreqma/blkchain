package secgate

import "net"

// recheck runs the exec-time rechecks that cannot be decided from the command
// structure alone: an already-resolved out-of-scope literal (ScopeViolation), a
// hostname that resolves out of scope (ResolveScopeViolation, does DNS), and a
// file-path/config-indirection violation (FileAccessViolation). It runs OUTSIDE
// g.mu - it does network I/O and only touches the concurrency-safe audit func -
// and is composed into the tail of both Authorize and Check so the two deny
// identically. A nil Scope makes the scope rechecks no-ops.
//
// The two scope rechecks (ScopeViolation, ResolveScopeViolation) are skipped
// when the scope is LOCAL with no in-scope network entries (Scope.Local() &&
// Scope.Empty()). This mirrors checkLocked's own local-profile policy: a
// scope of "local" alone authorizes local execution with no network target to
// scope, so checkLocked's scope check does not run for it either. Recheck must
// not independently re-impose a scope restriction checkLocked deliberately
// waives, or every local command with a literal IP argument (nc, nmap, curl,
// ...) would be denied under a bare "local" scope, which is the common case.
// A LOCAL scope that also lists network entries still gets both rechecks.
func (g *Gate) recheck(c Command) Decision {
	skipScopeRecheck := g.Scope != nil && g.Scope.Local() && g.Scope.Empty()
	if !skipScopeRecheck {
		if ip, ok := ScopeViolation(g.Scope, c); ok {
			g.audit(denialAction(c, "scope-recheck"), Signature(c))
			return Decision{Allowed: false, Reason: "a target resolves to an out-of-scope address: " + ip}
		}
		if host, ip, bad := ResolveScopeViolation(g.Scope, c); bad {
			g.audit(denialAction(c, "resolve"), Signature(c))
			if ip != "" {
				return Decision{Allowed: false, Reason: host + " resolves to an out-of-scope address: " + ip}
			}
			return Decision{Allowed: false, Reason: "could not resolve " + host + " to verify it is in scope"}
		}
	}
	if g.Policy != nil {
		if c.Surface != SurfaceWeb {
			ips := g.Policy.CommandIPs
			if ips == nil {
				ips = g.Scope
			}
			targets, nets, _ := ExtractTargetSet(c)
			for _, n := range nets {
				// A network target is re-checked against the same explicit IP scope
				// as a host: the exec-time recheck is the layer that catches a scope
				// that changed between authorization and execution.
				if ips == nil || ips.Empty() || !ips.NetworkInScope(n) {
					g.audit("deny:scope-recheck", Signature(c))
					return Decision{Reason: "command destination needs an explicit in-scope IP or CIDR entry"}
				}
			}
			for _, target := range targets {
				if ips == nil || ips.Empty() {
					g.audit("deny:scope-recheck", Signature(c))
					return Decision{Reason: "command destination needs an explicit in-scope IP or CIDR entry"}
				}
				if ip := net.ParseIP(target); ip != nil {
					if !ips.InScope(ip.String()) {
						g.audit("deny:scope-recheck", Signature(c))
						return Decision{Reason: "command destination needs an explicit in-scope IP or CIDR entry"}
					}
					continue
				}
				resolved, err := lookupIPFn(target)
				if err != nil || len(resolved) == 0 {
					g.audit("deny:resolve", Signature(c))
					return Decision{Reason: "command destination could not be resolved into the explicit IP scope"}
				}
				for _, ip := range resolved {
					if !ips.InScope(ip.String()) {
						g.audit("deny:scope-recheck", Signature(c))
						return Decision{Reason: "command destination needs an explicit in-scope IP or CIDR entry"}
					}
				}
			}
		}
		return Decision{Allowed: true}
	}
	if arg, bad := FileAccessViolation(c); bad {
		g.audit(denialAction(c, "fileaccess"), Signature(c))
		return Decision{Allowed: false, Reason: "file path outside the working directory, or a config-file option, is not allowed: " + arg}
	}
	return Decision{Allowed: true}
}
