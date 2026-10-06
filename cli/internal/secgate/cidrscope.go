package secgate

import "net"

// cidrscope.go decides whether a whole network may be a command's target. The
// token reader used to refuse every CIDR argument ("a whole network cannot be
// checked as one host"), which denied the ordinary sweep of a range the operator
// put in scope and left masscan with nothing it could do that nmap could not.
//
// A network target is allowed only when it is wholly inside one in-scope CIDR
// and touches nothing excluded. Containment is deliberately strict: it needs a
// single in-scope CIDR that covers the whole target, not a union of in-scope
// entries that happens to cover it between them, because a union argument is
// only as good as the enumeration behind it and an operator who authorized a
// range writes that range.

// networkRange is the first and last address of a network, which is all the
// containment and overlap tests need.
type networkRange struct{ first, last net.IP }

// rangeOf returns the address range of n, or ok=false when n is unusable.
func rangeOf(n *net.IPNet) (networkRange, bool) {
	if n == nil || n.IP == nil || n.Mask == nil {
		return networkRange{}, false
	}
	first := n.IP.Mask(n.Mask)
	if first == nil {
		return networkRange{}, false
	}
	last := make(net.IP, len(first))
	for i := range first {
		last[i] = first[i] | ^n.Mask[i]
	}
	return networkRange{first: first, last: last}, true
}

// contains reports whether r covers every address of other.
func (r networkRange) contains(other networkRange) bool {
	return bytesLessOrEqual(r.first, other.first) && bytesLessOrEqual(other.last, r.last)
}

// overlaps reports whether r and other share any address.
func (r networkRange) overlaps(other networkRange) bool {
	return bytesLessOrEqual(r.first, other.last) && bytesLessOrEqual(other.first, r.last)
}

// bytesLessOrEqual compares two addresses of the same family. Addresses of
// different families never compare, which keeps a v4 network from being judged
// inside a v6 one.
func bytesLessOrEqual(a, b net.IP) bool {
	a4, b4 := a.To4(), b.To4()
	switch {
	case a4 != nil && b4 != nil:
		a, b = a4, b4
	case a4 != nil || b4 != nil:
		return false
	default:
		a, b = a.To16(), b.To16()
		if a == nil || b == nil {
			return false
		}
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return true
}

// matcherRange returns the address range a scope matcher covers, for the IP and
// CIDR forms. A hostname matcher has no range.
func matcherRange(m scopeMatcher) (networkRange, bool) {
	if m.cidr != nil {
		return rangeOf(m.cidr)
	}
	if m.ip != nil {
		return networkRange{first: m.ip, last: m.ip}, true
	}
	return networkRange{}, false
}

// NetworkInScope reports whether every address of n is authorized: one in-scope
// CIDR or exact IP covers the whole network, and no out-of-scope entry shares a
// single address with it. Out of scope always wins, so an excluded host inside
// an authorized range refuses the whole range rather than silently sweeping it.
func (s *Scope) NetworkInScope(n *net.IPNet) bool {
	if s == nil {
		return false
	}
	target, ok := rangeOf(n)
	if !ok {
		return false
	}
	for _, m := range s.out {
		if r, ok := matcherRange(m); ok && r.overlaps(target) {
			return false
		}
	}
	for _, m := range s.in {
		if r, ok := matcherRange(m); ok && r.contains(target) {
			return true
		}
	}
	return false
}

// TargetInScope checks one extracted target, which may be a single host or a
// whole network. It is what the gate calls: InScope answers for a host, and
// NetworkInScope answers for a CIDR.
func (s *Scope) TargetInScope(target string) bool {
	if _, n, err := net.ParseCIDR(target); err == nil {
		return s.NetworkInScope(n)
	}
	return s.InScope(target)
}
