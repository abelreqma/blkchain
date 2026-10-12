package secgate

import (
	"fmt"
	"net"
)

func PrivateNetwork(cidr string) (string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil || network.String() != cidr {
		return "", fmt.Errorf("approved network must be a canonical CIDR")
	}
	target, ok := rangeOf(network)
	if !ok {
		return "", fmt.Errorf("invalid approved network")
	}
	for _, block := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		_, private, _ := net.ParseCIDR(block)
		if private.Contains(target.first) && private.Contains(target.last) {
			return cidr, nil
		}
	}
	return "", fmt.Errorf("approved network must be private")
}

func (s *Scope) WithApprovedPrivateNetworks(networks []string) (*Scope, error) {
	if s == nil {
		return nil, fmt.Errorf("approved networks require a base scope")
	}
	copy := *s
	copy.in = append([]scopeMatcher(nil), s.in...)
	copy.out = append([]scopeMatcher(nil), s.out...)
	for _, cidr := range networks {
		if _, err := PrivateNetwork(cidr); err != nil {
			return nil, err
		}
		_, network, _ := net.ParseCIDR(cidr)
		copy.in = append(copy.in, scopeMatcher{cidr: network})
	}
	return &copy, nil
}

func (g *Gate) scopeFor(c Command) *Scope {
	if g.PivotScope != nil && g.execOffHost(c) {
		return g.PivotScope
	}
	return g.Scope
}
