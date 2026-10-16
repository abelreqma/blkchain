package secgate

import "net"

// internalNetworks are blocks that route to a private, shared, reserved or
// tunnel-relay destination rather than to one public host. Go reports most of
// them as global unicast, so IsGlobalUnicast alone does not exclude them.
var internalNetworks = func() []*net.IPNet {
	var out []*net.IPNet
	for _, cidr := range []string{
		"0.0.0.0/8",      // "this network", RFC 1122
		"100.64.0.0/10",  // shared address space, RFC 6598
		"198.18.0.0/15",  // benchmarking, RFC 2544
		"240.0.0.0/4",    // reserved, RFC 1112
		"fec0::/10",      // site-local, RFC 3879
		"2001::/32",      // Teredo, RFC 4380
		"64:ff9b:1::/48", // local-use NAT64, RFC 8215
	} {
		_, network, _ := net.ParseCIDR(cidr)
		out = append(out, network)
	}
	return out
}()

var (
	sixToFour = func() *net.IPNet { _, n, _ := net.ParseCIDR("2002::/16"); return n }()
	nat64     = func() *net.IPNet { _, n, _ := net.ParseCIDR("64:ff9b::/96"); return n }()
)

// InternalAddress reports whether ip is not a single public host: loopback,
// link-local, multicast, unspecified, private (RFC 1918, ULA), shared, reserved
// or a tunnel relay, including an IPv4 address embedded in an IPv4-mapped, 6to4
// (RFC 3056) or NAT64 (RFC 6052) address. A nil address is internal.
func InternalAddress(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return true
	}
	for _, network := range internalNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	if ip.To4() != nil {
		return false
	}
	if sixToFour.Contains(ip) {
		return InternalAddress(net.IPv4(ip[2], ip[3], ip[4], ip[5]))
	}
	if nat64.Contains(ip) {
		return InternalAddress(net.IPv4(ip[12], ip[13], ip[14], ip[15]))
	}
	return false
}
