package secgate

import (
	"net"
	"strings"
	"testing"
)

func mustScope(t *testing.T, text string) *Scope {
	t.Helper()
	s, err := ParseScope(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestNetworkInScopeContainment is the two-sided audit of the relaxation. A
// network is authorized only when one in-scope CIDR covers all of it and nothing
// excluded shares an address with it.
func TestNetworkInScopeContainment(t *testing.T) {
	cases := []struct {
		scope  string
		target string
		want   bool
		why    string
	}{
		{"10.0.0.0/24\n", "10.0.0.0/24", true, "exactly the authorized range"},
		{"10.0.0.0/24\n", "10.0.0.128/25", true, "a subnet of the authorized range"},
		{"10.0.0.0/24\n", "10.0.0.7/32", true, "a single host inside it"},
		{"10.0.0.0/8\n", "10.255.255.0/24", true, "a subnet at the far end of a large range"},
		{"10.0.0.0/24\n", "10.0.0.0/16", false, "wider than anything authorized"},
		{"10.0.0.0/24\n", "10.0.1.0/24", false, "adjacent but outside"},
		{"10.0.0.0/24\n", "0.0.0.0/0", false, "the whole internet"},
		{"10.0.0.64/26\n", "10.0.0.0/25", false, "overlaps the authorized range but reaches below it"},
		{"10.0.0.64/26\n", "10.0.0.64/27", true, "a subnet of a mid-range authorized block"},
		{"10.0.0.0/24\n", "10.0.0.254/31", true, "the top pair of the authorized range"},
		// An exclusion anywhere inside the range refuses the whole range: a sweep
		// cannot skip one address, so out of scope wins.
		{"10.0.0.0/24\n!10.0.0.5\n", "10.0.0.0/24", false, "an excluded host sits inside"},
		{"10.0.0.0/24\n!10.0.0.0/25\n", "10.0.0.0/24", false, "an excluded subnet overlaps"},
		{"10.0.0.0/24\n!10.0.0.0/25\n", "10.0.0.128/25", true, "the excluded subnet is disjoint from this target"},
		{"10.0.0.0/24\n!10.9.9.9\n", "10.0.0.0/24", true, "the exclusion is elsewhere"},
		// Containment must come from one authorized entry, not a union that
		// happens to cover the target between several entries.
		{"10.0.0.0/25\n10.0.0.128/25\n", "10.0.0.0/24", false, "covered only by a union"},
		// A single authorized host authorizes exactly its own address.
		{"10.0.0.5\n", "10.0.0.5/32", true, "the authorized host as a /32"},
		{"10.0.0.5\n", "10.0.0.4/31", false, "a /31 reaches an address that is not authorized"},
		// A hostname entry has no address range, so it authorizes no network.
		{"corp.example\n", "10.0.0.0/24", false, "a hostname authorizes no range"},
		// Families never compare.
		{"10.0.0.0/8\n", "2001:db8::/32", false, "a v6 network against a v4 scope"},
		{"2001:db8::/32\n", "10.0.0.0/24", false, "a v4 network against a v6 scope"},
		{"2001:db8::/32\n", "2001:db8:1::/48", true, "a v6 subnet of a v6 scope"},
	}
	for _, c := range cases {
		s := mustScope(t, c.scope)
		if got := s.NetworkInScope(mustNet(t, c.target)); got != c.want {
			t.Errorf("scope %q NetworkInScope(%s) = %t, want %t (%s)",
				strings.ReplaceAll(c.scope, "\n", " "), c.target, got, c.want, c.why)
		}
	}
	// A nil scope and a malformed network authorize nothing.
	var nilScope *Scope
	if nilScope.NetworkInScope(mustNet(t, "10.0.0.0/24")) {
		t.Error("a nil scope must authorize no network")
	}
	if mustScope(t, "10.0.0.0/24\n").NetworkInScope(nil) {
		t.Error("a nil network must not be authorized")
	}
}

// TestTargetInScopeRoutesByShape asserts the one entry point the gate uses sends
// a host to InScope and a network to NetworkInScope.
func TestTargetInScopeRoutesByShape(t *testing.T) {
	s := mustScope(t, "10.0.0.0/24\n")
	for target, want := range map[string]bool{
		"10.0.0.5":     true,
		"10.0.1.5":     false,
		"10.0.0.0/25":  true,
		"10.0.0.0/16":  false,
		"not-a-target": false,
	} {
		if got := s.TargetInScope(target); got != want {
			t.Errorf("TargetInScope(%q) = %t, want %t", target, got, want)
		}
	}
}

// TestExtractTargetsStillRefusesNetworks pins the contract every existing caller
// relies on: a caller that cannot judge a whole network still sees a network
// argument as unverifiable, so only the layers that opted in through
// ExtractTargetSet decide one.
func TestExtractTargetsStillRefusesNetworks(t *testing.T) {
	c := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.0/24"}}
	if _, ok := ExtractTargets(c); ok {
		t.Error("ExtractTargets must report a network argument as unverifiable")
	}
	hosts, nets, ok := ExtractTargetSet(c)
	if !ok || len(nets) != 1 || nets[0].String() != "10.0.0.0/24" || len(hosts) != 0 {
		t.Fatalf("ExtractTargetSet = %v %v %t", hosts, nets, ok)
	}
	// A host argument behaves identically on both contracts.
	host := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}
	h1, ok1 := ExtractTargets(host)
	h2, nets2, ok2 := ExtractTargetSet(host)
	if !ok1 || !ok2 || len(nets2) != 0 || len(h1) != 1 || h1[0] != h2[0] {
		t.Fatalf("host contracts diverged: %v %t / %v %v %t", h1, ok1, h2, nets2, ok2)
	}
	// The network is normalized to the range a scanner sweeps.
	_, nets3, _ := ExtractTargetSet(Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5/24"}})
	if len(nets3) != 1 || nets3[0].String() != "10.0.0.0/24" {
		t.Fatalf("network not normalized: %v", nets3)
	}
}
