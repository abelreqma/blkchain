package secgate

import (
	"context"
	"strings"
	"testing"
)

func TestApprovedPrivateNetworkOnlyAppliesToPivotedSurface(t *testing.T) {
	base, err := ParseScope(strings.NewReader("203.0.113.10\n!10.7.0.5\n"))
	if err != nil {
		t.Fatal(err)
	}
	pivot, err := base.WithApprovedPrivateNetworks([]string{"10.7.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if base.InScope("10.7.0.7") || !pivot.InScope("10.7.0.7") || pivot.InScope("10.7.0.5") {
		t.Fatal("approval widened the base scope or bypassed an exclusion")
	}
	p := DefaultPolicy()
	p.Foothold = &Foothold{Host: "203.0.113.10", Surfaces: []Surface{SurfaceNetwork}}
	p.CommandIPs = base
	g := &Gate{Mode: Auto, Scope: base, PivotScope: pivot, Policy: p, Allow: NewAllowlist("nmap")}
	for _, tc := range []struct {
		surface Surface
		target  string
		allow   bool
	}{
		{SurfaceNetwork, "10.7.0.7", true},
		{SurfaceNetwork, "10.7.0.5", false},
		{SurfaceWeb, "10.7.0.7", false},
		{SurfaceNetwork, "10.8.0.7", false},
	} {
		d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "389", tc.target}, Phase: PhaseRecon, Surface: tc.surface})
		if d.Allowed != tc.allow {
			t.Errorf("surface=%s target=%s allowed=%t reason=%q", tc.surface, tc.target, d.Allowed, d.Reason)
		}
	}
	g.PivotScope = nil
	if d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "389", "10.7.0.7"}, Phase: PhaseRecon, Surface: SurfaceNetwork}); d.Allowed {
		t.Fatal("private target stayed authorized after removing the network approval")
	}
}

func TestApprovedPrivateNetworkRejectsPublicAndNoncanonical(t *testing.T) {
	s, err := ParseScope(strings.NewReader("203.0.113.10\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, cidr := range []string{"0.0.0.0/0", "8.8.8.0/24", "169.254.0.0/16", "10.7.0.1/24", "10.0.0.0/7", "fc00::/6"} {
		if _, err := s.WithApprovedPrivateNetworks([]string{cidr}); err == nil {
			t.Errorf("approved %s", cidr)
		}
	}
	if _, err := s.WithApprovedPrivateNetworks([]string{"fd00:7::/48"}); err != nil {
		t.Fatalf("private IPv6 network rejected: %v", err)
	}
}
