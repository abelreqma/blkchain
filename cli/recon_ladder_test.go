package main

import (
	"testing"

	"blkchain/cli/internal/engagement"
)

func TestLadderForNetworkIsReferenceLadder(t *testing.T) {
	l := ladderFor(engagement.SurfaceNetwork)
	want := []struct {
		name string
		dims []string
	}{
		{"host-discovery", []string{"hosts"}},
		{"port-service-sweep", []string{"ports", "services"}},
		{"version-safe-script-enum", []string{"versions", "safe-scripts"}},
		{"finding-driven-probes", []string{"probes"}},
	}
	if len(l) != len(want) {
		t.Fatalf("network ladder has %d tiers, want %d", len(l), len(want))
	}
	for i, w := range want {
		if l[i].Index != i {
			t.Errorf("tier %d Index = %d, want %d", i, l[i].Index, i)
		}
		if l[i].Name != w.name {
			t.Errorf("tier %d Name = %q, want %q", i, l[i].Name, w.name)
		}
		if len(l[i].Dimensions) != len(w.dims) {
			t.Fatalf("tier %d has %d dims, want %d", i, len(l[i].Dimensions), len(w.dims))
		}
		for j, d := range w.dims {
			if l[i].Dimensions[j] != d {
				t.Errorf("tier %d dim %d = %q, want %q", i, j, l[i].Dimensions[j], d)
			}
		}
	}
}

// TestRegisterLadderMakesLadderRetrievable pins the registration seam: a ladder
// registered for a surface is returned by ladderFor, while an unregistered
// surface still falls back to the generic single-tier ladder.
func TestRegisterLadderMakesLadderRetrievable(t *testing.T) {
	const s = engagement.Surface("ladder-test-surface")
	custom := reconLadder{{Index: 0, Name: "custom-tier", Dimensions: []string{"custom"}}}
	registerLadder(s, custom)
	t.Cleanup(func() { delete(surfaceLadders, s) })

	l := ladderFor(s)
	if len(l) != 1 || l[0].Name != "custom-tier" {
		t.Fatalf("ladderFor(registered) = %+v, want the registered custom ladder", l)
	}
	if g := ladderFor(engagement.Surface("ladder-no-such-surface")); len(g) != 1 || g[0].Name != "enumerate" {
		t.Fatalf("ladderFor(unregistered) = %+v, want generic fallback", g)
	}
}

func TestLadderForUnknownSurfaceFallsBackToGeneric(t *testing.T) {
	// A synthetic surface nothing registers: real surfaces (e.g. SurfaceWeb)
	// now have dedicated ladders, so the fallback must be probed with a surface
	// that stays unregistered.
	l := ladderFor(engagement.Surface("web-registry-probe-surface"))
	if len(l) != 1 {
		t.Fatalf("generic fallback ladder has %d tiers, want 1", len(l))
	}
	if l[0].Name != "enumerate" || len(l[0].Dimensions) != 1 || l[0].Dimensions[0] != "enumerated" {
		t.Fatalf("generic fallback tier = %+v, want {0, enumerate, [enumerated]}", l[0])
	}
}

func covWith(dims map[string]engagement.ReconDimStatus) engagement.ReconCoverage {
	return engagement.ReconCoverage{Surface: engagement.SurfaceNetwork, Asset: "10.0.0.1", Dimensions: dims}
}

func TestChecklistCompleteTrueWhenAllCovered(t *testing.T) {
	l := ladderFor(engagement.SurfaceNetwork)
	cov := covWith(map[string]engagement.ReconDimStatus{
		"hosts": engagement.ReconCovered, "ports": engagement.ReconCovered,
		"services": engagement.ReconCovered, "versions": engagement.ReconCovered,
		"safe-scripts": engagement.ReconCovered, "probes": engagement.ReconCovered,
	})
	if !checklistComplete(l, cov) {
		t.Fatalf("checklistComplete = false, want true when every dimension covered")
	}
}

func TestChecklistCompleteFalseWhenAnyPending(t *testing.T) {
	l := ladderFor(engagement.SurfaceNetwork)
	cov := covWith(map[string]engagement.ReconDimStatus{
		"hosts": engagement.ReconCovered, "ports": engagement.ReconPending,
	})
	if checklistComplete(l, cov) {
		t.Fatalf("checklistComplete = true, want false when a dimension is pending/missing")
	}
}

func TestNextTierReturnsFirstIncomplete(t *testing.T) {
	l := ladderFor(engagement.SurfaceNetwork)

	cov := covWith(map[string]engagement.ReconDimStatus{"hosts": engagement.ReconCovered})
	tier, ok := nextTier(l, cov)
	if !ok {
		t.Fatalf("nextTier returned ok=false, want the first incomplete tier")
	}
	if tier.Index != 1 || tier.Name != "port-service-sweep" {
		t.Fatalf("nextTier = %+v, want tier 1 port-service-sweep", tier)
	}

	full := covWith(map[string]engagement.ReconDimStatus{
		"hosts": engagement.ReconCovered, "ports": engagement.ReconCovered,
		"services": engagement.ReconCovered, "versions": engagement.ReconCovered,
		"safe-scripts": engagement.ReconCovered, "probes": engagement.ReconCovered,
	})
	if _, ok := nextTier(l, full); ok {
		t.Fatalf("nextTier returned ok=true for a fully covered checklist, want false")
	}
}
