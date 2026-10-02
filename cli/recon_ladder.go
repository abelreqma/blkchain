package main

import "blkchain/cli/internal/engagement"

// recon_ladder.go holds the per-surface recon tier ladders as code constants and
// the pure checklist helpers the tier loop uses to decide what to run next and
// when a surface/asset is saturated. The ladders are the deterministic backbone:
// the LLM proposes commands within a tier, but the tiers, their order, and the
// coverage dimensions they satisfy are fixed here.

// reconTier is one rung of a surface's recon ladder: an ordinal, a short name,
// and the coverage dimensions a pass of this tier is expected to satisfy.
type reconTier struct {
	Index      int
	Name       string
	Dimensions []string
}

// reconLadder is a surface's ordered tier ladder (lowest Index first).
type reconLadder []reconTier

// surfaceLadders maps each attack surface to its recon ladder. The network
// reference ladder is T0 host discovery -> T1 port/service sweep ->
// T2 version/safe-script enum -> T3 finding-driven probes. The other surfaces
// use genericReconLadder.
var surfaceLadders = map[engagement.Surface]reconLadder{
	engagement.SurfaceNetwork: {
		{Index: 0, Name: "host-discovery", Dimensions: []string{"hosts"}},
		{Index: 1, Name: "port-service-sweep", Dimensions: []string{"ports", "services"}},
		{Index: 2, Name: "version-safe-script-enum", Dimensions: []string{"versions", "safe-scripts"}},
		{Index: 3, Name: "finding-driven-probes", Dimensions: []string{"probes"}},
	},
}

// genericReconLadder is the single-tier fallback for a surface without its own
// ladder yet. One bounded enumerate pass, so a non-network surface still runs
// and saturates rather than looping.
var genericReconLadder = reconLadder{
	{Index: 0, Name: "enumerate", Dimensions: []string{"enumerated"}},
}

// registerLadder registers a recon ladder for a surface. It is the seam a future
// per-surface ladder fills from its OWN file via init(), so no two surface
// sessions edit this file. The network ladder above stays in-file (preserving
// today's behavior); ladderFor still falls back to genericReconLadder.
func registerLadder(surface engagement.Surface, l reconLadder) {
	surfaceLadders[surface] = l
}

// ladderFor returns the recon ladder for surface, or the generic fallback when
// the surface has no dedicated ladder.
func ladderFor(surface engagement.Surface) reconLadder {
	if l, ok := surfaceLadders[surface]; ok {
		return l
	}
	return genericReconLadder
}

// allDimensions returns every dimension across the ladder, in tier order.
func (l reconLadder) allDimensions() []string {
	out := []string{}
	for _, t := range l {
		out = append(out, t.Dimensions...)
	}
	return out
}

// checklistComplete reports whether every dimension in the ladder is marked
// ReconCovered in cov. A missing dimension counts as not covered.
func checklistComplete(l reconLadder, cov engagement.ReconCoverage) bool {
	for _, dim := range l.allDimensions() {
		if cov.Dimensions[dim] != engagement.ReconCovered {
			return false
		}
	}
	return true
}

// nextTier returns the first tier (lowest Index) with any dimension not yet
// ReconCovered, so a resumed run re-enters at the first incomplete tier rather
// than redoing covered work. The second return is false when every dimension is
// covered (the asset is saturated on this surface).
func nextTier(l reconLadder, cov engagement.ReconCoverage) (reconTier, bool) {
	for _, t := range l {
		for _, dim := range t.Dimensions {
			if cov.Dimensions[dim] != engagement.ReconCovered {
				return t, true
			}
		}
	}
	return reconTier{}, false
}
