package main

import "blkchain/cli/internal/engagement"

// adExecutor runs SurfaceAD tasks. It embeds genericExecutor and delegates Run,
// inheriting unchanged: the vantage reachability check (SurfaceAD requires
// internal-foothold+), the recon/exploit phase routing, the gate stamping of
// Phase/Surface/Armed on every run_command, help-grounding, and code-owned
// evidence capture. The AD-specific behavior is the registered recon ladder
// (adLadder) and the existing "ad" persona in domains.go, both keyed by surface so
// they take effect through the shared recon path (recon.go ladderFor(d.Surface);
// domains.go domainFor(task.Kind)).
type adExecutor struct {
	genericExecutor
}

// AD recon tier names. Enumeration -> targeted enum -> finding-driven, all
// recon-phase (auto tier) and all served by already-allowlisted enumeration tools.
const (
	adTierDCDiscovery   = "ad-dc-discovery"
	adTierAnonEnum      = "ad-anon-enum"
	adTierAuthEnum      = "ad-auth-enum"
	adTierFindingDriven = "ad-finding-driven"
)

var adLadder = reconLadder{
	{Index: 0, Name: adTierDCDiscovery, Dimensions: []string{"dcs", "domain"}},
	{Index: 1, Name: adTierAnonEnum, Dimensions: []string{"naming-contexts", "null-sessions"}},
	{Index: 2, Name: adTierAuthEnum, Dimensions: []string{"users", "groups", "computers"}},
	{Index: 3, Name: adTierFindingDriven, Dimensions: []string{"spns", "delegation", "acls", "adcs"}},
}

// init registers the AD executor and its recon ladder via the shared seams
// (surfaceexec.go, recon_ladder.go), so this file owns all SurfaceAD wiring and no
// shared file is edited. The "ad" persona already exists in domains.go and is
// reused by domainFor("ad"); it is intentionally not re-registered.
func init() {
	registerExecutor(engagement.SurfaceAD, func(d engageDeps) surfaceExecutor {
		return adExecutor{genericExecutor{d: d}}
	})
	registerLadder(engagement.SurfaceAD, adLadder)
}
