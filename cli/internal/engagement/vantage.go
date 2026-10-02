package engagement

// Vantage is the engagement's current access context: the position from which
// the operator acts. It advances monotonically as access-yielding exploits
// succeed. An empty
// Vantage ("") means unset: the executor does not gate surfaces by vantage until
// one is explicitly set.
type Vantage string

const (
	VantageExternalUnauth   Vantage = "external-unauth"
	VantageExternalAuth     Vantage = "external-auth"
	VantageInternalFoothold Vantage = "internal-foothold"
	VantageLocalElevated    Vantage = "local-elevated"
	VantageLateralDomain    Vantage = "lateral-domain"
)

var vantageRank = map[Vantage]int{
	VantageExternalUnauth:   0,
	VantageExternalAuth:     1,
	VantageInternalFoothold: 2,
	VantageLocalElevated:    3,
	VantageLateralDomain:    4,
}

func (v Vantage) valid() bool { _, ok := vantageRank[v]; return ok }
func (v Vantage) rank() int   { return vantageRank[v] }

// Reaches reports whether surface s is reachable from vantage v. The externally
// reachable surfaces (network, web, cloud and its per-CSP variants, container,
// and ai-security) are reachable at any vantage; local and ad require an
// internal foothold or better (the pivot that external->internal access
// unlocks). An unknown surface is not reachable (fail closed).
func (v Vantage) Reaches(s Surface) bool {
	switch s {
	case SurfaceNetwork, SurfaceWeb, SurfaceCloud, SurfaceCloudAWS,
		SurfaceCloudGCP, SurfaceCloudAzure, SurfaceContainer, SurfaceAISecurity:
		return true
	case SurfaceLocal, SurfaceAD:
		return v.rank() >= VantageInternalFoothold.rank()
	}
	return false
}
