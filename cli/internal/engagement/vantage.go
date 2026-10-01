package engagement

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

// Reaches reports whether surface s is reachable from vantage v. Network and web
// surfaces are reachable externally; local and ad-cloud require an internal
// foothold or better (the pivot that external->internal access unlocks).
func (v Vantage) Reaches(s Surface) bool {
	switch s {
	case SurfaceNetwork, SurfaceWeb:
		return true
	case SurfaceLocal, SurfaceADCloud:
		return v.rank() >= VantageInternalFoothold.rank()
	}
	return false
}
