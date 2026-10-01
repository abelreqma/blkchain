package engagement

import (
	"context"
	"testing"
)

func TestVantageReaches(t *testing.T) {
	// Externally reachable surfaces open at any vantage; local and ad require an
	// internal foothold. cloud (and its per-CSP variants), container, and
	// ai-security are external per the operator's taxonomy decision.
	external := []Surface{
		SurfaceNetwork, SurfaceWeb, SurfaceCloud, SurfaceCloudAWS,
		SurfaceCloudGCP, SurfaceCloudAzure, SurfaceContainer, SurfaceAISecurity,
	}
	internalOnly := []Surface{SurfaceLocal, SurfaceAD}

	ext := VantageExternalUnauth
	for _, s := range external {
		if !ext.Reaches(s) {
			t.Errorf("external-unauth should reach %q", s)
		}
	}
	for _, s := range internalOnly {
		if ext.Reaches(s) {
			t.Errorf("external-unauth must NOT reach %q (needs foothold)", s)
		}
	}
	// internal-foothold reaches every surface in the canonical set.
	foot := VantageInternalFoothold
	for _, s := range AllSurfaces() {
		if !foot.Reaches(s) {
			t.Errorf("internal-foothold should reach %q", s)
		}
	}
}

func TestVantageAdvanceAndMonotonic(t *testing.T) {
	s := openTemp(t)
	v, err := s.Vantage(context.Background())
	if err != nil || v != "" {
		t.Fatalf("unset vantage = %q err=%v, want \"\"", v, err)
	}
	ext := VantageExternalUnauth
	if _, err := s.Apply(Delta{SetVantage: &ext}); err != nil {
		t.Fatal(err)
	}
	foot := VantageInternalFoothold
	if _, err := s.Apply(Delta{SetVantage: &foot}); err != nil {
		t.Fatalf("advance to foothold: %v", err)
	}
	if got, _ := s.Vantage(context.Background()); got != VantageInternalFoothold {
		t.Errorf("vantage = %q, want internal-foothold", got)
	}
	// Snapshot carries it too.
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Vantage != VantageInternalFoothold {
		t.Errorf("snapshot vantage = %q, want internal-foothold", snap.Vantage)
	}
	// Downgrade is rejected transactionally.
	back := VantageExternalUnauth
	if _, err := s.Apply(Delta{SetVantage: &back}); err == nil {
		t.Errorf("downgrade: want error, got nil")
	}
	if got, _ := s.Vantage(context.Background()); got != VantageInternalFoothold {
		t.Errorf("after rejected downgrade vantage = %q, want unchanged", got)
	}
	// Invalid vantage rejected.
	bad := Vantage("bogus")
	if _, err := s.Apply(Delta{SetVantage: &bad}); err == nil {
		t.Errorf("invalid vantage: want error, got nil")
	}
}
