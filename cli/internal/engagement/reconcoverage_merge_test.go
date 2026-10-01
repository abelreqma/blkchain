package engagement

import (
	"path/filepath"
	"testing"
)

// Fix A: a second upsert for the same (surface, asset) must not clobber a
// dimension the first upsert covered; coverage merges ReconCovered-wins.
func TestReconCoverageMergePreservesCoveredDims(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.Apply(Delta{Kind: "a", ReconUpserts: []ReconCoverage{{
		Surface: SurfaceNetwork, Asset: "10.0.0.1",
		Dimensions: map[string]ReconDimStatus{"hosts": ReconCovered, "ports": ReconPending},
	}}}); err != nil {
		t.Fatal(err)
	}
	// A stale writer that still thinks hosts is pending but has covered ports.
	if _, err := s.Apply(Delta{Kind: "b", ReconUpserts: []ReconCoverage{{
		Surface: SurfaceNetwork, Asset: "10.0.0.1",
		Dimensions: map[string]ReconDimStatus{"hosts": ReconPending, "ports": ReconCovered},
	}}}); err != nil {
		t.Fatal(err)
	}

	cov, ok, err := s.ReconCoverageFor(SurfaceNetwork, "10.0.0.1")
	if err != nil || !ok {
		t.Fatalf("read: ok=%v err=%v", ok, err)
	}
	if cov.Dimensions["hosts"] != ReconCovered {
		t.Fatalf("hosts = %q, want covered (a stale pending upsert must not un-cover it)", cov.Dimensions["hosts"])
	}
	if cov.Dimensions["ports"] != ReconCovered {
		t.Fatalf("ports = %q, want covered (merged from the second upsert)", cov.Dimensions["ports"])
	}
}

// Fix C: an upsert carrying the ReconNoveltyThisRev sentinel records the
// committing revision into last_novelty_rev, in a single Apply.
func TestReconCoverageNoveltySentinelResolvesToRev(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rev, err := s.Apply(Delta{Kind: "a", ReconUpserts: []ReconCoverage{{
		Surface: SurfaceNetwork, Asset: "10.0.0.1",
		Dimensions:     map[string]ReconDimStatus{"hosts": ReconCovered},
		LastNoveltyRev: ReconNoveltyThisRev,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	cov, ok, err := s.ReconCoverageFor(SurfaceNetwork, "10.0.0.1")
	if err != nil || !ok {
		t.Fatalf("read: ok=%v err=%v", ok, err)
	}
	if cov.LastNoveltyRev != rev {
		t.Fatalf("LastNoveltyRev = %d, want the apply revision %d", cov.LastNoveltyRev, rev)
	}
}

// Fix A (counters): a later upsert with lower counters must not regress the
// stored monotonic counters.
func TestReconCoverageCountersMonotonic(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.Apply(Delta{Kind: "a", ReconUpserts: []ReconCoverage{{
		Surface: SurfaceNetwork, Asset: "h", Dimensions: map[string]ReconDimStatus{"hosts": ReconCovered},
		IterationCount: 5, LastNoveltyRev: 9,
	}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(Delta{Kind: "b", ReconUpserts: []ReconCoverage{{
		Surface: SurfaceNetwork, Asset: "h", Dimensions: map[string]ReconDimStatus{"hosts": ReconCovered},
		IterationCount: 2, LastNoveltyRev: 3,
	}}}); err != nil {
		t.Fatal(err)
	}
	cov, _, err := s.ReconCoverageFor(SurfaceNetwork, "h")
	if err != nil {
		t.Fatal(err)
	}
	if cov.IterationCount != 5 {
		t.Fatalf("IterationCount = %d, want 5 (monotonic, not regressed to 2)", cov.IterationCount)
	}
	if cov.LastNoveltyRev != 9 {
		t.Fatalf("LastNoveltyRev = %d, want 9 (monotonic, not regressed to 3)", cov.LastNoveltyRev)
	}
}

// Fix A + C together: the novelty sentinel resolves to the committing revision
// even when a prior row exists, and does so through the merge/max path (covered
// dims preserved, counters monotonic).
func TestReconCoverageNoveltySentinelResolvesAgainstExistingRow(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Seed a prior row: hosts covered, a known novelty rev.
	if _, err := s.Apply(Delta{Kind: "a", ReconUpserts: []ReconCoverage{{
		Surface: SurfaceNetwork, Asset: "10.0.0.1",
		Dimensions:     map[string]ReconDimStatus{"hosts": ReconCovered, "ports": ReconPending},
		LastNoveltyRev: 2,
	}}}); err != nil {
		t.Fatal(err)
	}
	// A novel pass on the same row: carries the sentinel and covers ports.
	rev, err := s.Apply(Delta{Kind: "b", ReconUpserts: []ReconCoverage{{
		Surface: SurfaceNetwork, Asset: "10.0.0.1",
		Dimensions:     map[string]ReconDimStatus{"hosts": ReconCovered, "ports": ReconCovered},
		LastNoveltyRev: ReconNoveltyThisRev,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	cov, ok, err := s.ReconCoverageFor(SurfaceNetwork, "10.0.0.1")
	if err != nil || !ok {
		t.Fatalf("read: ok=%v err=%v", ok, err)
	}
	if cov.LastNoveltyRev != rev {
		t.Fatalf("LastNoveltyRev = %d, want the second apply revision %d (sentinel resolved against an existing row)", cov.LastNoveltyRev, rev)
	}
	if cov.Dimensions["hosts"] != ReconCovered || cov.Dimensions["ports"] != ReconCovered {
		t.Fatalf("dimensions = %v, want hosts+ports covered (merge preserved prior + added new)", cov.Dimensions)
	}
}
