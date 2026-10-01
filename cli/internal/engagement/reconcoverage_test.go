package engagement

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestReconCoverageUpsertAndRead(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	dims := map[string]ReconDimStatus{"hosts": ReconCovered, "ports": ReconPending}
	if _, err := s.Apply(Delta{
		ReconUpserts: []ReconCoverage{{
			Surface:        SurfaceNetwork,
			Asset:          "10.0.0.1",
			Dimensions:     dims,
			IterationCount: 1,
			LastNoveltyRev: 2,
		}},
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	rc, found, err := s.ReconCoverageFor(SurfaceNetwork, "10.0.0.1")
	if err != nil {
		t.Fatalf("ReconCoverageFor: %v", err)
	}
	if !found {
		t.Fatalf("found = false, want true")
	}
	if !reflect.DeepEqual(rc.Dimensions, dims) {
		t.Fatalf("Dimensions = %#v, want %#v", rc.Dimensions, dims)
	}
	if rc.IterationCount != 1 {
		t.Fatalf("IterationCount = %d, want 1", rc.IterationCount)
	}
	if rc.LastNoveltyRev != 2 {
		t.Fatalf("LastNoveltyRev = %d, want 2", rc.LastNoveltyRev)
	}

	_, found, err = s.ReconCoverageFor(SurfaceNetwork, "10.0.0.2")
	if err != nil {
		t.Fatalf("ReconCoverageFor missing: %v", err)
	}
	if found {
		t.Fatalf("found = true, want false for unknown asset")
	}
}

func TestReconCoverageAllOrdered(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if _, err := s.Apply(Delta{ReconUpserts: []ReconCoverage{
		{Surface: SurfaceNetwork, Asset: "b-host", Dimensions: map[string]ReconDimStatus{}},
		{Surface: SurfaceNetwork, Asset: "a-host", Dimensions: map[string]ReconDimStatus{}},
	}}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	if _, err := s.Apply(Delta{ReconUpserts: []ReconCoverage{
		{Surface: SurfaceLocal, Asset: "z-host", Dimensions: map[string]ReconDimStatus{}},
	}}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}

	all, err := s.AllReconCoverage()
	if err != nil {
		t.Fatalf("AllReconCoverage: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("len(all) = %d, want 3", len(all))
	}
	// created_rev ASC first: the two from Apply 1 (ordered by surface, asset),
	// then the one from Apply 2.
	want := []struct {
		surface Surface
		asset   string
	}{
		{SurfaceNetwork, "a-host"},
		{SurfaceNetwork, "b-host"},
		{SurfaceLocal, "z-host"},
	}
	for i, w := range want {
		if all[i].Surface != w.surface || all[i].Asset != w.asset {
			t.Fatalf("all[%d] = {%q, %q}, want {%q, %q}", i, all[i].Surface, all[i].Asset, w.surface, w.asset)
		}
	}
}

func TestReconCoverageAllEmptyIsNonNil(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	all, err := s.AllReconCoverage()
	if err != nil {
		t.Fatalf("AllReconCoverage: %v", err)
	}
	if all == nil {
		t.Fatalf("AllReconCoverage() = nil, want non-nil empty slice")
	}
	if len(all) != 0 {
		t.Fatalf("len(all) = %d, want 0", len(all))
	}
}

func TestReconCoverageUpdatePreservesCreatedRev(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if _, err := s.Apply(Delta{ReconUpserts: []ReconCoverage{
		{Surface: SurfaceNetwork, Asset: "h", Dimensions: map[string]ReconDimStatus{"hosts": ReconPending}},
	}}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	rc1, found, err := s.ReconCoverageFor(SurfaceNetwork, "h")
	if err != nil || !found {
		t.Fatalf("ReconCoverageFor 1: found=%v err=%v", found, err)
	}
	r1 := rc1.CreatedRev

	if _, err := s.Apply(Delta{ReconUpserts: []ReconCoverage{
		{Surface: SurfaceNetwork, Asset: "h", Dimensions: map[string]ReconDimStatus{"hosts": ReconCovered, "ports": ReconCovered}},
	}}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	rc2, found, err := s.ReconCoverageFor(SurfaceNetwork, "h")
	if err != nil || !found {
		t.Fatalf("ReconCoverageFor 2: found=%v err=%v", found, err)
	}
	if rc2.CreatedRev != r1 {
		t.Fatalf("CreatedRev = %d, want unchanged %d", rc2.CreatedRev, r1)
	}
	if rc2.UpdatedRev <= r1 {
		t.Fatalf("UpdatedRev = %d, want > %d", rc2.UpdatedRev, r1)
	}
	want := map[string]ReconDimStatus{"hosts": ReconCovered, "ports": ReconCovered}
	if !reflect.DeepEqual(rc2.Dimensions, want) {
		t.Fatalf("Dimensions = %#v, want %#v", rc2.Dimensions, want)
	}
}

func TestReconCoverageRejectsEmptyAsset(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	before := revision(t, s)
	if _, err := s.Apply(Delta{ReconUpserts: []ReconCoverage{
		{Surface: SurfaceNetwork, Asset: ""},
	}}); err == nil {
		t.Fatalf("Apply with empty asset: want error, got nil")
	}
	if after := revision(t, s); after != before {
		t.Fatalf("revision changed from %q to %q, want unchanged", before, after)
	}
}

func TestReconCoverageRejectsInvalidSurface(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	before := revision(t, s)
	if _, err := s.Apply(Delta{ReconUpserts: []ReconCoverage{
		{Surface: Surface("bogus"), Asset: "h"},
	}}); err == nil {
		t.Fatalf("Apply with invalid surface: want error, got nil")
	}
	if after := revision(t, s); after != before {
		t.Fatalf("revision changed from %q to %q, want unchanged", before, after)
	}
}

func TestReconCoverageRejectsInvalidStatus(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	before := revision(t, s)
	if _, err := s.Apply(Delta{ReconUpserts: []ReconCoverage{
		{Surface: SurfaceNetwork, Asset: "h", Dimensions: map[string]ReconDimStatus{"hosts": ReconDimStatus("maybe")}},
	}}); err == nil {
		t.Fatalf("Apply with invalid status: want error, got nil")
	}
	if after := revision(t, s); after != before {
		t.Fatalf("revision changed from %q to %q, want unchanged", before, after)
	}
}

func TestReconCoverageRoundTripsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.Apply(Delta{ReconUpserts: []ReconCoverage{
		{Surface: SurfaceWeb, Asset: "example.com", Dimensions: map[string]ReconDimStatus{"endpoints": ReconCovered}},
	}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer s2.Close()
	rc, found, err := s2.ReconCoverageFor(SurfaceWeb, "example.com")
	if err != nil {
		t.Fatalf("ReconCoverageFor: %v", err)
	}
	if !found {
		t.Fatalf("found = false, want true after reopen")
	}
	want := map[string]ReconDimStatus{"endpoints": ReconCovered}
	if !reflect.DeepEqual(rc.Dimensions, want) {
		t.Fatalf("Dimensions = %#v, want %#v", rc.Dimensions, want)
	}
}
