package engagement

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// seedSurface returns a store with the seeded tasks and an evidence row of task A.
func seedSurface(t *testing.T) (*Store, int64) {
	t.Helper()
	s := openTemp(t)
	seedAB(t, s)
	id, err := s.RecordEvidence("A", "probe output")
	if err != nil {
		t.Fatal(err)
	}
	return s, id
}

func surfaceRecord(ev int64) SurfaceRecord {
	return SurfaceRecord{
		ID: "surf:1", TaskID: "A", Surface: SurfaceWeb, Asset: "www.example.com",
		Kind: "tls-protocol", Name: "TLSv1.0", Value: "negotiated",
		Source: "tls-probe", EvidenceID: ev,
	}
}

func TestSurfaceListHasABoundedDefaultPage(t *testing.T) {
	s, ev := seedSurface(t)
	ctx := context.Background()
	for i := 0; i < 101; i++ {
		r := surfaceRecord(ev)
		r.ID = fmt.Sprintf("surf:%03d", i)
		r.Name = fmt.Sprintf("header-%03d", i)
		if _, err := s.SaveSurface(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.Surfaces(ctx, SurfaceFilter{})
	if err != nil || len(page) != 100 {
		t.Errorf("default page has %d rows, want 100: %v", len(page), err)
	}
	if _, err := s.Surfaces(ctx, SurfaceFilter{Limit: 101}); err == nil {
		t.Error("an oversized page was accepted")
	}
}

func TestSurfaceRoundTrip(t *testing.T) {
	s, ev := seedSurface(t)
	ctx := context.Background()
	in := surfaceRecord(ev)
	in.Detail = json.RawMessage(`{"cipher":"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"}`)
	in.Gap = "SSLv2 and SSLv3 were not probed"
	got, err := s.SaveSurface(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "TLSv1.0" || got.Value != "negotiated" || got.Kind != "tls-protocol" {
		t.Errorf("identity fields wrong: %+v", got)
	}
	if got.Asset != "www.example.com" || got.Source != "tls-probe" {
		t.Errorf("attribution fields wrong: %+v", got)
	}
	if got.Gap != "SSLv2 and SSLv3 were not probed" {
		t.Errorf("Gap = %q", got.Gap)
	}
	var detail map[string]string
	if err := json.Unmarshal(got.Detail, &detail); err != nil {
		t.Fatalf("Detail is not JSON: %v", err)
	}
	if detail["cipher"] == "" {
		t.Errorf("Detail lost its content: %s", got.Detail)
	}
	if got.CreatedAt == "" || got.UpdatedAt == "" || got.ObservedAt == "" {
		t.Errorf("timestamps missing: %+v", got)
	}
}

func TestSurfaceRequiresEvidenceBelongingToTheTask(t *testing.T) {
	s, ev := seedSurface(t)
	ctx := context.Background()
	// An evidence row of another task cannot be cited.
	other, err := s.RecordEvidence("B", "another task's output")
	if err != nil {
		t.Fatal(err)
	}
	in := surfaceRecord(ev)
	in.EvidenceID = other
	if _, err := s.SaveSurface(ctx, in); err == nil {
		t.Error("a record citing another task's evidence was stored")
	} else if !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("error = %v, want the ownership message", err)
	}
	in.EvidenceID = 0
	if _, err := s.SaveSurface(ctx, in); err == nil {
		t.Error("a record with no evidence row was stored")
	} else if !strings.Contains(err.Error(), "requires an evidence row") {
		t.Errorf("error = %v, want the missing-evidence message", err)
	}
	in.EvidenceID = ev + 10000
	if _, err := s.SaveSurface(ctx, in); err == nil {
		t.Error("a record citing a row that does not exist was stored")
	}
}

func TestSurfaceRejectsMalformedRecords(t *testing.T) {
	s, ev := seedSurface(t)
	ctx := context.Background()
	for name, mutate := range map[string]func(*SurfaceRecord){
		"no id":              func(r *SurfaceRecord) { r.ID = "" },
		"over-long id":       func(r *SurfaceRecord) { r.ID = strings.Repeat("x", 129) },
		"unknown surface":    func(r *SurfaceRecord) { r.Surface = Surface("nowhere") },
		"unknown kind":       func(r *SurfaceRecord) { r.Kind = "made-up" },
		"no kind":            func(r *SurfaceRecord) { r.Kind = "" },
		"no asset":           func(r *SurfaceRecord) { r.Asset = "" },
		"no name":            func(r *SurfaceRecord) { r.Name = "" },
		"newline in name":    func(r *SurfaceRecord) { r.Name = "a\nInjected: yes" },
		"NUL in value":       func(r *SurfaceRecord) { r.Value = "a\x00b" },
		"newline in gap":     func(r *SurfaceRecord) { r.Gap = "a\r\nInjected: yes" },
		"over-long asset":    func(r *SurfaceRecord) { r.Asset = strings.Repeat("x", maxSurfaceField+1) },
		"over-long value":    func(r *SurfaceRecord) { r.Value = strings.Repeat("x", maxSurfaceField+1) },
		"over-long detail":   func(r *SurfaceRecord) { r.Detail = json.RawMessage(`"` + strings.Repeat("x", maxSurfaceDetail) + `"`) },
		"detail is not JSON": func(r *SurfaceRecord) { r.Detail = json.RawMessage(`{not json`) },
	} {
		in := surfaceRecord(ev)
		mutate(&in)
		if _, err := s.SaveSurface(ctx, in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestSaveSurfaceUpsertsRatherThanDuplicating(t *testing.T) {
	s, ev := seedSurface(t)
	ctx := context.Background()
	first, err := s.SaveSurface(ctx, surfaceRecord(ev))
	if err != nil {
		t.Fatal(err)
	}
	second := surfaceRecord(ev)
	second.Value = "refused"
	again, err := s.SaveSurface(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	all, err := s.Surfaces(ctx, SurfaceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("a re-probe created %d rows, want 1", len(all))
	}
	if all[0].Value != "refused" {
		t.Errorf("the re-probe did not update the value: %q", all[0].Value)
	}
	if again.CreatedAt != first.CreatedAt {
		t.Errorf("created_at changed on re-probe: %q then %q", first.CreatedAt, again.CreatedAt)
	}
}

func TestSurfacesOffsetAndLimitKeepAssetOrder(t *testing.T) {
	s, ev := seedSurface(t)
	ctx := context.Background()
	for _, spec := range []struct{ id, asset string }{
		{"c", "c.example"}, {"a", "a.example"}, {"b", "b.example"},
	} {
		r := surfaceRecord(ev)
		r.ID, r.Asset = spec.id, spec.asset
		if _, err := s.SaveSurface(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Surfaces(ctx, SurfaceFilter{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("paged surface records = %+v", got)
	}
}

func TestSurfacesFilterAndOrder(t *testing.T) {
	s, ev := seedSurface(t)
	ctx := context.Background()
	for _, spec := range []struct{ id, asset, kind, name string }{
		{"s1", "b.example.com", "http-header", "Strict-Transport-Security"},
		{"s2", "a.example.com", "tls-protocol", "TLSv1.0"},
		{"s3", "a.example.com", "http-header", "Content-Security-Policy"},
		{"s4", "a.example.com", "http-header", "X-Frame-Options"},
	} {
		r := surfaceRecord(ev)
		r.ID, r.Asset, r.Kind, r.Name = spec.id, spec.asset, spec.kind, spec.name
		if _, err := s.SaveSurface(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.Surfaces(ctx, SurfaceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"s3", "s4", "s2", "s1"}
	if len(all) != len(want) {
		t.Fatalf("got %d records, want %d", len(all), len(want))
	}
	for i := range want {
		if all[i].ID != want[i] {
			t.Fatalf("order = %v, want asset then kind then name (%v)", ids(all), want)
		}
	}
	byAsset, err := s.Surfaces(ctx, SurfaceFilter{Asset: "a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byAsset) != 3 {
		t.Errorf("asset filter returned %v", ids(byAsset))
	}
	byKind, err := s.Surfaces(ctx, SurfaceFilter{Kind: "http-header"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byKind) != 3 {
		t.Errorf("kind filter returned %v", ids(byKind))
	}
	byName, err := s.Surfaces(ctx, SurfaceFilter{Name: "TLSv1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byName) != 1 || byName[0].ID != "s2" {
		t.Errorf("name filter returned %v", ids(byName))
	}
	both, err := s.Surfaces(ctx, SurfaceFilter{Asset: "a.example.com", Kind: "http-header"})
	if err != nil {
		t.Fatal(err)
	}
	if len(both) != 2 {
		t.Errorf("two filters returned %v", ids(both))
	}
	limited, err := s.Surfaces(ctx, SurfaceFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 2 {
		t.Errorf("limit returned %d records", len(limited))
	}
}

func ids(in []SurfaceRecord) []string {
	out := make([]string, len(in))
	for i, r := range in {
		out[i] = r.ID
	}
	return out
}

func TestSurfaceStatsCountsPerKind(t *testing.T) {
	s, ev := seedSurface(t)
	ctx := context.Background()
	for _, spec := range []struct{ id, kind string }{
		{"s1", "http-header"}, {"s2", "http-header"}, {"s3", "tls-protocol"},
	} {
		r := surfaceRecord(ev)
		r.ID, r.Kind, r.Name = spec.id, spec.kind, spec.id
		if _, err := s.SaveSurface(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := s.SurfaceStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats["http-header"] != 2 || stats["tls-protocol"] != 1 {
		t.Errorf("stats = %v", stats)
	}
	if _, present := stats["http-cors"]; present {
		t.Errorf("a kind with no records was counted: %v", stats)
	}
}

func TestSurfaceMethodsOnANilStoreReportUnavailable(t *testing.T) {
	var s *Store
	ctx := context.Background()
	if _, err := s.SaveSurface(ctx, SurfaceRecord{}); err == nil {
		t.Error("SaveSurface on a nil store did not report unavailable")
	}
	if _, err := s.Surfaces(ctx, SurfaceFilter{}); err == nil {
		t.Error("Surfaces on a nil store did not report unavailable")
	}
	if _, err := s.Surface(ctx, "x"); err == nil {
		t.Error("Surface on a nil store did not report unavailable")
	}
	if _, err := s.SurfaceStats(ctx); err == nil {
		t.Error("SurfaceStats on a nil store did not report unavailable")
	}
}

func TestSurfaceLookupReportsAMissingRecord(t *testing.T) {
	s, _ := seedSurface(t)
	if _, err := s.Surface(context.Background(), "absent"); err == nil {
		t.Error("a missing record was returned without an error")
	}
}

func TestSurfaceKindsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range SurfaceKinds() {
		if seen[k] {
			t.Errorf("%q is listed twice", k)
		}
		seen[k] = true
		if !validSurfaceKind(k) {
			t.Errorf("%q is listed but not accepted", k)
		}
	}
	if validSurfaceKind("not-a-kind") {
		t.Error("an unlisted kind was accepted")
	}
}
