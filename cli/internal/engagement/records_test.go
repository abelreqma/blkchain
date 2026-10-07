package engagement

import (
	"context"
	"testing"

	"blkchain/cli/internal/webanalysis"
)

func TestRecordsPageSeparatesSurfacesAndRetainsProvenance(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	id, err := s.RecordEvidence("A", "fixture banner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordReceipt("A", "fixture", "digest"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveFinding(context.Background(), Finding{Surface: SurfaceNetwork, TaskID: "A", Asset: "192.0.2.1", Title: "banner", Status: FindingObserved, EvidenceIDs: []int64{id}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(Delta{Kind: "coverage", ReconUpserts: []ReconCoverage{{Surface: SurfaceNetwork, Asset: "192.0.2.1", Dimensions: map[string]ReconDimStatus{"services": ReconCovered}, IterationCount: 1}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Audit("operator", "review", "fixture decision"); err != nil {
		t.Fatal(err)
	}
	w := webanalysis.Finding{ID: webanalysis.ID("fixture-web"), Kind: "endpoint-lead", SourceURL: "https://example.test/"}
	if err := s.PutWeb(context.Background(), "finding", w.ID, "", w); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind    string
		surface Surface
		want    int
	}{
		{"task", SurfaceNetwork, 2}, {"task", SurfaceWeb, 0},
		{"evidence", SurfaceNetwork, 1}, {"receipt", SurfaceNetwork, 1},
		{"finding", SurfaceNetwork, 1}, {"finding", SurfaceWeb, 1},
		{"finding-event", SurfaceNetwork, 1}, {"coverage", SurfaceNetwork, 1},
		{"web", SurfaceWeb, 1}, {"web", SurfaceNetwork, 0},
	} {
		page, err := s.Records(context.Background(), tc.kind, tc.surface, 0, 10)
		if err != nil || page.Total != tc.want || len(page.Records) != tc.want {
			t.Fatalf("%s/%s: total=%d records=%d err=%v", tc.kind, tc.surface, page.Total, len(page.Records), err)
		}
		for _, rec := range page.Records {
			if rec.Surface != tc.surface {
				t.Fatalf("%s record surface=%s, want %s", tc.kind, rec.Surface, tc.surface)
			}
		}
	}
	page, err := s.Records(context.Background(), "task", SurfaceNetwork, 1, 1)
	if err != nil || page.Total != 2 || len(page.Records) != 1 || page.Records[0].ID != "task:B" {
		t.Fatalf("page: %+v %v", page, err)
	}
	for _, kind := range []string{"audit", "transition"} {
		page, err := s.Records(context.Background(), kind, "", 0, 10)
		if err != nil || page.Total == 0 || len(page.Records) == 0 {
			t.Fatalf("global %s records: %+v %v", kind, page, err)
		}
	}
}

func TestRecordsRejectUnboundedAndInvalidQueries(t *testing.T) {
	s := openTemp(t)
	for _, tc := range []struct {
		kind    string
		surface Surface
		offset  int
		limit   int
	}{
		{"task", "", 0, 0}, {"task", "", -1, 1}, {"task", "", 0, 101},
		{"nope", "", 0, 1}, {"audit", SurfaceWeb, 0, 1}, {"task", "unknown", 0, 1},
	} {
		if _, err := s.Records(context.Background(), tc.kind, tc.surface, tc.offset, tc.limit); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}
