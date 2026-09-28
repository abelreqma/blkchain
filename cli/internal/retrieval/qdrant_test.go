package retrieval

import (
	"testing"

	"github.com/qdrant/go-client/qdrant"
)

func TestBuildHybridQueryShape(t *testing.T) {
	q := buildHybridQuery("blkchain_dwq", "dense", "sparse", "qdrant/bm25",
		"ssrf metadata", []float32{0.1, 0.2}, nil, 50)
	if q.GetCollectionName() != "blkchain_dwq" {
		t.Errorf("collection = %s", q.GetCollectionName())
	}
	if len(q.GetPrefetch()) != 2 {
		t.Fatalf("want 2 prefetch legs, got %d", len(q.GetPrefetch()))
	}
	if q.GetQuery().GetFusion() != qdrant.Fusion_RRF {
		t.Errorf("fusion query not RRF")
	}
	if q.GetLimit() != 50 {
		t.Errorf("limit = %d", q.GetLimit())
	}
}

func TestBuildHybridQueryFilterOnEachPrefetchLeg(t *testing.T) {
	q := buildHybridQuery("blkchain_dwq", "dense", "sparse", "qdrant/bm25",
		"ssrf metadata", []float32{0.1, 0.2}, map[string]any{"source": "wstg"}, 50)
	if q.GetFilter() == nil {
		t.Fatal("top-level Filter = nil, want non-nil")
	}
	legs := q.GetPrefetch()
	if len(legs) != 2 {
		t.Fatalf("want 2 prefetch legs, got %d", len(legs))
	}
	for i, leg := range legs {
		if leg.GetFilter() == nil {
			t.Errorf("prefetch leg %d Filter = nil, want non-nil", i)
		}
	}
}

func TestBuildHybridQueryNilFilterKeepsPrefetchLegsUnfiltered(t *testing.T) {
	q := buildHybridQuery("blkchain_dwq", "dense", "sparse", "qdrant/bm25",
		"ssrf metadata", []float32{0.1, 0.2}, nil, 50)
	if q.GetFilter() != nil {
		t.Errorf("top-level Filter = %v, want nil", q.GetFilter())
	}
	for i, leg := range q.GetPrefetch() {
		if leg.GetFilter() != nil {
			t.Errorf("prefetch leg %d Filter = %v, want nil", i, leg.GetFilter())
		}
	}
}

func TestBuildFilterEmpty(t *testing.T) {
	if f := buildFilter(nil); f != nil {
		t.Errorf("buildFilter(nil) = %v, want nil", f)
	}
	if f := buildFilter(map[string]any{}); f != nil {
		t.Errorf("buildFilter(empty map) = %v, want nil", f)
	}
}

func TestBuildFilterMustMatch(t *testing.T) {
	f := buildFilter(map[string]any{"source": "wstg"})
	if f == nil {
		t.Fatal("buildFilter returned nil for non-empty map")
	}
	if len(f.GetMust()) != 1 {
		t.Fatalf("want 1 must condition, got %d", len(f.GetMust()))
	}
}
