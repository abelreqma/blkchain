package retrieval

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/qdrant/go-client/qdrant"
	"google.golang.org/grpc"

	"blkchain/cli/internal/ragconfig"
)

// fakeFacet answers Facet with fixed hits and records the request.
type fakeFacet struct {
	qdrant.UnimplementedPointsServer
	hits []*qdrant.FacetHit
	err  error
	last *qdrant.FacetCounts
}

func (f *fakeFacet) Facet(_ context.Context, r *qdrant.FacetCounts) (*qdrant.FacetResponse, error) {
	f.last = r
	if f.err != nil {
		return nil, f.err
	}
	return &qdrant.FacetResponse{Hits: f.hits}, nil
}

func facetHit(source string, n uint64) *qdrant.FacetHit {
	return &qdrant.FacetHit{Value: &qdrant.FacetValue{Variant: &qdrant.FacetValue_StringValue{StringValue: source}}, Count: n}
}

func facetClient(t *testing.T, f *fakeFacet) *Client {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	qdrant.RegisterPointsServer(gs, f)
	go gs.Serve(l)
	t.Cleanup(gs.Stop)
	c, err := New(ragconfig.Config{QdrantGRPCURL: l.Addr().String()}, "blkchain_dwq")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestSourceCountsSortsByCountThenName(t *testing.T) {
	f := &fakeFacet{hits: []*qdrant.FacetHit{
		facetHit("beta", 5), facetHit("wstg", 3201), facetHit("alpha", 5), facetHit("hacktricks", 2940),
	}}
	c := facetClient(t, f)
	got, partial, err := c.SourceCounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if partial {
		t.Error("partial = true for a short list")
	}
	want := []SourceCount{{"wstg", 3201}, {"hacktricks", 2940}, {"alpha", 5}, {"beta", 5}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestSourceCountsRequestIsExactBoundedAndReadOnly(t *testing.T) {
	f := &fakeFacet{}
	c := facetClient(t, f)
	if _, _, err := c.SourceCounts(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := f.last
	if r.GetCollectionName() != "blkchain_dwq" || r.GetKey() != "source" {
		t.Errorf("request = collection %q key %q", r.GetCollectionName(), r.GetKey())
	}
	if !r.GetExact() {
		t.Error("request is not exact")
	}
	if r.GetLimit() != uint64(sourceFacetLimit) {
		t.Errorf("limit = %d, want %d", r.GetLimit(), sourceFacetLimit)
	}
}

func TestSourceCountsEmptyCollection(t *testing.T) {
	c := facetClient(t, &fakeFacet{})
	got, partial, err := c.SourceCounts(context.Background())
	if err != nil || partial || got == nil || len(got) != 0 {
		t.Fatalf("got %v partial=%v err=%v, want empty non-nil, false, nil", got, partial, err)
	}
}

func TestSourceCountsSkipsBlankAndNonStringValues(t *testing.T) {
	f := &fakeFacet{hits: []*qdrant.FacetHit{
		facetHit("", 4), {Value: &qdrant.FacetValue{Variant: &qdrant.FacetValue_IntegerValue{IntegerValue: 7}}, Count: 2}, facetHit("wstg", 1),
	}}
	c := facetClient(t, f)
	got, _, err := c.SourceCounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (SourceCount{"wstg", 1}) {
		t.Errorf("got %v, want only wstg", got)
	}
}

func TestSourceCountsFlagsPartialAtTheCap(t *testing.T) {
	old := sourceFacetLimit
	sourceFacetLimit = 3
	t.Cleanup(func() { sourceFacetLimit = old })
	f := &fakeFacet{hits: []*qdrant.FacetHit{facetHit("a", 3), facetHit("b", 2), facetHit("c", 1)}}
	c := facetClient(t, f)
	got, partial, err := c.SourceCounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !partial || len(got) != 3 {
		t.Errorf("partial=%v len=%d, want true and the 3 counted sources", partial, len(got))
	}
	if f.last.GetLimit() != 3 {
		t.Errorf("limit = %d, want 3", f.last.GetLimit())
	}
}

func TestSourceCountsUnreachableIsActionable(t *testing.T) {
	c, err := New(ragconfig.Config{QdrantGRPCURL: "127.0.0.1:6399"}, "blkchain")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _, err = c.SourceCounts(context.Background())
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("want ErrUnreachable, got %v", err)
	}
}
