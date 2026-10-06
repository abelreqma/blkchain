package retrieval

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/qdrant/go-client/qdrant"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"blkchain/cli/internal/ragconfig"
)

// fakeQdrant answers Query with points in hybrid (RRF) order, each scored by
// its RRF score, on a loopback gRPC port.
type fakeQdrant struct {
	qdrant.UnimplementedPointsServer
	points []*qdrant.ScoredPoint
}

func (f *fakeQdrant) Query(context.Context, *qdrant.QueryPoints) (*qdrant.QueryResponse, error) {
	return &qdrant.QueryResponse{Result: f.points}, nil
}

// searchBackends starts a fake Qdrant with texts a..d (RRF scores falling) and
// a fake embed_server whose rerank puts them in reverse order. It returns a
// config pointing at both and a counter of /rerank requests.
func searchBackends(t *testing.T) (ragconfig.Config, *atomic.Int32) {
	t.Helper()
	var points []*qdrant.ScoredPoint
	for i, text := range []string{"a", "b", "c", "d"} {
		points = append(points, &qdrant.ScoredPoint{
			Id:      qdrant.NewIDNum(uint64(i + 1)),
			Score:   float32(0.5 - 0.1*float64(i)),
			Payload: map[string]*qdrant.Value{"text": qdrant.NewValueString(text)},
		})
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	qdrant.RegisterPointsServer(gs, &fakeQdrant{points: points})
	go gs.Serve(l)
	t.Cleanup(gs.Stop)

	var reranks atomic.Int32
	embed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/embed":
			json.NewEncoder(w).Encode(embedResponse{Embeddings: [][]float32{{0.1, 0.2}}, Dim: 2})
		case "/rerank":
			reranks.Add(1)
			var req rerankRequest
			json.NewDecoder(r.Body).Decode(&req)
			scores := make([]float64, len(req.Documents))
			for i := range scores {
				scores[i] = float64(i) // the last document scores highest
			}
			json.NewEncoder(w).Encode(rerankResponse{Scores: scores})
		}
	}))
	t.Cleanup(embed.Close)

	cfg := ragconfig.Config{QdrantGRPCURL: l.Addr().String(), EmbedServerURL: embed.URL,
		DenseVectorName: "dense", SparseVectorName: "sparse", SparseModel: "qdrant/bm25", PoolSize: 10, TopK: 3}
	return cfg, &reranks
}

func resultTexts(rs []Result) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Payload.Text
	}
	return out
}

func TestSearchWithRerankOffKeepsHybridOrder(t *testing.T) {
	cfg, reranks := searchBackends(t)
	c, err := New(cfg, "blkchain")
	if err != nil {
		t.Fatal(err)
	}
	c.SkipRerank = true
	got, err := c.Search(context.Background(), "q", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := reranks.Load(); n != 0 {
		t.Errorf("rerank off made %d /rerank requests, want 0", n)
	}
	if texts := resultTexts(got); len(texts) != 3 || texts[0] != "a" || texts[1] != "b" || texts[2] != "c" {
		t.Errorf("rerank off order = %v, want the first 3 in hybrid order [a b c]", texts)
	}
	if got[0].Score < 0.49 || got[0].Score > 0.51 {
		t.Errorf("rerank off score = %v, want the RRF score 0.5", got[0].Score)
	}
}

func TestSearchWithRerankOnReranks(t *testing.T) {
	cfg, reranks := searchBackends(t)
	c, err := New(cfg, "blkchain")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Search(context.Background(), "q", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := reranks.Load(); n != 1 {
		t.Errorf("rerank on made %d /rerank requests, want 1", n)
	}
	if texts := resultTexts(got); len(texts) != 3 || texts[0] != "d" || texts[1] != "c" || texts[2] != "b" {
		t.Errorf("rerank on order = %v, want [d c b]", texts)
	}
}

func TestSearchUnreachableQdrantGivesActionableError(t *testing.T) {
	cfg := ragconfig.Config{QdrantGRPCURL: "127.0.0.1:6399", EmbedServerURL: "http://127.0.0.1:8199", DenseVectorName: "dense", SparseVectorName: "sparse", SparseModel: "qdrant/bm25", PoolSize: 10}
	c, err := New(cfg, "blkchain_dwq")
	if err != nil {
		t.Fatalf("New: %v", err) // New should not dial eagerly
	}
	_, err = c.Search(context.Background(), "ssrf", 5, nil)
	if err == nil || !errors.Is(err, ErrUnreachable) {
		t.Fatalf("want ErrUnreachable, got %v", err)
	}
}

// TestUnreachableClassifiesOnlyTransportFailures pins the distinction the
// operator-facing error depends on: a service that could not be reached says so
// and names `blk up`, while a request the service answered and refused, such as
// one naming a collection that does not exist, must not, because the services
// are already running and the advice would send the operator after the wrong
// problem.
func TestUnreachableClassifiesOnlyTransportFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"unavailable", status.Error(codes.Unavailable, "connection refused"), true},
		{"deadline", status.Error(codes.DeadlineExceeded, "timed out"), true},
		{"canceled", status.Error(codes.Canceled, "canceled"), true},
		{"missing collection", status.Error(codes.NotFound, "Collection `x` doesn't exist!"), false},
		{"invalid argument", status.Error(codes.InvalidArgument, "bad vector name"), false},
		{"internal", status.Error(codes.Internal, "boom"), false},
		{"plain error", errors.New("not a status"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := unreachable(tc.err); got != tc.want {
				t.Errorf("unreachable(%v) = %t, want %t", tc.err, got, tc.want)
			}
		})
	}
}
