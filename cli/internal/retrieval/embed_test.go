package retrieval

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEmbedQueryParsesVector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/embed" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Write([]byte(`{"embeddings":[[0.1,0.2,0.3]],"dim":3}`))
	}))
	defer srv.Close()
	vec, err := embedQuery(context.Background(), srv.URL, "ssrf")
	if err != nil || len(vec) != 3 || vec[0] != 0.1 {
		t.Fatalf("got %v, %v", vec, err)
	}
}

func TestRerankParsesScores(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"scores":[0.9,0.1]}`))
	}))
	defer srv.Close()
	scores, err := rerank(context.Background(), srv.URL, "q", []string{"a", "b"})
	if err != nil || len(scores) != 2 || scores[0] != 0.9 {
		t.Fatalf("got %v, %v", scores, err)
	}
}
