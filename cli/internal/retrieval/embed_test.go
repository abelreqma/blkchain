package retrieval

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

// A failing embed_server's body is cut short in the error, which reaches the
// terminal.
func TestPostJSONCutsTheErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(strings.Repeat("e", 1<<20)))
	}))
	defer srv.Close()
	_, err := embedQuery(context.Background(), srv.URL, "q")
	if err == nil {
		t.Fatal("want an error")
	}
	if n := len(err.Error()); n > 1024 {
		t.Errorf("error is %d bytes, want the body cut to about %d", n, maxErrorBodyBytes)
	}
}

// Close releases the client; a search after it fails instead of dialing.
func TestCloseReleasesTheClient(t *testing.T) {
	cfg, _ := searchBackends(t)
	c, err := New(cfg, "blkchain")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Search(context.Background(), "q", 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := c.Search(context.Background(), "q", 0, nil); err == nil {
		t.Error("search after Close succeeded")
	}
}
