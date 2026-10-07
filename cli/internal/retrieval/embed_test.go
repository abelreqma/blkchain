package retrieval

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The shared HTTP client carries no fixed Timeout, so a configured
// request_timeout_seconds larger than the old hardcoded 60s is honored end to
// end instead of being silently capped. The per-call context deadline (set in
// Search from cfg.RequestTimeout) is the only bound.
func TestHTTPClientHasNoFixedTimeout(t *testing.T) {
	if httpClient.Timeout != 0 {
		t.Errorf("httpClient.Timeout = %s, want 0 (rely on the context deadline)", httpClient.Timeout)
	}
}

// A request still honors the caller's context deadline: a server slower than
// the deadline is cancelled, not left to run.
func TestPostJSONHonorsContextDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte(`{"embeddings":[[0.1]],"dim":1}`))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := embedQuery(ctx, srv.URL, "q")
	if err == nil {
		t.Fatal("want a deadline error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want context.DeadlineExceeded", err)
	}
}

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

func TestRerankNullScoreRanksBelowValidScores(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"scores":[null,0.0,0.9]}`))
	}))
	defer server.Close()
	scores, err := rerank(context.Background(), server.URL, "q", []string{"a", "b", "c"})
	if err != nil || len(scores) != 3 || scores[0] >= scores[1] || scores[2] != 0.9 {
		t.Fatalf("null score was not ranked last: %v %v", scores, err)
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
