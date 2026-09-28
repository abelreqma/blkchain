package modeleval

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func embedCfg(base string) Config {
	return Config{
		EmbedHealthURL: base + "/health",
		EmbedURL:       base + "/embed",
		RerankURL:      base + "/rerank",
		ReadyTimeout:   2 * time.Second,
		ProbeTimeout:   2 * time.Second,
		HTTPClient:     &http.Client{Timeout: 2 * time.Second},
	}
}

func TestProbeEmbedOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(200)
		case "/embed":
			json.NewEncoder(w).Encode(map[string]any{
				"embeddings": [][]float64{make([]float64, 1024)},
				"dim":        1024,
			})
		}
	}))
	defer srv.Close()

	rep := ProbeEmbed(context.Background(), embedCfg(srv.URL))
	if !rep.Ready || rep.Err != nil {
		t.Fatalf("expected ready, got ready=%v err=%v", rep.Ready, rep.Err)
	}
	if rep.Perf == nil || rep.Perf.Dim != 1024 {
		t.Fatalf("expected dim 1024, got %+v", rep.Perf)
	}
}

func TestProbeEmbedWrongDim(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(200)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"embeddings": [][]float64{{1, 2, 3}}, "dim": 3})
	}))
	defer srv.Close()

	rep := ProbeEmbed(context.Background(), embedCfg(srv.URL))
	if rep.Err == nil {
		t.Fatalf("expected error for wrong dim, got nil (perf=%+v)", rep.Perf)
	}
}

func TestProbeRerankScoreSanity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(200)
			return
		}
		// one null (sanitized non-finite) and one out-of-range sentinel.
		w.Write([]byte(`{"scores":[0.9,null,0.5,-1.0]}`))
	}))
	defer srv.Close()

	rep := ProbeRerank(context.Background(), embedCfg(srv.URL))
	if rep.Err != nil {
		t.Fatalf("unexpected err: %v", rep.Err)
	}
	if rep.Perf.NonFinite != 1 || rep.Perf.OutOfRange != 1 {
		t.Fatalf("sanity mismatch: %+v", rep.Perf)
	}
}

func TestProbeEmbedDown(t *testing.T) {
	// A server that is closed immediately -> connection refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	cfg := embedCfg(url)
	cfg.ReadyTimeout = 300 * time.Millisecond
	rep := ProbeEmbed(context.Background(), cfg)
	if rep.Ready || rep.Err == nil {
		t.Fatalf("expected unreachable, got ready=%v err=%v", rep.Ready, rep.Err)
	}
}
