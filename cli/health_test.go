package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/client"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

// TestProbeHealthEmbedDown verifies probeHealth never panics and reports both
// dependencies down when nothing is listening on either port (Task 16).
func TestProbeHealthEmbedDown(t *testing.T) {
	cfg := ragconfig.Config{QdrantGRPCURL: "127.0.0.1:6399", EmbedServerURL: "http://127.0.0.1:8199"}
	q, e := probeHealth(cfg)
	if q || e {
		t.Fatalf("both should be false when nothing is up: q=%v e=%v", q, e)
	}
}

// TestFormatHealthNamesDependencies checks the TUI health report describes the
// real dependencies and their addresses, not the API.
func TestFormatHealthNamesDependencies(t *testing.T) {
	useDeadServices(t)
	cfg := ragconfig.Config{QdrantGRPCURL: "127.0.0.1:6399", EmbedServerURL: "http://127.0.0.1:8199"}
	out := formatHealth(nativeHealth(cfg), nil, cfg)
	for _, want := range []string{"qdrant", "127.0.0.1:6399", "embed_server", "http://127.0.0.1:8199", "blk up"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "API") {
		t.Errorf("output still mentions the API:\n%s", out)
	}
}

// TestNativeHealthDegraded verifies the TUI health path folds the native
// probes into a HealthResponse without the Python API: degraded when down.
func TestNativeHealthDegraded(t *testing.T) {
	useDeadServices(t)
	cfg := ragconfig.Config{QdrantGRPCURL: "127.0.0.1:6399", EmbedServerURL: "http://127.0.0.1:8199"}
	h := nativeHealth(cfg)
	if h.Status != "degraded" || h.Qdrant || h.EmbedServer {
		t.Fatalf("want degraded with both down, got %+v", h)
	}
}

// TestReplSearchUnreachableKeepsPrev verifies replSearch goes through the
// native retrieval client: with services down it reports the error and returns
// the previous results so `open N` keeps working.
func TestReplSearchUnreachableKeepsPrev(t *testing.T) {
	useDeadServices(t)
	t.Setenv("QDRANT_GRPC_URL", "127.0.0.1:1")
	prev := []client.SearchResult{{ID: "keep"}}
	got := replSearch("ssrf", prev)
	if len(got) != 1 || got[0].ID != "keep" {
		t.Fatalf("want previous results kept, got %+v", got)
	}
}

// TestRunDoctorProbesNativeDependencies verifies doctor reports qdrant and
// embed_server rows (with a `blk up` hint when down) and never the Python API.
func TestRunDoctorProbesNativeDependencies(t *testing.T) {
	useDeadServices(t)
	t.Setenv("QDRANT_GRPC_URL", "127.0.0.1:1")
	t.Setenv("HERMES_HOME", t.TempDir())
	out := captureStdout(t, func() {
		if err := runDoctor(nil); err != nil {
			t.Fatalf("runDoctor() error = %v", err)
		}
	})
	for _, want := range []string{"qdrant", "127.0.0.1:1", "embed_server", "blk up"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "blkChain API") {
		t.Errorf("output still mentions the API:\n%s", out)
	}
}

// TestStyleErrUnreachableHintOnce verifies an unreachable retrieval error shows
// the `blk up` instruction exactly once (the error text carries it already).
func TestStyleErrUnreachableHintOnce(t *testing.T) {
	err := fmt.Errorf("%w: qdrant: connection refused", retrieval.ErrUnreachable)
	out := styleErr(err)
	if n := strings.Count(out, "blk up"); n != 1 {
		t.Errorf("want `blk up` exactly once, got %d:\n%s", n, out)
	}
}

// deadLoopbackURL returns a base URL nothing listens on.
func deadLoopbackURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return "http://" + addr + "/v1"
}

func TestProbeLLMUpSendsKeyAndUsesModelsPath(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()
	if !probeLLM(srv.URL+"/v1", "s3cret") {
		t.Fatal("probeLLM = false against a healthy server")
	}
	if gotPath != "/v1/models" || gotAuth != "Bearer s3cret" {
		t.Errorf("path=%q auth=%q", gotPath, gotAuth)
	}
}

func TestProbeLLMNoKeyNoAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer srv.Close()
	if !probeLLM(srv.URL, "") {
		t.Fatal("probeLLM = false")
	}
	if gotAuth != "" {
		t.Errorf("Authorization = %q, want none", gotAuth)
	}
}

func TestProbeLLMDownAndNon2xx(t *testing.T) {
	if probeLLM(deadLoopbackURL(t), "") {
		t.Error("dead port reported up")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if probeLLM(srv.URL, "") {
		t.Error("HTTP 500 reported up")
	}
}

// An endless body must not hang the probe: the read is capped and discarded.
func TestProbeLLMCapsBodyRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 64<<10)
		for r.Context().Err() == nil {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	start := time.Now()
	if !probeLLM(srv.URL, "") {
		t.Fatal("probeLLM = false for an endless 200 body")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("probe took %v, the body read is not capped", d)
	}
}

func TestProbeLLMTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	start := time.Now()
	if probeLLMWithTimeout(srv.URL, "", 150*time.Millisecond) {
		t.Fatal("hung server reported up")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("probe took %v, timeout not honored", d)
	}
}

func TestNativeHealthReportsThreeServices(t *testing.T) {
	cfg := ragconfig.Config{QdrantGRPCURL: "127.0.0.1:6399", EmbedServerURL: "http://127.0.0.1:8199"}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()

	t.Setenv("OMLX_BASE_URL", up.URL)
	if h := nativeHealth(cfg); !h.LLM || h.Status != "degraded" {
		t.Errorf("llm up, qdrant+embed down: %+v", h)
	}
	t.Setenv("OMLX_BASE_URL", deadLoopbackURL(t))
	if h := nativeHealth(cfg); h.LLM {
		t.Errorf("llm down reported up: %+v", h)
	}
}

func TestDownServicesNamesEachOne(t *testing.T) {
	cases := []struct {
		h    client.HealthResponse
		want string
	}{
		{client.HealthResponse{Qdrant: true, EmbedServer: true, LLM: true}, ""},
		{client.HealthResponse{Qdrant: true, EmbedServer: true}, "llm"},
		{client.HealthResponse{EmbedServer: true, LLM: true}, "qdrant"},
		{client.HealthResponse{Qdrant: true, LLM: true}, "embed_server"},
		{client.HealthResponse{}, "qdrant, embed_server, llm"},
	}
	for _, c := range cases {
		if got := strings.Join(downServices(&c.h), ", "); got != c.want {
			t.Errorf("%+v: got %q want %q", c.h, got, c.want)
		}
	}
}

func TestFormatHealthShowsLLMRowAndHint(t *testing.T) {
	cfg := ragconfig.Config{QdrantGRPCURL: "127.0.0.1:6399", EmbedServerURL: "http://127.0.0.1:8199"}
	base := "http://127.0.0.1:8123/v1"
	t.Setenv("OMLX_BASE_URL", base)
	h := &client.HealthResponse{Status: "degraded", Qdrant: true, EmbedServer: true}
	out := formatHealth(h, nil, cfg)
	for _, want := range []string{"llm", base, "start the LLM server"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "blk up") {
		t.Errorf("qdrant and embed_server are up, `blk up` hint is wrong:\n%s", out)
	}
	ok := formatHealth(&client.HealthResponse{Status: "ok", Qdrant: true, EmbedServer: true, LLM: true}, nil, cfg)
	if strings.Contains(ok, "start the LLM server") || strings.Contains(ok, "blk up") {
		t.Errorf("all up must not print hints:\n%s", ok)
	}
}

func TestRunHealthAndDoctorReportLLM(t *testing.T) {
	useDeadServices(t)
	t.Setenv("QDRANT_GRPC_URL", "127.0.0.1:1")
	t.Setenv("HERMES_HOME", t.TempDir())
	base := deadLoopbackURL(t)
	t.Setenv("OMLX_BASE_URL", base)
	t.Setenv("OMLX_API_KEY", "must-not-print")

	health := captureStdout(t, func() { _ = runHealth(nil) })
	doctor := captureStdout(t, func() { _ = runDoctor(nil) })
	for name, out := range map[string]string{"health": health, "doctor": doctor} {
		if !strings.Contains(out, "llm") || !strings.Contains(out, base) {
			t.Errorf("%s output lacks the llm row:\n%s", name, out)
		}
		if strings.Contains(out, "must-not-print") {
			t.Errorf("%s output leaks the API key", name)
		}
	}
}

// useDeadServices points the embed server (through the loadConfig seam, since
// it has no environment override) and the LLM server at dead loopback ports, so
// tests never probe the real default ones. A test that needs a live LLM sets
// OMLX_BASE_URL after calling it.
func useDeadServices(t *testing.T) {
	t.Helper()
	dead := deadLoopbackURL(t)
	t.Setenv("OMLX_BASE_URL", deadLoopbackURL(t))
	prev := loadConfig
	loadConfig = func() ragconfig.Config {
		cfg := prev()
		cfg.EmbedServerURL = dead
		return cfg
	}
	t.Cleanup(func() { loadConfig = prev })
}
