package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

// healthOf runs nativeHealth with a retrieval client made from cfg.
func healthOf(t *testing.T, cfg ragconfig.Config) *serviceHealth {
	t.Helper()
	rc, err := newRetrievalClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	return nativeHealth(cfg, rc)
}

// The probes never panic and report both dependencies down when nothing is
// listening on either port, or when there is no retrieval client at all.
func TestProbesReportDownServices(t *testing.T) {
	cfg := ragconfig.Config{QdrantGRPCURL: "127.0.0.1:6399", EmbedServerURL: "http://127.0.0.1:8199"}
	rc, err := newRetrievalClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if q, e := probeQdrant(rc), probeEmbedServer(cfg); q || e {
		t.Fatalf("both should be false when nothing is up: q=%v e=%v", q, e)
	}
	if probeQdrant(nil) {
		t.Error("no client reported qdrant up")
	}
}

// The Qdrant probe is a liveness RPC on the retrieval client's own connection.
func TestProbeQdrantUsesTheRetrievalClient(t *testing.T) {
	conns := useFakeRetrieval(t, goldenPayload())
	rc, err := newRetrievalClient(loadConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if !probeQdrant(rc) {
		t.Fatal("probeQdrant = false against a live Qdrant")
	}
	if _, err := rc.Search(context.Background(), "q", 0, nil); err != nil {
		t.Fatal(err)
	}
	if n := conns.Load(); n != 1 {
		t.Errorf("probe and search opened %d connections, want 1", n)
	}
}

// TestFormatHealthNamesDependencies checks the TUI health report describes the
// real dependencies and their addresses, not the API.
func TestFormatHealthNamesDependencies(t *testing.T) {
	useDeadServices(t)
	cfg := ragconfig.Config{QdrantGRPCURL: "127.0.0.1:6399", EmbedServerURL: "http://127.0.0.1:8199"}
	out := formatHealth(healthOf(t, cfg), cfg)
	for _, want := range []string{"qdrant", "127.0.0.1:6399", "embed_server", "http://127.0.0.1:8199", "blk up"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "API") {
		t.Errorf("output still mentions the API:\n%s", out)
	}
}

// TestNativeHealthDegraded verifies the health path folds the probes into one
// report: not ok when services are down.
func TestNativeHealthDegraded(t *testing.T) {
	useDeadServices(t)
	cfg := ragconfig.Config{QdrantGRPCURL: "127.0.0.1:6399", EmbedServerURL: "http://127.0.0.1:8199"}
	h := healthOf(t, cfg)
	if h.ok() || h.Qdrant || h.EmbedServer {
		t.Fatalf("want degraded with both down, got %+v", h)
	}
}

// TestReplSearchUnreachableKeepsPrev verifies replSearch goes through the
// native retrieval client: with services down it reports the error and returns
// the previous results so `open N` keeps working.
func TestReplSearchUnreachableKeepsPrev(t *testing.T) {
	useDeadServices(t)
	t.Setenv("QDRANT_GRPC_URL", "127.0.0.1:1")
	prev := []retrieval.Result{{ID: "keep"}}
	got := replSearch("ssrf", prev, &replClient{})
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
func deadLoopbackURL(t testing.TB) string {
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
	if probeLLM(srv.URL+"/v1", "s3cret", healthProbeTimeout) != nil {
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
	if probeLLM(srv.URL, "", healthProbeTimeout) != nil {
		t.Fatal("probeLLM = false")
	}
	if gotAuth != "" {
		t.Errorf("Authorization = %q, want none", gotAuth)
	}
}

func TestProbeLLMDownAndNon2xx(t *testing.T) {
	if probeLLM(deadLoopbackURL(t), "", healthProbeTimeout) == nil {
		t.Error("dead port reported up")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if probeLLM(srv.URL, "", healthProbeTimeout) == nil {
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
	if probeLLM(srv.URL, "", healthProbeTimeout) != nil {
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
	if probeLLM(srv.URL, "", 150*time.Millisecond) == nil {
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
	if h := healthOf(t, cfg); !h.LLM || h.ok() {
		t.Errorf("llm up, qdrant+embed down: %+v", h)
	}
	t.Setenv("OMLX_BASE_URL", deadLoopbackURL(t))
	if h := healthOf(t, cfg); h.LLM {
		t.Errorf("llm down reported up: %+v", h)
	}
}

func TestDownServicesNamesEachOne(t *testing.T) {
	cases := []struct {
		h    serviceHealth
		want string
	}{
		{serviceHealth{Qdrant: true, EmbedServer: true, LLM: true}, ""},
		{serviceHealth{Qdrant: true, EmbedServer: true}, "llm"},
		{serviceHealth{EmbedServer: true, LLM: true}, "qdrant"},
		{serviceHealth{Qdrant: true, LLM: true}, "embed_server"},
		{serviceHealth{}, "qdrant, embed_server, llm"},
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
	h := &serviceHealth{Qdrant: true, EmbedServer: true}
	out := formatHealth(h, cfg)
	for _, want := range []string{"llm", base, "start the LLM server"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "blk up") {
		t.Errorf("qdrant and embed_server are up, `blk up` hint is wrong:\n%s", out)
	}
	ok := formatHealth(&serviceHealth{Qdrant: true, EmbedServer: true, LLM: true}, cfg)
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
func useDeadServices(t testing.TB) {
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

// blk doctor says to change a Hermes entry that still runs the retired Python
// MCP server to blk mcp, and never edits the file.
func TestDoctorFlagsTheRetiredPythonMCPServer(t *testing.T) {
	useDeadServices(t)
	t.Setenv("QDRANT_GRPC_URL", "127.0.0.1:1")
	home := t.TempDir()
	t.Setenv("HERMES_HOME", home)
	cfg := filepath.Join(home, "config.yaml")
	body := []byte("mcp_servers:\n  blkchain:\n    command: python\n    args: [\"-m\", \"blkchain.mcp_server\"]\n")
	if err := os.WriteFile(cfg, body, 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() { _ = runDoctor(nil) })
	if !strings.Contains(out, "python -m blkchain.mcp_server") || !strings.Contains(out, "blk mcp") {
		t.Errorf("doctor does not say to switch to blk mcp:\n%s", out)
	}
	if strings.Contains(out, "registered + enabled") {
		t.Errorf("doctor calls the retired entry fine:\n%s", out)
	}
	if got, _ := os.ReadFile(cfg); string(got) != string(body) {
		t.Error("doctor changed the Hermes config")
	}
}

// Each doctor hint sits under the rows it refers to: "try blk up" right after
// qdrant and embed_server, before the llm row, and the LLM hint after the llm
// row.
func TestDoctorHintsFollowTheirRows(t *testing.T) {
	noColor(t)
	order := func(t *testing.T, out string, want ...string) {
		t.Helper()
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		at := 0
		for _, w := range want {
			found := false
			for ; at < len(lines); at++ {
				if strings.Contains(lines[at], w) {
					found = true
					at++
					break
				}
			}
			if !found {
				t.Errorf("want %q in order %q:\n%s", w, want, out)
				return
			}
		}
	}

	isolateUserDirs(t)
	useDeadServices(t)
	t.Setenv("QDRANT_GRPC_URL", "127.0.0.1:1")
	t.Setenv("HERMES_HOME", t.TempDir())
	all := captureStdout(t, func() { runDoctor(nil) })
	order(t, all, "qdrant", "embed_server", "try `blk up`", "llm", "start the LLM server at")

	cfg := loadConfig()
	for name, c := range map[string]struct {
		h       serviceHealth
		want    []string
		without string
	}{
		"only the LLM down":  {serviceHealth{Qdrant: true, EmbedServer: true}, []string{"qdrant", "embed_server", "llm", "start the LLM server at"}, "blk up"},
		"only qdrant down":   {serviceHealth{EmbedServer: true, LLM: true}, []string{"qdrant", "embed_server", "try `blk up`", "llm"}, "start the LLM server"},
		"everything running": {serviceHealth{Qdrant: true, EmbedServer: true, LLM: true}, []string{"qdrant", "embed_server", "llm"}, "try"},
	} {
		t.Run(name, func(t *testing.T) {
			out := captureStdout(t, func() { printDoctorServices(&c.h, cfg, "http://llm.test/v1") })
			order(t, out, c.want...)
			if strings.Contains(out, c.without) {
				t.Errorf("output has %q:\n%s", c.without, out)
			}
		})
	}
}

// upLLM points OMLX_BASE_URL at a loopback server whose /models answers 200.
func upLLM(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OMLX_BASE_URL", srv.URL)
}

// A degraded stack still prints the human table, then returns the silent
// degraded sentinel, which maps to exit 1 and prints no second error line.
func TestRunHealthDegradedPrintsTableAndExitsOne(t *testing.T) {
	useDeadServices(t)
	t.Setenv("QDRANT_GRPC_URL", "127.0.0.1:1")
	var err error
	out := captureStdout(t, func() { err = runHealth(nil) })
	if !errors.Is(err, errDegraded) {
		t.Fatalf("runHealth err = %v, want errDegraded", err)
	}
	for _, want := range []string{"blkChain services:", "qdrant", "embed_server", "llm"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
	if got := exitCode(err); got != 1 {
		t.Errorf("exitCode = %d, want 1", got)
	}
	if got := exitCode(fmt.Errorf("wrapped: %w", errDegraded)); got != 1 {
		t.Errorf("exitCode(wrapped) = %d, want 1", got)
	}
	var stderr strings.Builder
	reportError(&stderr, err)
	if stderr.Len() != 0 {
		t.Errorf("reportError printed %q for the degraded sentinel, want nothing", stderr.String())
	}
}

// --json prints one object with the three booleans and no table.
func TestRunHealthJSONDegraded(t *testing.T) {
	useDeadServices(t)
	t.Setenv("QDRANT_GRPC_URL", "127.0.0.1:1")
	var err error
	out := captureStdout(t, func() { err = runHealth([]string{"--json"}) })
	if !errors.Is(err, errDegraded) {
		t.Fatalf("runHealth --json err = %v, want errDegraded", err)
	}
	if strings.Contains(out, "blkChain services:") {
		t.Errorf("--json printed the human table:\n%s", out)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("output is not one JSON object: %v\n%s", err, out)
	}
	for _, k := range []string{"ok", "qdrant", "embed_server", "llm"} {
		v, present := raw[k]
		if !present {
			t.Errorf("JSON missing %q: %s", k, out)
		} else if b, isBool := v.(bool); !isBool || b {
			t.Errorf("JSON %q = %v, want false", k, v)
		}
	}
}

// With every service answering, the table prints and the exit status is 0; with
// --json, ok is true.
func TestRunHealthAllUp(t *testing.T) {
	useFakeRetrieval(t, goldenPayload())
	upLLM(t)
	var err error
	out := captureStdout(t, func() { err = runHealth(nil) })
	if err != nil {
		t.Fatalf("runHealth err = %v, want nil when all services are up\n%s", err, out)
	}
	if !strings.Contains(out, "blkChain services:") {
		t.Errorf("table missing:\n%s", out)
	}
	out = captureStdout(t, func() { err = runHealth([]string{"--json"}) })
	if err != nil {
		t.Fatalf("runHealth --json err = %v, want nil\n%s", err, out)
	}
	var got healthResponse
	if e := json.Unmarshal([]byte(out), &got); e != nil {
		t.Fatalf("bad JSON: %v\n%s", e, out)
	}
	if !got.OK || !got.Qdrant || !got.EmbedServer || !got.LLM {
		t.Errorf("health JSON = %+v, want all true", got)
	}
}

// ok is true only when all three services are up.
func TestHealthResponseOKNeedsAllThree(t *testing.T) {
	cases := []struct {
		h    serviceHealth
		want bool
	}{
		{serviceHealth{Qdrant: true, EmbedServer: true, LLM: true}, true},
		{serviceHealth{Qdrant: true, EmbedServer: true}, false},
		{serviceHealth{EmbedServer: true, LLM: true}, false},
		{serviceHealth{Qdrant: true, LLM: true}, false},
	}
	for _, c := range cases {
		if got := newHealthResponse(&c.h).OK; got != c.want {
			t.Errorf("ok for %+v = %v, want %v", c.h, got, c.want)
		}
	}
}
