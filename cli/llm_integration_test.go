package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/structgen"
	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/cache"
)

type integrationRequests struct {
	count   atomic.Int64
	mu      sync.Mutex
	formats []map[string]any
}

func TestJSONAnswerReportsCallMetrics(t *testing.T) {
	authorizeWebTest(t)
	srv := fakeLLM(t, nil, "answer [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	prior := webSearch
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		return []retrieval.Result{chunk(webSource, "https://fixture.test/doc", "Example", "evidence")}, nil
	}
	t.Cleanup(func() { webSearch = prior })
	var err error
	out := captureStdout(t, func() { _, err = askWithPreface(nil, nil, []string{"--web", "--json", "question"}, "") })
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatal(err)
	}
	var calls []map[string]any
	if err := json.Unmarshal(response["llm_calls"], &calls); err != nil || len(calls) != 1 || calls[0]["stage"] != "synthesis" {
		t.Fatalf("call metrics = %s, %v", response["llm_calls"], err)
	}
}

func TestInvalidSamplingCannotMergeCacheNamespaces(t *testing.T) {
	cfg := ragconfig.Load()
	_, first := integrationServer(t, "GROUND", false)
	a, err := newOMLX(cfg, "test-model")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), samplingKey{}, sampling{topP: math.NaN()})
	if kind, err := routeQuery(ctx, a, cfg, "explain network segmentation", enabledRoutes{Local: true}); err != nil || kind != routeGround {
		t.Fatalf("first route = %v, %v", kind, err)
	}
	_, second := integrationServer(t, "SKIP", false)
	b, err := newOMLX(cfg, "test-model")
	if err != nil {
		t.Fatal(err)
	}
	if kind, err := routeQuery(ctx, b, cfg, "explain network segmentation", enabledRoutes{Local: true}); err != nil || kind != routeSkip {
		t.Fatalf("second route = %v, %v", kind, err)
	}
	if first.count.Load() != 1 || second.count.Load() != 1 {
		t.Fatal("invalid sampling reused another endpoint's cache")
	}
}

func TestGradingCacheUsesEvidenceAndDoesNotReplayUsage(t *testing.T) {
	_, seen := integrationServer(t, `{"sufficient":true,"rewrite":"","use_web":false}`, true)
	cfg := ragconfig.Load()
	model, err := newOMLX(cfg, "test-model")
	if err != nil {
		t.Fatal(err)
	}
	ctx, metrics := withCallMetrics(context.Background())
	for _, text := range []string{"first evidence", "first evidence", "changed evidence"} {
		g, err := gradeContext(ctx, model, cfg, "question", []retrieval.Result{chunk("wstg", "doc", "section", text)})
		if err != nil || !g.Sufficient {
			t.Fatalf("grade = %+v, %v", g, err)
		}
	}
	calls, _ := metrics.snapshot()
	if seen.count.Load() != 2 || len(calls) != 3 || !calls[1].Cached || calls[1].UsageReported || calls[1].CompletionTokens != 0 {
		t.Fatalf("requests=%d, metrics=%+v", seen.count.Load(), calls)
	}
}

func TestCallMetricsAccountForMissingUsageAndCancellation(t *testing.T) {
	_, seen := integrationServer(t, "answer", false)
	model, err := newOMLX(ragconfig.Load(), "test-model")
	if err != nil {
		t.Fatal(err)
	}
	ctx, metrics := withCallMetrics(context.Background())
	msgs := []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, "question")}
	if _, err := model.GenerateContent(ctx, msgs); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := model.GenerateContent(canceled, msgs); err == nil {
		t.Fatal("canceled call succeeded")
	}
	calls, _ := metrics.snapshot()
	if len(calls) != 2 || calls[0].UsageReported || calls[1].Status != "canceled" || seen.count.Load() != 1 {
		t.Fatalf("call metrics = %+v", calls)
	}
}

func TestConcurrentCallMetricsStayBounded(t *testing.T) {
	_, seen := integrationServer(t, "answer", false)
	model, err := newOMLX(ragconfig.Load(), "test-model")
	if err != nil {
		t.Fatal(err)
	}
	ctx, metrics := withCallMetrics(context.Background())
	var wg sync.WaitGroup
	for range 80 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := model.GenerateContent(ctx, []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, "question")}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	calls, partial := metrics.snapshot()
	if len(calls) != 64 || !partial || seen.count.Load() != 80 {
		t.Fatalf("calls=%d partial=%v requests=%d", len(calls), partial, seen.count.Load())
	}
}

func TestRoutingCacheExpiresAndEvicts(t *testing.T) {
	_, seen := integrationServer(t, "GROUND", false)
	cfg := ragconfig.Load()
	model, err := newOMLX(cfg, "test-model")
	if err != nil {
		t.Fatal(err)
	}
	backend := &decisionResponses{entries: map[string]decisionEntry{}}
	model.cached = cache.New(model.raw, backend)
	for i := 0; i < 129; i++ {
		question := "network context " + string(rune('a'+i))
		if _, err := routeQuery(context.Background(), model, cfg, question, enabledRoutes{Local: true}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := routeQuery(context.Background(), model, cfg, "network context a", enabledRoutes{Local: true}); err != nil {
		t.Fatal(err)
	}
	if seen.count.Load() != 130 {
		t.Fatalf("requests=%d, oldest response was not evicted", seen.count.Load())
	}
	backend.mu.Lock()
	for key, entry := range backend.entries {
		entry.expires = time.Now().Add(-time.Second)
		backend.entries[key] = entry
	}
	backend.mu.Unlock()
	if _, err := routeQuery(context.Background(), model, cfg, "network context a", enabledRoutes{Local: true}); err != nil {
		t.Fatal(err)
	}
	if seen.count.Load() != 131 {
		t.Fatal("expired response was reused")
	}
}

func TestRoutingCacheSeparatesModelCredentialsAndThinking(t *testing.T) {
	_, seen := integrationServer(t, "GROUND", false)
	cfg := ragconfig.Load()
	route := func(modelName string) {
		t.Helper()
		model, err := newOMLX(cfg, modelName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := routeQuery(context.Background(), model, cfg, "network context", enabledRoutes{Local: true}); err != nil {
			t.Fatal(err)
		}
	}
	route("test-model")
	route("test-model")
	route("other-model")
	t.Setenv("OMLX_API_KEY", "other-test-key")
	route("test-model")
	t.Setenv("BLK_ENABLE_THINKING", "1")
	route("test-model")
	if n := seen.count.Load(); n != 4 {
		t.Fatalf("requests=%d, want isolated configuration caches", n)
	}
}

func TestReconAndProseCallsAreNotCached(t *testing.T) {
	_, seen := integrationServer(t, `{"continue":false}`, true)
	cfg := ragconfig.Load()
	model, err := newOMLX(cfg, "test-model")
	if err != nil {
		t.Fatal(err)
	}
	grader := newLLMReconGrader(model, cfg)
	for range 2 {
		if !grader(context.Background(), engagement.SurfaceNetwork, "fixture.test", "coverage").Parsed {
			t.Fatal("invalid recon response")
		}
	}
	for range 2 {
		if _, err := model.GenerateContent(context.Background(), []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, "question")}, llms.WithTemperature(0)); err != nil {
			t.Fatal(err)
		}
	}
	if n := seen.count.Load(); n != 4 {
		t.Fatalf("requests=%d, cached a mutable or generative call", n)
	}
}

func TestCallMetricsCaptureTransportFailureWithoutErrorContent(t *testing.T) {
	srv, _ := integrationServer(t, "answer", false)
	model, err := newOMLX(ragconfig.Load(), "test-model")
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()
	ctx, metrics := withCallMetrics(context.Background())
	if _, err := model.GenerateContent(ctx, []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, "untrusted-input-marker")}); err == nil {
		t.Fatal("closed endpoint succeeded")
	}
	calls, _ := metrics.snapshot()
	if len(calls) != 1 || calls[0].Status != "error" || calls[0].UsageReported {
		t.Fatalf("metrics=%+v", calls)
	}
	raw, err := json.Marshal(calls)
	if err != nil || strings.Contains(string(raw), "untrusted-input-marker") || strings.Contains(string(raw), srv.URL) {
		t.Fatalf("unsafe failure metadata: %s, %v", raw, err)
	}
}

func TestStrictSchemaStillValidatesPortRange(t *testing.T) {
	_, _ = integrationServer(t, `{"target":"fixture.test","asset_type":"host","technologies":[],"exposed_services":[{"port":70000,"service":"http","notes":""}],"attack_surface":[],"notes":""}`, false)
	model, err := newOMLX(ragconfig.Load(), "test-model")
	if err != nil {
		t.Fatal(err)
	}
	schema, _ := structgen.Lookup("target-profile")
	if _, err := structgen.Generate(context.Background(), model, "fixture.test", schema, structgen.Options{}); !errors.Is(err, structgen.ErrInvalidOutput) {
		t.Fatalf("invalid port accepted: %v", err)
	}
}

func TestTUICostReportsModelStages(t *testing.T) {
	m := newKeyModel(t)
	authorizeWebTest(t)
	srv := fakeLLM(t, nil, "answer [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	prior := webSearch
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		return []retrieval.Result{chunk(webSource, "https://fixture.test/doc", "Example", "evidence")}, nil
	}
	t.Cleanup(func() { webSearch = prior })
	m.cfg = ragconfig.Load()
	m.ragModel = "m"
	message := m.streamCmd(context.Background(), "question", "", time.Now(), false, true)()
	done, ok := message.(streamDoneMsg)
	if !ok {
		t.Fatalf("message=%T", message)
	}
	updated, _ := m.Update(done)
	if output := updated.(model).costLine(); !strings.Contains(output, "synthesis") {
		t.Fatalf("cost details missing synthesis: %s", output)
	}
}

func integrationServer(t *testing.T, content string, usage bool) (*httptest.Server, *integrationRequests) {
	t.Helper()
	seen := &integrationRequests{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		format, _ := body["response_format"].(map[string]any)
		seen.mu.Lock()
		seen.formats = append(seen.formats, format)
		seen.mu.Unlock()
		seen.count.Add(1)
		response := map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": content}, "finish_reason": "stop",
		}}}
		if usage {
			response["usage"] = map[string]int{"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("BLK_ENABLE_THINKING", "0")
	return srv, seen
}

func TestStructuredCallsSendJSONMode(t *testing.T) {
	for _, kind := range []string{"grade", "recon"} {
		t.Run(kind, func(t *testing.T) {
			content := `{"sufficient":true,"rewrite":"","use_web":false}`
			if kind == "recon" {
				content = `{"continue":false}`
			}
			_, seen := integrationServer(t, content, false)
			cfg := ragconfig.Load()
			model, err := newOMLX(cfg, "test-model")
			if err != nil {
				t.Fatal(err)
			}
			if kind == "grade" {
				_, err = gradeContext(context.Background(), model, cfg, "question", nil)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				v := newLLMReconGrader(model, cfg)(context.Background(), engagement.SurfaceNetwork, "fixture.test", "coverage")
				if !v.Parsed {
					t.Fatal("valid recon response rejected")
				}
			}
			if len(seen.formats) != 1 || seen.formats[0]["type"] != "json_object" {
				t.Fatalf("response formats = %v, want json_object", seen.formats)
			}
		})
	}
}

func TestRoutingCacheSurvivesClientRecreation(t *testing.T) {
	_, seen := integrationServer(t, "GROUND", true)
	cfg := ragconfig.Load()
	for range 2 {
		model, err := newOMLX(cfg, "test-model")
		if err != nil {
			t.Fatal(err)
		}
		kind, err := routeQuery(context.Background(), model, cfg, "explain network segmentation", enabledRoutes{Local: true})
		if err != nil || kind != routeGround {
			t.Fatalf("route = %v, %v", kind, err)
		}
	}
	if n := seen.count.Load(); n != 1 {
		t.Fatalf("model requests = %d, want 1", n)
	}
}

func TestGenerationRecordsMetadataWithoutContent(t *testing.T) {
	_, _ = integrationServer(t, "untrusted-response-marker", true)
	model, err := newOMLX(ragconfig.Load(), "test-model")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := model.GenerateContent(context.Background(), []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, "untrusted-input-marker")})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(resp.Choices[0].GenerationInfo["CallStats"])
	if err != nil {
		t.Fatal(err)
	}
	var stats map[string]any
	if err := json.Unmarshal(raw, &stats); err != nil {
		t.Fatal(err)
	}
	if stats["stage"] != "generation" || stats["model"] != "test-model" || stats["usage_reported"] != true || stats["completion_tokens"] != float64(3) {
		t.Fatalf("call metadata = %s", raw)
	}
	if strings.Contains(string(raw), "untrusted-") || strings.Contains(string(raw), "test-key") {
		t.Fatal("content leaked into call metadata")
	}
}

func TestStructuredSchemaDoesNotAffectProseClient(t *testing.T) {
	_, seen := integrationServer(t, `{"target":"fixture.test","asset_type":"host","technologies":[],"exposed_services":[],"attack_surface":[],"notes":""}`, false)
	model, err := newOMLX(ragconfig.Load(), "test-model")
	if err != nil {
		t.Fatal(err)
	}
	schema, ok := structgen.Lookup("target-profile")
	if !ok {
		t.Fatal("target-profile schema missing")
	}
	if _, err := structgen.Generate(context.Background(), model, "fixture.test", schema, structgen.Options{MaxTokens: 128}); err != nil {
		t.Fatal(err)
	}
	if _, err := model.GenerateContent(context.Background(), []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, "explain the result")}); err != nil {
		t.Fatal(err)
	}
	if len(seen.formats) != 2 || seen.formats[0]["type"] != "json_schema" || len(seen.formats[1]) != 0 {
		t.Fatalf("response formats = %v, want scoped json_schema followed by prose", seen.formats)
	}
}
