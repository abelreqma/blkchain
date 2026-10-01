package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"blkchain/cli/internal/modeleval"
	"blkchain/cli/internal/ragconfig"
)

func TestRenderReportChatReady(t *testing.T) {
	r := modeleval.ModelReport{
		Kind:         modeleval.KindChat,
		Ready:        true,
		ReadyElapsed: 1200 * time.Millisecond,
		Perf: &modeleval.PerfResult{
			ModelID: "supergemma4-26b", TTFT: 180 * time.Millisecond,
			GenTokens: 60, TokensPerSec: 492.3, UsageReported: true,
		},
	}
	out := renderReport(r)
	for _, want := range []string{"chat", "supergemma4-26b", "tok/s", "ttft"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderReportUnreachable(t *testing.T) {
	cfg := modeleval.Config{EmbedHealthURL: deadLoopbackURL(t) + "/health", ReadyTimeout: time.Millisecond, ProbeTimeout: time.Second}
	r := modeleval.ProbeEmbed(context.Background(), cfg)
	out := renderReport(r)
	if !strings.Contains(out, "blk up") {
		t.Errorf("unreachable render should mention `blk up`, got:\n%s", out)
	}
}

func TestRenderReportRerankNonFinite(t *testing.T) {
	r := modeleval.ModelReport{
		Kind: modeleval.KindRerank, Ready: true,
		Perf: &modeleval.PerfResult{PoolSize: 5, Ms: 41, NonFinite: 2},
	}
	out := renderReport(r)
	if !strings.Contains(out, "non-finite") {
		t.Errorf("expected non-finite flag, got:\n%s", out)
	}
}

// TestModelsConfigEmbedURLsFromContract verifies the embed probe URLs derive
// from ragconfig's EmbedServerURL rather than a hardcoded port.
func TestModelsConfigEmbedURLsFromContract(t *testing.T) {
	base := strings.TrimRight(ragconfig.Load().EmbedServerURL, "/")
	cfg := modelsConfig()
	if cfg.EmbedHealthURL != base+"/health" || cfg.EmbedURL != base+"/embed" || cfg.RerankURL != base+"/rerank" {
		t.Errorf("embed URLs not derived from %q: %+v", base, cfg)
	}
}

func sampleReports() []modeleval.ModelReport {
	return []modeleval.ModelReport{
		{Kind: modeleval.KindChat, Ready: true, Perf: &modeleval.PerfResult{ModelID: "gemma", TokensPerSec: 40, UsageReported: true}},
		{Kind: modeleval.KindEmbed, Ready: true, Perf: &modeleval.PerfResult{Dim: 1024, MsPerVector: 3}},
		{Kind: modeleval.KindRerank, Ready: true, Perf: &modeleval.PerfResult{PoolSize: 50, Ms: 300}},
	}
}

// blk models shows the /models switches: the reranker off, web search, and the
// hidden chat models, in words.
func TestModelsTextShowsTheSwitches(t *testing.T) {
	noColor(t)
	p := modelPrefs{Hidden: []string{"qwen-a", "x\x1b]0;t\x07y"}, Rerank: false, Web: true}
	out := renderModelsText(sampleReports(), p, webProviderTavily)
	if l := lineWith(out, "rerank"); !strings.Contains(l, "off") {
		t.Errorf("rerank line lacks off: %q", l)
	}
	if l := lineWith(out, "web"); !strings.Contains(l, "on (tavily)") {
		t.Errorf("web line = %q, want on (tavily)", l)
	}
	if l := lineWith(out, "hidden"); !strings.Contains(l, "qwen-a") {
		t.Errorf("hidden line = %q", l)
	}
	if strings.Contains(out, "\x07") {
		t.Errorf("hidden id was not sanitized: %q", out)
	}
	out = renderModelsText(sampleReports(), defaultPrefs(), webProviderNone)
	if l := lineWith(out, "web"); !strings.Contains(l, "no provider") {
		t.Errorf("web line = %q, want no provider", l)
	}
	if strings.Contains(lineWith(out, "rerank"), "off") || strings.Contains(out, "hidden") {
		t.Errorf("defaults should show nothing off or hidden:\n%s", out)
	}
}

func TestModelsJSONIncludesTheSwitches(t *testing.T) {
	var buf strings.Builder
	p := modelPrefs{Hidden: []string{"qwen-a"}, Rerank: false, Web: false}
	if err := emitReportsJSON(&buf, sampleReports(), p, webProviderTavily); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(buf.String()), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	byModel := map[string]map[string]any{}
	for _, r := range got {
		byModel[r["model"].(string)] = r
	}
	if byModel["rerank"]["enabled"] != false || byModel["embed"]["enabled"] != true || byModel["chat"]["enabled"] != true {
		t.Errorf("enabled fields wrong: %s", buf.String())
	}
	if h, _ := byModel["chat"]["hidden"].([]any); len(h) != 1 || h[0] != "qwen-a" {
		t.Errorf("chat hidden = %v", byModel["chat"]["hidden"])
	}
	web := byModel["web"]
	if web == nil || web["ready"] != true || web["enabled"] != false || web["provider"] != "tavily" {
		t.Errorf("web entry = %v", web)
	}
}

// Hidden ids come from the LLM server. C1 controls and DEL in them are escaped
// in the JSON, so none reaches the terminal raw, and they decode unchanged.
func TestModelsJSONEscapesControlRunes(t *testing.T) {
	hostile := []string{"csi\u009b31m", "osc\u009d0;t\u0007", "del\u007f"}
	var buf strings.Builder
	if err := emitReportsJSON(&buf, sampleReports(), modelPrefs{Hidden: hostile}, webProviderTavily); err != nil {
		t.Fatal(err)
	}
	for _, r := range []rune{0x9b, 0x9d, 0x7f} {
		if strings.ContainsRune(buf.String(), r) {
			t.Errorf("U+%04X reached the output raw", r)
		}
	}
	var got []struct {
		Model  string   `json:"model"`
		Hidden []string `json:"hidden"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	for _, r := range got {
		if r.Model == "chat" && strings.Join(r.Hidden, "|") != strings.Join(hostile, "|") {
			t.Errorf("hidden decoded to %q, want %q", r.Hidden, hostile)
		}
	}
	if !strings.HasSuffix(buf.String(), "]\n") {
		t.Errorf("output should end with one newline: %q", buf.String()[max(buf.Len()-10, 0):])
	}
}

// The blk models chat probe sends only its own fixed settings: none of the
// answer sampling settings reach it.
func TestModelsChatProbeSendsNoSampling(t *testing.T) {
	isolateUserDirs(t)
	useDeadServices(t)
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/models") {
			w.Write([]byte(`{"data":[{"id":"m"}]}`))
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n"))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "")
	modeleval.ProbeChat(context.Background(), modelsConfig())
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("probe sent %d chat calls, want 1", len(bodies))
	}
	for _, k := range []string{"top_p", "top_k", "presence_penalty"} {
		if _, ok := bodies[0][k]; ok {
			t.Errorf("probe body carries %s: %v", k, bodies[0])
		}
	}
}

// The /models text web row names the active provider and composes it with the
// web switch: on/off for a configured provider, and a no-provider message
// (switch moot) when nothing is configured.
func TestRenderModelsTextWebProviderStates(t *testing.T) {
	noColor(t)
	cases := []struct {
		provider string
		web      bool
		want     string
	}{
		{webProviderTavily, true, "on (tavily)"},
		{webProviderTavily, false, "off (tavily configured)"},
		{webProviderDuckDuckGo, true, "on (duckduckgo fallback)"},
		{webProviderDuckDuckGo, false, "off (duckduckgo fallback configured)"},
		{webProviderNone, true, "no provider"},
		{webProviderNone, false, "no provider"},
	}
	for _, c := range cases {
		out := renderModelsText(sampleReports(), modelPrefs{Web: c.web}, c.provider)
		if l := lineWith(out, "web"); !strings.Contains(l, c.want) {
			t.Errorf("provider %q web=%v: line = %q, want %q", c.provider, c.web, l, c.want)
		}
	}
}

// The web row in blk models --json reports ready by capability (any provider,
// including the keyless DuckDuckGo fallback) and carries the provider label.
func TestEmitReportsJSONWebProvider(t *testing.T) {
	cases := []struct {
		provider  string
		web       bool
		wantReady bool
	}{
		{webProviderTavily, true, true},
		{webProviderDuckDuckGo, false, true},
		{webProviderNone, false, false},
	}
	for _, c := range cases {
		var buf strings.Builder
		if err := emitReportsJSON(&buf, sampleReports(), modelPrefs{Web: c.web}, c.provider); err != nil {
			t.Fatal(err)
		}
		var got []map[string]any
		if err := json.Unmarshal([]byte(buf.String()), &got); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
		}
		var web map[string]any
		for _, r := range got {
			if r["model"] == "web" {
				web = r
			}
		}
		if web == nil {
			t.Fatalf("no web row: %s", buf.String())
		}
		if web["ready"] != c.wantReady {
			t.Errorf("provider %q: ready = %v, want %v", c.provider, web["ready"], c.wantReady)
		}
		if web["provider"] != c.provider {
			t.Errorf("provider %q: provider field = %v", c.provider, web["provider"])
		}
		if web["enabled"] != c.web {
			t.Errorf("provider %q: enabled = %v, want %v", c.provider, web["enabled"], c.web)
		}
	}
}
