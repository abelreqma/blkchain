package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"blkchain/cli/internal/retrieval"
	"github.com/tmc/langchaingo/llms"
)

func TestRouteGuard(t *testing.T) {
	cases := []struct {
		q      string
		kind   routeKind
		forced bool
	}{
		{"CVE-2024-1234 poc", routeGround, true},
		{"is there an exploit for this", routeGround, true},
		{"2 + 2 * 3", routeSkip, true},
		{"(10 - 4) / 2 =", routeSkip, true},
		{"what is SSRF", routeSkip, false}, // no guardrail: ask the model
		{"how does XSS work", routeSkip, false},
	}
	for _, c := range cases {
		kind, forced := routeGuard(c.q)
		if forced != c.forced {
			t.Errorf("routeGuard(%q) forced = %v, want %v", c.q, forced, c.forced)
			continue
		}
		if forced && kind != c.kind {
			t.Errorf("routeGuard(%q) kind = %v, want %v", c.q, kind, c.kind)
		}
	}
}

func TestIsPureArithmetic(t *testing.T) {
	yes := []string{"2+2", "10 * (3 - 1)", "42 / 7 =", "3.5 + 1", "(10-4)/2="}
	no := []string{
		"what is 2+2 in binary", "ssrf", "port 8080 open", "cve 2024",
		"10.0.0.0/8", "192.168.0.0/16", "2024-01-15", "1.2.3-4", "2024-1234",
		"()+()", "(+)",
	}
	for _, s := range yes {
		if !isPureArithmetic(s) {
			t.Errorf("isPureArithmetic(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if isPureArithmetic(s) {
			t.Errorf("isPureArithmetic(%q) = true, want false", s)
		}
	}
}

func TestRouteQueryBothDisabledSkips(t *testing.T) {
	m := &fakeModel{queue: []*llms.ContentResponse{textResp("GROUND")}}
	got, err := routeQuery(context.Background(), m, kbTestCfg(), "what is ssrf", enabledRoutes{Local: false, Web: false})
	if err != nil {
		t.Fatal(err)
	}
	if got != routeSkip {
		t.Errorf("route = %v, want routeSkip (nothing to ground with)", got)
	}
	if m.calls != 0 {
		t.Errorf("model called %d times, want 0 (short-circuit)", m.calls)
	}
}

func TestRouteQueryGuardrailForcesWithoutModel(t *testing.T) {
	m := &fakeModel{queue: []*llms.ContentResponse{textResp("SKIP")}}
	got, err := routeQuery(context.Background(), m, kbTestCfg(), "CVE-2024-1234", enabledRoutes{Local: true, Web: true})
	if err != nil {
		t.Fatal(err)
	}
	if got != routeGround {
		t.Errorf("route = %v, want routeGround (CVE guardrail)", got)
	}
	if m.calls != 0 {
		t.Errorf("model called %d times, want 0 (guardrail short-circuit)", m.calls)
	}
}

func TestRouteQueryClassifier(t *testing.T) {
	cases := []struct {
		reply string
		want  routeKind
	}{
		{"GROUND", routeGround},
		{"SKIP", routeSkip},
		{"skip", routeSkip},
		{" Ground ", routeGround},
		{"maybe", routeGround}, // garbage defaults to ground
		{"", routeGround},      // empty defaults to ground
	}
	for _, c := range cases {
		m := &fakeModel{queue: []*llms.ContentResponse{textResp(c.reply)}}
		got, err := routeQuery(context.Background(), m, kbTestCfg(), "what is xss", enabledRoutes{Local: true, Web: true})
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("reply %q: route = %v, want %v", c.reply, got, c.want)
		}
	}
}

// optsModel replies with a fixed response and records the call options.
type optsModel struct {
	resp *llms.ContentResponse
	opts llms.CallOptions
}

func (o *optsModel) GenerateContent(_ context.Context, _ []llms.MessageContent, opts ...llms.CallOption) (*llms.ContentResponse, error) {
	for _, fn := range opts {
		fn(&o.opts)
	}
	return o.resp, nil
}

func TestRouteQueryGenerateErrorDefaultsToGround(t *testing.T) {
	got, err := routeQuery(context.Background(), errModel{}, kbTestCfg(), "what is xss", enabledRoutes{Local: true, Web: true})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != routeGround {
		t.Errorf("route = %v, want routeGround", got)
	}
}

func TestRouteQueryEmptyChoicesDefaultsToGround(t *testing.T) {
	m := &fakeModel{queue: []*llms.ContentResponse{{}}}
	got, err := routeQuery(context.Background(), m, kbTestCfg(), "what is xss", enabledRoutes{Local: true, Web: true})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != routeGround {
		t.Errorf("route = %v, want routeGround", got)
	}
	if m.calls != 1 {
		t.Errorf("model called %d times, want 1", m.calls)
	}
}

func TestRouteQueryZeroMaxTokensFallsBack(t *testing.T) {
	cfg := kbTestCfg()
	cfg.RouteMaxTokens = 0
	m := &optsModel{resp: textResp("SKIP")}
	got, err := routeQuery(context.Background(), m, cfg, "what is xss", enabledRoutes{Local: true, Web: true})
	if err != nil {
		t.Fatal(err)
	}
	if got != routeSkip {
		t.Errorf("route = %v, want routeSkip (the reply was parsed)", got)
	}
	if m.opts.MaxTokens != 8 {
		t.Errorf("max tokens = %d, want 8 fallback", m.opts.MaxTokens)
	}
}

func TestDirectAnswerIncludesPreface(t *testing.T) {
	var (
		mu   sync.Mutex
		body string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		body = string(raw)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")

	_, _, err := directAnswer(context.Background(), kbTestCfg(), "capital of France?", AnswerOpts{
		Preface: "PROJECT-CONTEXT-XYZ",
		Stream:  func([]byte) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(body, "PROJECT-CONTEXT-XYZ") {
		t.Errorf("request body missing preface: %s", body)
	}
	if !strings.Contains(body, "capital of France?") {
		t.Errorf("request body missing question: %s", body)
	}
}

func TestDirectAnswerStreamsWithoutRetrieval(t *testing.T) {
	srv := fakeLLM(t, nil, "Paris is the capital of France.")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")

	var streamed strings.Builder
	answer, _, err := directAnswer(context.Background(), kbTestCfg(), "capital of France?", AnswerOpts{
		Stream: func(b []byte) { streamed.Write(b) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(answer, "Paris") {
		t.Errorf("answer = %q, want it to contain Paris", answer)
	}
	if !strings.Contains(streamed.String(), "Paris") {
		t.Errorf("stream = %q, want streamed tokens", streamed.String())
	}
}

func TestAdaptiveAnswerSkipDoesNotSearch(t *testing.T) {
	srv := fakeLLM(t, []string{"SKIP"}, "direct answer, no sources")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "")

	rs := &recSearcher{results: []retrieval.Result{chunk("wstg", "a.md", "s", "local")}}
	ans, cits, usedWeb, results, _, route, err := adaptiveAnswer(context.Background(), rs, answerCfg(2), "capital of France?", enabledRoutes{Local: true, Web: false}, false, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if route != "skip" {
		t.Errorf("route = %q, want skip", route)
	}
	if rs.query != "" {
		t.Errorf("skip must not call Search, got %q", rs.query)
	}
	if !strings.Contains(ans, "direct answer") {
		t.Errorf("answer = %q", ans)
	}
	if len(cits) != 0 || usedWeb || len(results) != 0 {
		t.Errorf("skip must have empty cits/results and used_web false")
	}
}

func TestAdaptiveAnswerGroundSearches(t *testing.T) {
	srv := fakeLLM(t, []string{"GROUND", `{"sufficient":true,"rewrite":"","use_web":false}`}, "grounded [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "")

	rs := &recSearcher{results: []retrieval.Result{chunk("wstg", "a.md", "s", "local text")}}
	_, _, _, _, _, route, err := adaptiveAnswer(context.Background(), rs, answerCfg(2), "what is ssrf", enabledRoutes{Local: true, Web: false}, false, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if route != "rag" {
		t.Errorf("route = %q, want rag", route)
	}
	if rs.query != "what is ssrf" {
		t.Errorf("ground must call Search, got %q", rs.query)
	}
}

func TestAdaptiveAnswerForceBypassesRouter(t *testing.T) {
	// Only one non-streaming reply queued: the grade. If the router ran it would
	// consume a reply first, so force proves the router was skipped.
	srv := fakeLLM(t, []string{`{"sufficient":true,"rewrite":"","use_web":false}`}, "grounded [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "")

	rs := &recSearcher{results: []retrieval.Result{chunk("wstg", "a.md", "s", "local text")}}
	// force=true, and Local disabled: force must still ground locally.
	_, _, _, _, _, route, err := adaptiveAnswer(context.Background(), rs, answerCfg(2), "anything", enabledRoutes{Local: false, Web: false}, true, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if route != "rag" {
		t.Errorf("route = %q, want rag (forced)", route)
	}
	if rs.query != "anything" {
		t.Errorf("force must call Search, got %q", rs.query)
	}
}
