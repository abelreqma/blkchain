package modeleval

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sse writes an OpenAI-style streaming chat completion: three content deltas,
// then (if withUsage) a usage-only chunk, then [DONE].
func sse(w http.ResponseWriter, withUsage bool) {
	fl, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	for _, tok := range []string{"Server", " side", " request"} {
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", tok)
		if fl != nil {
			fl.Flush()
		}
		time.Sleep(5 * time.Millisecond)
	}
	if withUsage {
		fmt.Fprint(w, "data: {\"choices\":[],\"usage\":{\"completion_tokens\":3}}\n\n")
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
	if fl != nil {
		fl.Flush()
	}
}

func chatCfg(base string) Config {
	return Config{
		ChatBaseURL:  base + "/v1",
		ReadyTimeout: 2 * time.Second,
		ProbeTimeout: 2 * time.Second,
		HTTPClient:   &http.Client{Timeout: 2 * time.Second},
	}
}

func TestProbeChatUsageReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/models"):
			w.Write([]byte(`{"data":[{"id":"supergemma4-26b"}]}`))
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			sse(w, true)
		}
	}))
	defer srv.Close()

	rep := ProbeChat(context.Background(), chatCfg(srv.URL))
	if !rep.Ready || rep.Err != nil {
		t.Fatalf("ready=%v err=%v", rep.Ready, rep.Err)
	}
	if rep.Perf.ModelID != "supergemma4-26b" {
		t.Errorf("model id = %q", rep.Perf.ModelID)
	}
	if !rep.Perf.UsageReported || rep.Perf.GenTokens != 3 {
		t.Errorf("usage: reported=%v tokens=%d want 3", rep.Perf.UsageReported, rep.Perf.GenTokens)
	}
	if rep.Perf.TTFT <= 0 || rep.Perf.TokensPerSec <= 0 {
		t.Errorf("ttft=%v tps=%v want both > 0", rep.Perf.TTFT, rep.Perf.TokensPerSec)
	}
}

func TestProbeChatUsageAbsentFallsBackToDeltaCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/models"):
			w.Write([]byte(`{"data":[{"id":"m"}]}`))
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			sse(w, false) // no usage chunk
		}
	}))
	defer srv.Close()

	rep := ProbeChat(context.Background(), chatCfg(srv.URL))
	if rep.Err != nil {
		t.Fatalf("err=%v", rep.Err)
	}
	if rep.Perf.UsageReported {
		t.Errorf("expected UsageReported=false")
	}
	if rep.Perf.GenTokens != 3 { // counted 3 content deltas
		t.Errorf("delta count = %d want 3", rep.Perf.GenTokens)
	}
}

func TestChatReadinessUsesConfiguredAuthentication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/models") {
			fmt.Fprint(w, `{"data":[{"id":"fixture"}]}`)
			return
		}
		sse(w, true)
	}))
	defer server.Close()
	cfg := chatCfg(server.URL)
	cfg.ChatAPIKey = "fixture-key"
	cfg.ReadyTimeout = 100 * time.Millisecond
	report := ProbeChat(context.Background(), cfg)
	if !report.Ready || report.Err != nil {
		t.Fatalf("authenticated server misclassified: %+v", report)
	}
}
