package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

func TestNextAction(t *testing.T) {
	cases := []struct {
		suff, web, tav, cve bool
		res                 int
		want                string
	}{
		{true, false, true, false, 3, "sufficient"},
		{false, true, true, false, 3, "web"},
		{false, false, true, true, 3, "web"},      // CVE heuristic forces web
		{false, true, false, false, 3, "rewrite"}, // no tavily key -> rewrite
		{false, false, false, false, 0, "rewrite"},
	}
	for i, c := range cases {
		if got := nextAction(grade{Sufficient: c.suff, UseWeb: c.web}, c.tav, c.cve, c.res); got != c.want {
			t.Errorf("case %d: got %s want %s", i, got, c.want)
		}
	}
}

func TestLooksLikeCVEorPoC(t *testing.T) {
	yes := []string{
		"CVE-2024-1234",
		"CVE-2024-12345678",
		"cve-2021-44228 details",
		"is there a poc for this bug",
		"proof-of-concept exploit",
		"proof of concept code",
		"any known exploit for this",
	}
	for _, q := range yes {
		if !looksLikeCVEorPoC(q) {
			t.Errorf("looksLikeCVEorPoC(%q) = false, want true", q)
		}
	}

	no := []string{
		"what is SSRF",
		"how does XSS work",
		"pocket knife safety",
	}
	for _, q := range no {
		if looksLikeCVEorPoC(q) {
			t.Errorf("looksLikeCVEorPoC(%q) = true, want false", q)
		}
	}
}

// fakeSearcher returns a fixed result set for every query.
type fakeSearcher struct{ results []retrieval.Result }

func (f fakeSearcher) Search(context.Context, string, int, map[string]any) ([]retrieval.Result, error) {
	return f.results, nil
}

// fakeLLM serves a loopback OpenAI-compatible endpoint. Non-streaming chat
// calls (grading) get the next entry of grades (the last one repeats);
// streaming calls get streamText.
func fakeLLM(t *testing.T, grades []string, streamText string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Stream bool `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			delta, _ := json.Marshal(streamText)
			fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":%s}}]}\n\ndata: [DONE]\n\n", delta)
			return
		}
		mu.Lock()
		g := grades[min(n, len(grades)-1)]
		n++
		mu.Unlock()
		content, _ := json.Marshal(g)
		fmt.Fprintf(w, `{"choices":[{"index":0,"message":{"role":"assistant","content":%s},"finish_reason":"stop"}]}`, content)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func answerCfg(maxLoops int) ragconfig.Config {
	cfg := ragconfig.Load()
	cfg.MaxLoops = maxLoops
	return cfg
}

func TestAnswerLoopStageOrderSufficient(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":true,"rewrite":"","use_web":false}`}, "ok [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "")

	var stages []string
	rc := fakeSearcher{[]retrieval.Result{chunk("wstg", "a.md", "s", "text")}}
	_, _, _, _, _, err := AnswerLoop(context.Background(), rc, answerCfg(2), "q", AnswerOpts{
		Stage: func(s string) { stages = append(stages, s) },
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"retrieving", "grading", "answering"}
	if !reflect.DeepEqual(stages, want) {
		t.Fatalf("stages = %v, want %v", stages, want)
	}
}

// MaxLoops <= 0 must not skip grading, the web fallback, and the guardrails: it
// is clamped to at least one pass. With MaxLoops=0 the loop still grades once.
func TestAnswerLoopClampsMaxLoopsToAtLeastOne(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":true,"rewrite":"","use_web":false}`}, "ok [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "")

	var stages []string
	rc := fakeSearcher{[]retrieval.Result{chunk("wstg", "a.md", "s", "text")}}
	_, _, _, _, _, err := AnswerLoop(context.Background(), rc, answerCfg(0), "q", AnswerOpts{
		Stage: func(s string) { stages = append(stages, s) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(stages, stageGrading) {
		t.Fatalf("stages = %v, want a grading pass even with MaxLoops=0", stages)
	}
}

func TestAnswerLoopStageOrderWebAndRewrite(t *testing.T) {
	srv := fakeLLM(t, []string{
		`{"sufficient":false,"rewrite":"better","use_web":true}`,
		`{"sufficient":false,"rewrite":"better2","use_web":false}`,
	}, "ok [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	authorizeWebTest(t)
	t.Setenv("TAVILY_SETUP_TOKEN", "k")
	old := webSearch
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		return []retrieval.Result{chunk("web", "https://example.com/x", "T", "body")}, nil
	}
	defer func() { webSearch = old }()

	var stages []string
	rc := fakeSearcher{[]retrieval.Result{chunk("wstg", "a.md", "s", "text")}}
	_, _, usedWeb, _, _, err := AnswerLoop(context.Background(), rc, answerCfg(2), "q", AnswerOpts{
		Stage: func(s string) { stages = append(stages, s) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !usedWeb {
		t.Error("usedWeb = false")
	}
	want := []string{"retrieving", "grading", "searching web", "grading", "rewriting query", "answering"}
	if !reflect.DeepEqual(stages, want) {
		t.Fatalf("stages = %v, want %v", stages, want)
	}
}

// With the web switch off the loop never searches the web, even with a token
// and a grade that asks for it; it takes the rewrite path instead.
func TestAnswerLoopWebOffMakesNoWebCall(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":false,"rewrite":"better","use_web":true}`}, "ok [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	authorizeWebTest(t)
	t.Setenv("TAVILY_SETUP_TOKEN", "k")
	calls := 0
	old := webSearch
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		calls++
		return []retrieval.Result{chunk("web", "https://example.com/x", "T", "body")}, nil
	}
	defer func() { webSearch = old }()

	var stages []string
	rc := fakeSearcher{[]retrieval.Result{chunk("wstg", "a.md", "s", "text")}}
	_, _, usedWeb, _, _, err := AnswerLoop(context.Background(), rc, answerCfg(2), "CVE-2024-1234 poc", AnswerOpts{
		NoWeb: true,
		Stage: func(s string) { stages = append(stages, s) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 || usedWeb {
		t.Errorf("web off: %d web calls, usedWeb=%v; want none", calls, usedWeb)
	}
	want := []string{"retrieving", "grading", "rewriting query", "grading", "rewriting query", "answering"}
	if !reflect.DeepEqual(stages, want) {
		t.Errorf("stages = %v, want %v", stages, want)
	}
}

func TestAnswerLoopNilStageIsNoop(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":true}`}, "ok [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	rc := fakeSearcher{[]retrieval.Result{chunk("wstg", "a.md", "s", "text")}}
	if _, _, _, _, _, err := AnswerLoop(context.Background(), rc, answerCfg(1), "q", AnswerOpts{}); err != nil {
		t.Fatal(err)
	}
}

func TestAnswerLoopNoResultsIsSentinelNotAnswer(t *testing.T) {
	isolateUserDirs(t)
	srv := fakeLLM(t, []string{`{"sufficient":false,"rewrite":"","use_web":false}`}, "unused")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "")

	streamed := false
	answer, cits, _, _, _, err := AnswerLoop(context.Background(), fakeSearcher{}, answerCfg(1), "q", AnswerOpts{
		Stream: func([]byte) { streamed = true },
	})
	if !errors.Is(err, ErrNoResults) {
		t.Fatalf("err = %v, want ErrNoResults", err)
	}
	if streamed || answer != "" || len(cits) != 0 {
		t.Errorf("no-results must not stream or answer: streamed=%v answer=%q cits=%v", streamed, answer, cits)
	}
}

func TestAnswerLoopCanceledEmptyRetrievalReturnsContextError(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":false,"rewrite":"","use_web":false}`}, "unused")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, _, _, err := AnswerLoop(ctx, fakeSearcher{}, answerCfg(1), "q", AnswerOpts{})
	if errors.Is(err, ErrNoResults) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled and not ErrNoResults", err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	_, _, _, _, _, err = AnswerLoop(ctx, fakeSearcher{}, answerCfg(1), "q", AnswerOpts{})
	if errors.Is(err, ErrNoResults) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded and not ErrNoResults", err)
	}
}

func TestAnswerLoopLLMDownNamesBaseURL(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + l.Addr().String() + "/v1"
	l.Close() // nothing listens here now
	t.Setenv("OMLX_BASE_URL", base)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "")

	rc := fakeSearcher{[]retrieval.Result{chunk("wstg", "a.md", "s", "text")}}
	_, _, _, _, _, err = AnswerLoop(context.Background(), rc, answerCfg(1), "q", AnswerOpts{})
	var down *llmUnreachableError
	if !errors.As(err, &down) {
		t.Fatalf("err = %v, want *llmUnreachableError", err)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("mapped error lost the underlying ECONNREFUSED: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, base) || !strings.Contains(msg, "start the LLM server") || strings.Contains(msg, "\n") {
		t.Errorf("message = %q, want one line naming %s and how to recover", msg, base)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestMapLLMError(t *testing.T) {
	const base = "http://127.0.0.1:8000/v1"
	other := errors.New("boom")
	if mapLLMError(nil, base) != nil {
		t.Error("nil must stay nil")
	}
	if got := mapLLMError(context.Canceled, base); !errors.Is(got, context.Canceled) || errors.As(got, new(*llmUnreachableError)) {
		t.Errorf("cancel must pass through, got %v", got)
	}
	if got := mapLLMError(other, base); got != other {
		t.Errorf("unrelated error must pass through, got %v", got)
	}
	for name, in := range map[string]error{
		"net timeout":       fmt.Errorf("post: %w", timeoutErr{}),
		"deadline exceeded": fmt.Errorf("post: %w", context.DeadlineExceeded),
	} {
		got := mapLLMError(in, base)
		msg := got.Error()
		if !strings.Contains(msg, "timed out") || !strings.Contains(msg, "BLKCHAIN_TIMEOUT_SECONDS") || strings.Contains(msg, "start the LLM server") {
			t.Errorf("%s: got %v, want a timeout message that says to raise BLKCHAIN_TIMEOUT_SECONDS", name, got)
		}
		var down *llmUnreachableError
		if !errors.As(got, &down) || down.refused() {
			t.Errorf("%s: a timeout must not count as the server being down: %v", name, got)
		}
	}
	refused := mapLLMError(syscall.ECONNREFUSED, base)
	var rd *llmUnreachableError
	if !errors.As(refused, &rd) || !rd.refused() || !strings.Contains(refused.Error(), "start the LLM server at "+base) {
		t.Errorf("refused: got %v", refused)
	}
	// A base URL with embedded credentials must not leak the password.
	got := mapLLMError(syscall.ECONNREFUSED, "http://u:secret@127.0.0.1:8000/v1")
	if strings.Contains(got.Error(), "secret") {
		t.Errorf("password leaked: %v", got)
	}
}

func TestRedactedURLDropsCredentialsQueryAndFragment(t *testing.T) {
	for _, raw := range []string{
		"http://sk-TOKEN@h/v1?key=SECRET",
		"http://u:pw@h/v1?key=SECRET#frag",
	} {
		got := redactedURL(raw)
		for _, leak := range []string{"sk-TOKEN", "SECRET", "pw", "frag", "u:"} {
			if strings.Contains(got, leak) {
				t.Errorf("redactedURL(%q) = %q leaks %q", raw, got, leak)
			}
		}
		if !strings.Contains(got, "h/v1") {
			t.Errorf("redactedURL(%q) = %q, want the host and path kept", raw, got)
		}
	}
	err := mapLLMError(syscall.ECONNREFUSED, "http://sk-TOKEN@h/v1?key=SECRET")
	if s := err.Error(); strings.Contains(s, "sk-TOKEN") || strings.Contains(s, "SECRET") {
		t.Errorf("error message leaks: %s", s)
	}
}

// llmRequest is what recordingLLM saw of one chat call.
type llmRequest struct {
	stream    bool
	maxTokens int
	auth      string
}

// recordingLLM is fakeLLM that also records each chat call's body and
// Authorization header. It answers the grade as sufficient.
func recordingLLM(t *testing.T) (*httptest.Server, func() []llmRequest) {
	t.Helper()
	var mu sync.Mutex
	var seen []llmRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Stream              bool `json:"stream"`
			MaxCompletionTokens int  `json:"max_completion_tokens"`
			MaxTokens           int  `json:"max_tokens"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		seen = append(seen, llmRequest{stream: body.Stream, maxTokens: max(body.MaxCompletionTokens, body.MaxTokens), auth: r.Header.Get("Authorization")})
		mu.Unlock()
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok [1]\"}}]}\n\ndata: [DONE]\n\n")
			return
		}
		fmt.Fprint(w, `{"choices":[{"index":0,"message":{"role":"assistant","content":"{\"sufficient\":true,\"rewrite\":\"\",\"use_web\":false}"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []llmRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]llmRequest(nil), seen...)
	}
}

// The answer cap and the grade cap each reach the call they belong to.
func TestAnswerLoopSendsTheTokenCaps(t *testing.T) {
	srv, seen := recordingLLM(t)
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	cfg := answerCfg(1)
	cfg.AnswerMaxTokens, cfg.GradeMaxTokens = 321, 45
	rc := fakeSearcher{[]retrieval.Result{chunk("wstg", "a.md", "s", "text")}}
	if _, _, _, _, _, err := AnswerLoop(context.Background(), rc, cfg, "q", AnswerOpts{}); err != nil {
		t.Fatal(err)
	}
	var graded, answered bool
	for _, r := range seen() {
		if r.stream {
			answered = true
			if r.maxTokens != 321 {
				t.Errorf("answer call max tokens = %d, want 321", r.maxTokens)
			}
		} else {
			graded = true
			if r.maxTokens != 45 {
				t.Errorf("grade call max tokens = %d, want 45", r.maxTokens)
			}
		}
	}
	if !graded || !answered {
		t.Fatalf("calls seen: %+v, want a grade and an answer", seen())
	}
}

// An LLM server that needs no key works with no key set anywhere, and gets no
// Authorization header.
func TestAnswerLoopWorksWithoutAnAPIKey(t *testing.T) {
	srv, seen := recordingLLM(t)
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	rc := fakeSearcher{[]retrieval.Result{chunk("wstg", "a.md", "s", "text")}}
	answer, _, _, _, _, err := AnswerLoop(context.Background(), rc, answerCfg(1), "q", AnswerOpts{})
	if err != nil {
		t.Fatalf("keyless ask failed: %v", err)
	}
	if answer != "ok [1]" {
		t.Errorf("answer = %q", answer)
	}
	for _, r := range seen() {
		if r.auth != "" {
			t.Errorf("keyless call sent Authorization %q", r.auth)
		}
	}
}

// With a key set, it is sent as a Bearer token.
func TestAnswerLoopSendsTheAPIKey(t *testing.T) {
	srv, seen := recordingLLM(t)
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	rc := fakeSearcher{[]retrieval.Result{chunk("wstg", "a.md", "s", "text")}}
	if _, _, _, _, _, err := AnswerLoop(context.Background(), rc, answerCfg(1), "q", AnswerOpts{}); err != nil {
		t.Fatal(err)
	}
	for _, r := range seen() {
		if r.auth != "Bearer test-key" {
			t.Errorf("Authorization = %q, want the key", r.auth)
		}
	}
}

// An LLM error body is read only up to a cap, so a huge error message never
// reaches the terminal whole.
func TestAnswerLoopBoundsTheLLMErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":{"message":%q}}`, strings.Repeat("e", 1<<20))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	rc := fakeSearcher{[]retrieval.Result{chunk("wstg", "a.md", "s", "text")}}
	_, _, _, _, _, err := AnswerLoop(context.Background(), rc, answerCfg(1), "q", AnswerOpts{})
	if err == nil {
		t.Fatal("want an error from a failing LLM")
	}
	if n := len(err.Error()); n > 1024 {
		t.Errorf("error is %d bytes, want the body cut short", n)
	}
}

// A model named by the caller (the /model picker) is used for the grade and the
// answer, and no model list is fetched to find one.
func TestAnswerLoopUsesTheNamedModelWithoutListing(t *testing.T) {
	var mu sync.Mutex
	var listed int
	var models []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/models") {
			mu.Lock()
			listed++
			mu.Unlock()
			w.Write([]byte(`{"data":[{"id":"listed"}]}`))
			return
		}
		var body struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		models = append(models, body.Model)
		mu.Unlock()
		if body.Stream {
			fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n")
			return
		}
		fmt.Fprint(w, `{"choices":[{"index":0,"message":{"role":"assistant","content":"{\"sufficient\":true}"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "")
	t.Setenv("OMLX_API_KEY", "test-key")
	rc := fakeSearcher{[]retrieval.Result{chunk("wstg", "a.md", "s", "text")}}
	if _, _, _, _, _, err := AnswerLoop(context.Background(), rc, answerCfg(1), "q", AnswerOpts{Model: "picked"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if listed != 0 {
		t.Errorf("listed the models %d times with a model named", listed)
	}
	if len(models) != 2 || models[0] != "picked" || models[1] != "picked" {
		t.Errorf("models used = %v, want picked for the grade and the answer", models)
	}
}

// bodyLLM is recordingLLM that keeps each chat call's raw JSON body, so a test
// can check exactly which fields reached the server.
func bodyLLM(t *testing.T) (*httptest.Server, func() []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var seen []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		seen = append(seen, body)
		mu.Unlock()
		if body["stream"] == true {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok [1]\"}}]}\n\ndata: [DONE]\n\n")
			return
		}
		fmt.Fprint(w, `{"choices":[{"index":0,"message":{"role":"assistant","content":"{\"sufficient\":true,\"rewrite\":\"\",\"use_web\":false}"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]any(nil), seen...)
	}
}

// samplingFields is every sampling or cap field a chat body may carry.
var samplingFields = []string{"temperature", "top_p", "top_k", "presence_penalty", "max_tokens", "max_completion_tokens"}

// sampled returns the sampling and cap fields present in body.
func sampled(body map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range samplingFields {
		if v, ok := body[k]; ok {
			out[k] = v
		}
	}
	return out
}

// runAnswerForBodies runs one answer turn against bodyLLM with cfg and returns
// the sampling fields of the grade call and of the answer call.
func runAnswerForBodies(t *testing.T, cfg ragconfig.Config) (grade, answer map[string]any) {
	t.Helper()
	isolateUserDirs(t)
	useDeadServices(t)
	srv, seen := bodyLLM(t)
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "")
	rc := fakeSearcher{[]retrieval.Result{chunk("wstg", "a.md", "s", "text")}}
	if _, _, _, _, _, err := AnswerLoop(context.Background(), rc, cfg, "q", AnswerOpts{}); err != nil {
		t.Fatal(err)
	}
	for _, b := range seen() {
		if b["stream"] == true {
			answer = sampled(b)
		} else {
			grade = sampled(b)
		}
	}
	if grade == nil || answer == nil {
		t.Fatalf("calls seen: %v, want a grade and an answer", seen())
	}
	t.Logf("grade body: %v", grade)
	t.Logf("answer body: %v", answer)
	return grade, answer
}

// The answer call carries the configured sampling settings and the answer cap
// as top-level fields. The grade call carries temperature 0 and its own cap
// and no other sampling field, so grading stays deterministic.
func TestAnswerLoopSendsTheSamplingSettings(t *testing.T) {
	cfg := answerCfg(1)
	cfg.SynthTemperature, cfg.SynthTopP, cfg.SynthTopK, cfg.SynthPresencePenalty = 0.7, 0.95, 64, 0.5
	cfg.GradeTemperature, cfg.AnswerMaxTokens, cfg.GradeMaxTokens = 0, 321, 45
	grade, answer := runAnswerForBodies(t, cfg)

	want := map[string]any{"temperature": 0.7, "top_p": 0.95, "top_k": 64.0, "presence_penalty": 0.5, "max_completion_tokens": 321.0}
	if !reflect.DeepEqual(answer, want) {
		t.Errorf("answer body sampling = %v, want %v", answer, want)
	}
	wantGrade := map[string]any{"temperature": 0.0, "max_completion_tokens": 45.0}
	if !reflect.DeepEqual(grade, wantGrade) {
		t.Errorf("grade body sampling = %v, want %v", grade, wantGrade)
	}
}

// A zero top_p, top_k, or presence_penalty means the server default, so the
// field is left out. A zero temperature is a real value and is still sent.
func TestAnswerLoopOmitsZeroSampling(t *testing.T) {
	cfg := answerCfg(1)
	cfg.SynthTemperature, cfg.SynthTopP, cfg.SynthTopK, cfg.SynthPresencePenalty = 0, 0, 0, 0
	cfg.AnswerMaxTokens = 321
	_, answer := runAnswerForBodies(t, cfg)
	want := map[string]any{"temperature": 0.0, "max_completion_tokens": 321.0}
	if !reflect.DeepEqual(answer, want) {
		t.Errorf("answer body sampling = %v, want %v", answer, want)
	}
}

func TestAnswerLoopNoLocalSkipsSearch(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":false,"rewrite":"","use_web":true}`}, "web answer [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	authorizeWebTest(t)
	t.Setenv("TAVILY_SETUP_TOKEN", "tvly-test")

	oldWeb := webSearch
	webSearch = func(_ context.Context, _, _ string, _ int, _ []string) ([]retrieval.Result, error) {
		return []retrieval.Result{chunk(webSource, "https://x/y", "T", "web text")}, nil
	}
	defer func() { webSearch = oldWeb }()

	rs := &recSearcher{results: []retrieval.Result{chunk("wstg", "a.md", "s", "local")}}
	_, _, usedWeb, _, _, err := AnswerLoop(context.Background(), rs, answerCfg(2), "q", AnswerOpts{NoLocal: true})
	if err != nil {
		t.Fatal(err)
	}
	if rs.query != "" {
		t.Errorf("NoLocal must not call Search, got query %q", rs.query)
	}
	if !usedWeb {
		t.Error("NoLocal grounding should have used web")
	}
}

func TestAnswerLoopNoLocalNoWebIsNoResults(t *testing.T) {
	isolateUserDirs(t)
	t.Setenv(webProviderEnv, "off")
	srv := fakeLLM(t, []string{`{"sufficient":false,"rewrite":"","use_web":true}`}, "")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "") // no web configured

	rs := &recSearcher{results: []retrieval.Result{chunk("wstg", "a.md", "s", "local")}}
	_, _, _, _, _, err := AnswerLoop(context.Background(), rs, answerCfg(2), "q", AnswerOpts{NoLocal: true})
	if !errors.Is(err, ErrNoResults) {
		t.Errorf("err = %v, want ErrNoResults", err)
	}
	if rs.query != "" {
		t.Errorf("NoLocal must not call Search, got query %q", rs.query)
	}
}

func TestAnswerLoopCVEUsesPocDomains(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":false,"rewrite":"","use_web":true}`}, "poc answer [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	authorizeWebTest(t)
	t.Setenv("TAVILY_SETUP_TOKEN", "tvly-test")
	oldNVD := nvdLookup
	nvdLookup = func(_ context.Context, id string) ([]retrieval.Result, error) {
		return []retrieval.Result{chunk(nvdSource, "https://nvd.nist.gov/vuln/detail/"+id, id+" summary", "NVD facts")}, nil
	}
	defer func() { nvdLookup = oldNVD }()

	var gotDomains []string
	var gotQuery string
	oldWeb := webSearch
	webSearch = func(_ context.Context, _, query string, _ int, domains []string) ([]retrieval.Result, error) {
		gotDomains, gotQuery = domains, query
		return []retrieval.Result{chunk(webSource, "https://github.com/nomi-sec/PoC-in-GitHub", "CVE-2024-1234", "poc")}, nil
	}
	defer func() { webSearch = oldWeb }()

	cfg := answerCfg(2)
	cfg.PocDomains = []string{"github.com", "nvd.nist.gov"}
	rs := &recSearcher{}
	_, _, _, _, _, err := AnswerLoop(context.Background(), rs, cfg, "CVE-2024-1234 exploit", AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotDomains) == 0 || gotDomains[0] != "github.com" {
		t.Errorf("web domains = %v, want PocDomains (github.com first)", gotDomains)
	}
	if !strings.Contains(gotQuery, "nomi-sec/PoC-in-GitHub") {
		t.Errorf("web query = %q, want PoC-repo hint", gotQuery)
	}
}

func TestAnswerLoopCVEAddsNVDAndPoCSearchEvenWhenLocalIsSufficient(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":true,"rewrite":"","use_web":false}`}, "CVE answer [1] [2]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	authorizeWebTest(t)
	t.Setenv("TAVILY_SETUP_TOKEN", "tvly-test")

	oldNVD, oldWeb := nvdLookup, webSearch
	defer func() { nvdLookup, webSearch = oldNVD, oldWeb }()
	nvdCalls, webCalls := 0, 0
	nvdLookup = func(_ context.Context, id string) ([]retrieval.Result, error) {
		nvdCalls++
		if id != "CVE-2021-44228" {
			t.Errorf("NVD id = %q", id)
		}
		return []retrieval.Result{chunk(nvdSource, "https://nvd.nist.gov/vuln/detail/"+id, id+" summary", "NVD facts")}, nil
	}
	webSearch = func(_ context.Context, _, query string, _ int, domains []string) ([]retrieval.Result, error) {
		webCalls++
		if !strings.Contains(query, "CVE-2021-44228") || len(domains) == 0 {
			t.Errorf("PoC query = %q domains = %v", query, domains)
		}
		return []retrieval.Result{chunk(webSource, "https://exploit-db.com/exploits/1", "CVE-2021-44228 PoC", "unverified lead")}, nil
	}
	cfg := answerCfg(2)
	rs := &recSearcher{results: []retrieval.Result{chunk("kb", "local.md", "local", "local facts")}}
	var persona string
	answer, cits, usedWeb, results, _, err := AnswerLoop(context.Background(), rs, cfg, "Explain cve-2021-44228 and give a test playbook", AnswerOpts{Persona: func(d string) { persona = d }})
	if err != nil {
		t.Fatal(err)
	}
	if nvdCalls != 1 || webCalls != 1 || !usedWeb {
		t.Errorf("NVD calls = %d, web calls = %d, usedWeb = %v", nvdCalls, webCalls, usedWeb)
	}
	if len(results) < 3 || results[0].Payload.Source != nvdSource {
		t.Errorf("results do not prioritize NVD: %+v", results)
	}
	if persona != "cve" {
		t.Errorf("persona = %q, want cve", persona)
	}
	if !strings.HasPrefix(answer, "NVD record [1]\nNVD facts\n\n") {
		t.Errorf("answer omitted code-owned NVD facts: %q", answer)
	}
	if len(cits) < 2 || !cits[0].Untrusted || !cits[1].Untrusted {
		t.Errorf("external citations should be untrusted: %+v", cits)
	}
}

func TestAnswerLoopCVEHonorsWebOff(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":true,"rewrite":"","use_web":false}`}, "local answer [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	authorizeWebTest(t)
	oldNVD := nvdLookup
	defer func() { nvdLookup = oldNVD }()
	nvdLookup = func(context.Context, string) ([]retrieval.Result, error) {
		t.Fatal("NVD called when web is off")
		return nil, nil
	}
	_, _, usedWeb, _, _, err := AnswerLoop(context.Background(), &recSearcher{results: []retrieval.Result{chunk("kb", "a", "s", "text")}}, answerCfg(1), "CVE-2021-44228", AnswerOpts{NoWeb: true})
	if err != nil || usedWeb {
		t.Fatalf("web-off answer: usedWeb=%v err=%v", usedWeb, err)
	}
}

func TestCVEResearchKeepsOnlyMatchingPoCLeads(t *testing.T) {
	oldNVD, oldWeb := nvdLookup, webSearch
	defer func() { nvdLookup, webSearch = oldNVD, oldWeb }()
	nvdLookup = func(_ context.Context, id string) ([]retrieval.Result, error) {
		return []retrieval.Result{chunk(nvdSource, "https://nvd.nist.gov/vuln/detail/"+id, id+" summary", "NVD facts")}, nil
	}
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		return []retrieval.Result{
			chunk(webSource, "https://github.com/author/CVE-2021-44228", "PoC", "matching lead"),
			chunk(webSource, "https://exploit-db.com/exploits/1", "Unrelated exploit", "CVE-2020-1234"),
			chunk(webSource, "https://github.com/topics/cve-2021-44228", "CVE-2021-44228", "repository directory"),
			chunk(webSource, "https://sploitus.com/exploit?id=1", "exploit-availability-check", "mentions CVE-2021-44228 among many others"),
		}, nil
	}
	results, err := cveResearch(context.Background(), answerCfg(1), "CVE-2021-44228", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[1].Payload.Path != "https://github.com/author/CVE-2021-44228" {
		t.Fatalf("CVE research results = %+v", results)
	}
}

func TestAnswerLoopWebOnlyCVEUsesNVDAndOnePoCSearch(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":true,"rewrite":"","use_web":false}`}, "playbook [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	authorizeWebTest(t)
	t.Setenv("TAVILY_SETUP_TOKEN", "tvly-test")
	oldNVD, oldWeb := nvdLookup, webSearch
	defer func() { nvdLookup, webSearch = oldNVD, oldWeb }()
	nvdLookup = func(_ context.Context, id string) ([]retrieval.Result, error) {
		return []retrieval.Result{chunk(nvdSource, "https://nvd.nist.gov/vuln/detail/"+id, id+" summary", "NVD\x1b[31m facts")}, nil
	}
	webCalls := 0
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		webCalls++
		return nil, nil
	}
	answer, _, usedWeb, results, _, err := AnswerLoop(context.Background(), nil, answerCfg(1), "CVE-2021-44228", AnswerOpts{WebOnly: true, NoLocal: true})
	if err != nil || !usedWeb || webCalls != 1 || len(results) != 1 {
		t.Fatalf("web-only CVE: err=%v usedWeb=%v webCalls=%d results=%d", err, usedWeb, webCalls, len(results))
	}
	if !strings.Contains(answer, "NVD facts") || strings.Contains(answer, "\x1b") {
		t.Errorf("NVD prelude was not sanitized: %q", answer)
	}
}

func TestAnswerLoopCVEKeepsNVDFirstAfterLocalRewrite(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":false,"rewrite":"log4j version","use_web":false}`}, "answer [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	authorizeWebTest(t)
	t.Setenv("TAVILY_SETUP_TOKEN", "tvly-test")
	oldNVD, oldWeb := nvdLookup, webSearch
	defer func() { nvdLookup, webSearch = oldNVD, oldWeb }()
	nvdLookup = func(_ context.Context, id string) ([]retrieval.Result, error) {
		return []retrieval.Result{
			chunk(nvdSource, "https://nvd.nist.gov/vuln/detail/"+id, id+" summary", "NVD summary"),
			chunk(nvdSource, "https://nvd.nist.gov/vuln/detail/"+id, id+" details", "NVD details"),
		}, nil
	}
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) { return nil, nil }
	local := []retrieval.Result{
		chunk("skills", "pentesting-web/1", "local", "one"), chunk("skills", "pentesting-web/2", "local", "two"),
		chunk("skills", "pentesting-web/3", "local", "three"), chunk("skills", "pentesting-web/4", "local", "four"), chunk("skills", "pentesting-web/5", "local", "five"),
	}
	cfg := answerCfg(2)
	cfg.AnswerMaxChunks = 6
	answer, _, _, results, _, err := AnswerLoop(context.Background(), &recSearcher{results: local}, cfg, "CVE-2021-44228", AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) < 2 || results[0].Payload.Source != nvdSource || results[1].Payload.Source != nvdSource {
		t.Fatalf("NVD evidence lost priority after rewrite: %+v", results)
	}
	if !strings.HasPrefix(answer, "NVD record [1]\nNVD summary") {
		t.Errorf("NVD prelude missing after rewrite: %q", answer)
	}
}

func TestAnswerLoopNonCVEUsesReputableDomains(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":false,"rewrite":"","use_web":true}`}, "answer [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	authorizeWebTest(t)
	t.Setenv("TAVILY_SETUP_TOKEN", "tvly-test")

	var gotDomains []string
	oldWeb := webSearch
	webSearch = func(_ context.Context, _, _ string, _ int, domains []string) ([]retrieval.Result, error) {
		gotDomains = domains
		return []retrieval.Result{chunk(webSource, "https://owasp.org/x", "T", "t")}, nil
	}
	defer func() { webSearch = oldWeb }()

	cfg := answerCfg(2)
	cfg.ReputableDomains = []string{"owasp.org"}
	cfg.PocDomains = []string{"github.com"}
	rs := &recSearcher{results: []retrieval.Result{chunk("wstg", "a.md", "s", "local")}}
	_, _, _, _, _, err := AnswerLoop(context.Background(), rs, cfg, "how does clickjacking work", AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotDomains) != 1 || gotDomains[0] != "owasp.org" {
		t.Errorf("web domains = %v, want ReputableDomains", gotDomains)
	}
}

func TestRetrievalQueryNoHistoryReturnsQuestion(t *testing.T) {
	if got := retrievalQuery(nil, "what is xss?"); got != "what is xss?" {
		t.Errorf("retrievalQuery(nil) = %q, want the question unchanged", got)
	}
}

func TestRetrievalQueryFoldsInPriorUserQuestion(t *testing.T) {
	history := []priorTurn{
		{Role: "human", Content: "how do I escalate privileges on Linux?"},
		{Role: "ai", Content: "use sudo misconfigurations, SUID binaries, and kernel exploits"},
	}
	got := retrievalQuery(history, "and for Windows?")
	if !strings.Contains(got, "and for Windows?") {
		t.Errorf("query dropped the current question: %q", got)
	}
	if !strings.Contains(got, "Linux") {
		t.Errorf("query is not history-aware; the prior topic is missing: %q", got)
	}
}

func TestRetrievalQueryIgnoresPriorAIAnswerText(t *testing.T) {
	history := []priorTurn{
		{Role: "human", Content: "first question"},
		{Role: "ai", Content: "an answer mentioning ZZUNIQUEMARKER that must not steer retrieval"},
	}
	got := retrievalQuery(history, "follow up")
	if strings.Contains(got, "ZZUNIQUEMARKER") {
		t.Errorf("AI answer text leaked into the retrieval query: %q", got)
	}
	if !strings.Contains(got, "first question") {
		t.Errorf("prior user question missing from the query: %q", got)
	}
}

func TestRetrievalQueryBoundsPriorContext(t *testing.T) {
	long := strings.Repeat("x", 600)
	got := retrievalQuery([]priorTurn{{Role: "human", Content: long}}, "q")
	if strings.Contains(got, strings.Repeat("x", 500)) {
		t.Errorf("prior question was not bounded; query carries an unbounded prefix (len %d)", len(got))
	}
	if !strings.Contains(got, "q") {
		t.Errorf("current question missing after bounding: %q", got)
	}
}

func TestBoundTurnsKeepsAllUnderBudget(t *testing.T) {
	in := []priorTurn{{Role: "human", Content: "a"}, {Role: "ai", Content: "b"}, {Role: "human", Content: "c"}}
	got := boundTurns(in, 100)
	if !reflect.DeepEqual(got, in) {
		t.Errorf("boundTurns under budget = %v, want all turns unchanged", got)
	}
}

func TestBoundTurnsDropsOldestOverBudget(t *testing.T) {
	in := []priorTurn{
		{Role: "human", Content: strings.Repeat("o", 50)}, // oldest
		{Role: "ai", Content: strings.Repeat("m", 50)},
		{Role: "human", Content: strings.Repeat("n", 50)}, // newest
	}
	// Budget fits the 2 newest (100) but not all 3 (150).
	got := boundTurns(in, 120)
	if !reflect.DeepEqual(got, in[1:]) {
		t.Errorf("boundTurns over budget kept %d turns, want the 2 newest in order", len(got))
	}
}

func TestBoundTurnsKeepsNewestEvenIfOverBudget(t *testing.T) {
	in := []priorTurn{{Role: "human", Content: strings.Repeat("x", 500)}}
	got := boundTurns(in, 100)
	if len(got) != 1 {
		t.Errorf("boundTurns dropped the only (over-budget) turn; want it kept so some memory survives")
	}
}

func TestBoundTurnsEmpty(t *testing.T) {
	if got := boundTurns(nil, 100); len(got) != 0 {
		t.Errorf("boundTurns(nil) = %v, want empty", got)
	}
}

func TestAnswerLoopFiresPersonaForDomain(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":true,"rewrite":"","use_web":false}`}, "grounded [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "k")
	t.Setenv("TAVILY_SETUP_TOKEN", "")
	rc := fakeSearcher{[]retrieval.Result{chunk("skills", "attacking-active-directory/SKILL.md", "s", "kerberos ticket")}}
	var got string
	_, _, _, _, _, err := AnswerLoop(context.Background(), rc, answerCfg(1), "how does kerberoasting work", AnswerOpts{
		Persona: func(dom string) { got = dom },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "ad" {
		t.Errorf("persona cue domain = %q, want \"ad\"", got)
	}
}

func authorizeWebTest(t *testing.T) {
	t.Helper()
	isolateUserDirs(t)
	t.Setenv(webProviderEnv, "auto")
	p := defaultPrefs()
	p.Web = true
	if err := savePrefs(p); err != nil {
		t.Fatal(err)
	}
}

func TestAnswerLoopHonorsWebRequestBeforeSufficiency(t *testing.T) {
	authorizeWebTest(t)
	t.Setenv("TAVILY_API_KEY", "test-key")
	srv := fakeLLM(t, []string{`{"sufficient":true,"use_web":true}`, `{"sufficient":true,"use_web":false}`}, "Reasoned answer using local and current evidence [1] [2].")
	defer srv.Close()
	t.Setenv("OMLX_BASE_URL", srv.URL+"/v1")
	original := webSearch
	calls := 0
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		calls++
		return []retrieval.Result{chunk(webSource, "https://example.com/current", "Current", "current evidence")}, nil
	}
	defer func() { webSearch = original }()
	local := fakeSearcher{[]retrieval.Result{chunk("local", "local.md", "Local", "local evidence")}}
	answer, citations, used, results, _, err := AnswerLoop(context.Background(), local, answerCfg(2), "current techniques", AnswerOpts{})
	if err != nil || calls != 1 || !used || len(results) != 2 || len(citations) != 2 || !strings.Contains(answer, "Reasoned answer") {
		t.Fatalf("answer %q citations %+v results %+v calls %d used %v err %v", answer, citations, results, calls, used, err)
	}
}

func TestAnswerLoopKeepsWebEvidenceAfterLocalRewrite(t *testing.T) {
	authorizeWebTest(t)
	t.Setenv("TAVILY_API_KEY", "test-key")
	srv := fakeLLM(t, []string{`{"sufficient":false,"use_web":true}`, `{"sufficient":false,"rewrite":"refined","use_web":false}`}, "Reasoned answer [1] [2].")
	defer srv.Close()
	t.Setenv("OMLX_BASE_URL", srv.URL+"/v1")
	original := webSearch
	calls := 0
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		calls++
		return []retrieval.Result{chunk(webSource, "https://example.com/current", "Current", "current evidence")}, nil
	}
	defer func() { webSearch = original }()
	local := fakeSearcher{[]retrieval.Result{chunk("local", "local.md", "Local", "local evidence")}}
	_, _, used, results, _, err := AnswerLoop(context.Background(), local, answerCfg(2), "techniques", AnswerOpts{})
	if err != nil || !used || calls != 1 || len(results) != 2 || results[1].Payload.Source != webSource {
		t.Fatalf("results %+v used %v calls %d err %v", results, used, calls, err)
	}
}

func TestSynthesisReceivesLocalAndWebEvidence(t *testing.T) {
	authorizeWebTest(t)
	t.Setenv("TAVILY_API_KEY", "test-key")
	var mu sync.Mutex
	synthesis := ""
	grades := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var request struct {
			Stream bool `json:"stream"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if request.Stream {
			synthesis = string(body)
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Reasoned synthesis [1] [2].\"}}]}\n\ndata: [DONE]\n\n")
			return
		}
		grade := `{"sufficient":true,"use_web":true}`
		if grades > 0 {
			grade = `{"sufficient":true,"use_web":false}`
		}
		grades++
		text, _ := json.Marshal(grade)
		fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","content":%s}}]}`, text)
	}))
	defer srv.Close()
	t.Setenv("OMLX_BASE_URL", srv.URL+"/v1")
	original := webSearch
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		return []retrieval.Result{chunk(webSource, "https://example.com/current", "Current", "CURRENT_WEB_EVIDENCE")}, nil
	}
	defer func() { webSearch = original }()
	answer, _, usedWeb, _, _, err := AnswerLoop(context.Background(), fakeSearcher{[]retrieval.Result{chunk("local", "local.md", "Local", "LOCAL_CORPUS_EVIDENCE")}}, answerCfg(2), "current testing approaches", AnswerOpts{})
	mu.Lock()
	defer mu.Unlock()
	if err != nil || !usedWeb || answer != "Reasoned synthesis [1] [2]." {
		t.Fatalf("answer %q web %v err %v", answer, usedWeb, err)
	}
	for _, evidence := range []string{"LOCAL_CORPUS_EVIDENCE", "CURRENT_WEB_EVIDENCE", "Synthesize the sources into a clear"} {
		if !strings.Contains(synthesis, evidence) {
			t.Errorf("synthesis request omitted %q", evidence)
		}
	}
}
