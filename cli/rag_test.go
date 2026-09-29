package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func TestAnswerLoopStageOrderWebAndRewrite(t *testing.T) {
	srv := fakeLLM(t, []string{
		`{"sufficient":false,"rewrite":"better","use_web":true}`,
		`{"sufficient":false,"rewrite":"better2","use_web":false}`,
	}, "ok [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
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
