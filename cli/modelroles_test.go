package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

// httpClientError returns the error net/http hands back for req without any
// network traffic: the request fails before a connection is attempted.
func httpClientError(t *testing.T, req *http.Request) error {
	t.Helper()
	_, err := http.DefaultClient.Do(req)
	if err == nil {
		t.Fatal("expected a client error")
	}
	return err
}

func TestFailoverEligibleRefusesWhatIsNotTheModelsFault(t *testing.T) {
	_, badURLErr := http.NewRequest(http.MethodGet, "http://127.0.0.1/%zz", nil)
	if badURLErr == nil {
		t.Fatal("expected a URL parse error")
	}
	ftpReq, err := http.NewRequest(http.MethodGet, "ftp://127.0.0.1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	schemeErr := httpClientError(t, ftpReq)
	cases := []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"cancellation", context.Canceled},
		{"wrapped cancellation", fmt.Errorf("tool loop: %w", context.Canceled)},
		{"plain error", errors.New("scope refused: target outside scope")},
		{"client status", errors.New("API returned unexpected status code: 404: Model 'x' not found")},
		{"bad request without a context message", errors.New("API returned unexpected status code: 400: invalid 'temperature'")},
		{"cancellation inside a url error", &url.Error{Op: "Post", URL: "http://127.0.0.1:8000/v1/chat/completions", Err: context.Canceled}},
		{"cancellation inside a dial error", &url.Error{Op: "Post", URL: "http://127.0.0.1:8000/v1/chat/completions", Err: &net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled}}},
		{"malformed url", badURLErr},
		{"unsupported scheme", schemeErr},
		{"url error around a plain error", &url.Error{Op: "Post", URL: "http://127.0.0.1:8000/v1/chat/completions", Err: errors.New("plain app error")}},
		{"certificate verification failure", &url.Error{Op: "Post", URL: "https://127.0.0.1:8000/v1/chat/completions", Err: x509.UnknownAuthorityError{}}},
	}
	for _, c := range cases {
		if failoverEligible(c.err) {
			t.Errorf("%s: eligible, want not eligible", c.name)
		}
	}
}

func TestFailoverEligibleAcceptsAModelThatCouldNotAnswer(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"connection refused", fmt.Errorf("dial: %w", syscall.ECONNREFUSED)},
		{"deadline", fmt.Errorf("call: %w", context.DeadlineExceeded)},
		{"unreachable", &llmUnreachableError{base: "http://127.0.0.1:8000/v1", err: syscall.ECONNREFUSED}},
		{"server error", errors.New("API returned unexpected status code: 503: upstream unavailable")},
		{"context window", errors.New("API returned unexpected status code: 400: This model's maximum context length is 4096 tokens")},
		// The pinned client keeps only a body's message and type and drops its
		// code field, so only the message text is ever matched.
		{"context window by message", errors.New("API returned unexpected status code: 400: request failed with context_length_exceeded for this model")},
		{"net op error", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("network is unreachable")}},
		{"dns error", &net.DNSError{Err: "no such host", Name: "model.invalid"}},
	}
	for _, c := range cases {
		if !failoverEligible(c.err) {
			t.Errorf("%s: not eligible, want eligible", c.name)
		}
	}
}

// TestFailoverEligibleOnARealServerError drives a real client against a real
// 503 so the status this code reads out of the client's error text is the text
// the pinned client actually produces. A format change upstream fails here
// instead of silently turning failover off.
func TestFailoverEligibleOnARealServerError(t *testing.T) {
	var hit atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"error":{"message":"upstream unavailable","type":"server_error"}}`)
	}))
	defer srv.Close()
	t.Setenv("OMLX_BASE_URL", srv.URL+"/v1")
	l, err := newOMLX(kbTestCfg(), "any-model")
	if err != nil {
		t.Fatalf("newOMLX: %v", err)
	}
	_, callErr := l.GenerateContent(context.Background(), []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeHuman, "hi"),
	}, llms.WithMaxTokens(4))
	if callErr == nil {
		t.Fatal("expected an error from a 503")
	}
	t.Logf("observed 503 error: %q", callErr.Error())
	if !hit.Load() {
		t.Fatal("the fixture server was never reached")
	}
	if !strings.Contains(callErr.Error(), "503") {
		t.Fatalf("error does not name the 503: %v", callErr)
	}
	if !failoverEligible(callErr) {
		t.Errorf("a 503 from a real client is not eligible: %v", callErr)
	}
}

// TestFailoverNotEligibleOnARealUnknownModel is the same path for a 404, which
// is the request's own fault and must not advance the chain.
func TestFailoverNotEligibleOnARealUnknownModel(t *testing.T) {
	var hit atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":{"message":"Model 'nope' not found","type":"not_found_error"}}`)
	}))
	defer srv.Close()
	t.Setenv("OMLX_BASE_URL", srv.URL+"/v1")
	l, err := newOMLX(kbTestCfg(), "nope")
	if err != nil {
		t.Fatalf("newOMLX: %v", err)
	}
	_, callErr := l.GenerateContent(context.Background(), []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeHuman, "hi"),
	}, llms.WithMaxTokens(4))
	if callErr == nil {
		t.Fatal("expected an error from a 404")
	}
	t.Logf("observed 404 error: %q", callErr.Error())
	if !hit.Load() {
		t.Fatal("the fixture server was never reached")
	}
	if !strings.Contains(callErr.Error(), "404") {
		t.Fatalf("error does not name the 404: %v", callErr)
	}
	if failoverEligible(callErr) {
		t.Errorf("a 404 from a real client is eligible: %v", callErr)
	}
}

// chainFake answers a fixed script: err[i] for call i, then a reply naming the
// model it was built for.
type chainFake struct {
	id    string
	errs  []error
	calls int
	log   *[]string
	// stream is delivered to the call's streaming function, when one is set,
	// before the scripted result.
	stream string
	// gotOpts and gotStream describe the options the last call received.
	gotOpts   int
	gotStream bool
}

func (f *chainFake) GenerateContent(ctx context.Context, msgs []llms.MessageContent, opts ...llms.CallOption) (*llms.ContentResponse, error) {
	i := f.calls
	f.calls++
	*f.log = append(*f.log, f.id)
	var applied llms.CallOptions
	for _, o := range opts {
		o(&applied)
	}
	f.gotOpts = len(opts)
	f.gotStream = applied.StreamingFunc != nil
	if f.stream != "" && applied.StreamingFunc != nil {
		if err := applied.StreamingFunc(ctx, []byte(f.stream)); err != nil {
			return nil, err
		}
	}
	if i < len(f.errs) && f.errs[i] != nil {
		return nil, f.errs[i]
	}
	return &llms.ContentResponse{Choices: []*llms.ContentChoice{{Content: "answered by " + f.id}}}, nil
}

func TestRoleChainsPutTheConfiguredModelFirstAndTheDefaultBehind(t *testing.T) {
	cfg := kbTestCfg()
	cfg.DefaultModel = "fallback"
	cfg.RouterModel = "small"
	cfg.AssessmentModel = "big"
	t.Setenv("OMLX_MODEL", "fallback") // keeps resolveModel off the network
	router, assessment := roleChains(cfg, "")
	if got, want := router, []string{"small", "fallback"}; !slices.Equal(got, want) {
		t.Errorf("router chain: got %v want %v", got, want)
	}
	if got, want := assessment, []string{"big", "fallback"}; !slices.Equal(got, want) {
		t.Errorf("assessment chain: got %v want %v", got, want)
	}
}

func TestRoleChainsUnconfiguredIsOneModel(t *testing.T) {
	cfg := kbTestCfg()
	cfg.DefaultModel = "only"
	cfg.RouterModel, cfg.AssessmentModel = "", ""
	t.Setenv("OMLX_MODEL", "only")
	router, assessment := roleChains(cfg, "")
	if got, want := router, []string{"only"}; !slices.Equal(got, want) {
		t.Errorf("router chain: got %v want %v", got, want)
	}
	if got, want := assessment, []string{"only"}; !slices.Equal(got, want) {
		t.Errorf("assessment chain: got %v want %v", got, want)
	}
}

// TestRoleChainsHonorAnExplicitPick is a correctness control, not a nicety: a
// turn reports the model that answered it, so a named model must not be
// quietly replaced by another one.
func TestRoleChainsHonorAnExplicitPick(t *testing.T) {
	cfg := kbTestCfg()
	cfg.DefaultModel = "fallback"
	cfg.RouterModel = "small"
	cfg.AssessmentModel = "big"
	t.Setenv("OMLX_MODEL", "fallback")
	router, assessment := roleChains(cfg, "  picked  ")
	if got, want := router, []string{"picked"}; !slices.Equal(got, want) {
		t.Errorf("router chain: got %v want %v", got, want)
	}
	if got, want := assessment, []string{"picked"}; !slices.Equal(got, want) {
		t.Errorf("assessment chain: got %v want %v", got, want)
	}
}

func TestRoleChainsDoNotRepeatOneModel(t *testing.T) {
	cfg := kbTestCfg()
	cfg.DefaultModel = "same"
	cfg.RouterModel = "same"
	cfg.AssessmentModel = ""
	t.Setenv("OMLX_MODEL", "same")
	router, _ := roleChains(cfg, "")
	if got, want := router, []string{"same"}; !slices.Equal(got, want) {
		t.Errorf("router chain: got %v want %v", got, want)
	}
}

func TestModelChainAdvancesOnlyWhenTheModelCouldNotAnswer(t *testing.T) {
	for _, c := range []struct {
		name      string
		first     error
		wantOrder []string
		wantErr   bool
	}{
		{"eligible", errors.New("API returned unexpected status code: 503: down"), []string{"a", "b"}, false},
		{"not eligible", errors.New("API returned unexpected status code: 404: no such model"), []string{"a"}, true},
		{"cancelled", context.Canceled, []string{"a"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var log []string
			chain := &modelChain{
				ids: []string{"a", "b"},
				clients: []toolLoopModel{
					&chainFake{id: "a", errs: []error{c.first}, log: &log},
					&chainFake{id: "b", log: &log},
				},
			}
			resp, err := chain.GenerateContent(context.Background(), nil)
			if c.wantErr {
				if err == nil {
					t.Fatal("want an error")
				}
			} else {
				if err != nil {
					t.Fatalf("GenerateContent: %v", err)
				}
				if resp.Choices[0].Content != "answered by b" {
					t.Errorf("answer: got %q", resp.Choices[0].Content)
				}
			}
			if !slices.Equal(log, c.wantOrder) {
				t.Errorf("models called: got %v want %v", log, c.wantOrder)
			}
		})
	}
}

func TestModelChainReturnsTheLastErrorWhenEveryModelFails(t *testing.T) {
	var log []string
	down := errors.New("API returned unexpected status code: 503: down")
	last := errors.New("API returned unexpected status code: 502: also down")
	chain := &modelChain{
		ids: []string{"a", "b"},
		clients: []toolLoopModel{
			&chainFake{id: "a", errs: []error{down}, log: &log},
			&chainFake{id: "b", errs: []error{last}, log: &log},
		},
	}
	if _, err := chain.GenerateContent(context.Background(), nil); err != last {
		t.Errorf("error: got %v want %v", err, last)
	}
	if !slices.Equal(log, []string{"a", "b"}) {
		t.Errorf("models called: got %v", log)
	}
}

func TestModelChainPrimaryNamesTheModelTheTurnReports(t *testing.T) {
	chain := &modelChain{ids: []string{"big", "fallback"}}
	if got := chain.primary(); got != "big" {
		t.Errorf("primary: got %q want %q", got, "big")
	}
	if got := (&modelChain{}).primary(); got != "" {
		t.Errorf("empty chain primary: got %q want empty", got)
	}
}

func TestModelChainAnsweredNamesTheModelThatAnswered(t *testing.T) {
	down := errors.New("API returned unexpected status code: 503: down")
	var log []string
	failover := &modelChain{
		ids: []string{"a", "b"},
		clients: []toolLoopModel{
			&chainFake{id: "a", errs: []error{down}, log: &log},
			&chainFake{id: "b", log: &log},
		},
	}
	if got := failover.answered(); got != "a" {
		t.Errorf("before any call: got %q want %q", got, "a")
	}
	if _, err := failover.GenerateContent(context.Background(), nil); err != nil {
		t.Fatalf("GenerateContent: %v", err)
	}
	if got := failover.answered(); got != "b" {
		t.Errorf("after failover: got %q want %q", got, "b")
	}
	if got := failover.primary(); got != "a" {
		t.Errorf("primary after failover: got %q want %q", got, "a")
	}

	first := &modelChain{
		ids:     []string{"a", "b"},
		clients: []toolLoopModel{&chainFake{id: "a", log: &log}, &chainFake{id: "b", log: &log}},
	}
	if _, err := first.GenerateContent(context.Background(), nil); err != nil {
		t.Fatalf("GenerateContent: %v", err)
	}
	if got := first.answered(); got != "a" {
		t.Errorf("first model answered: got %q want %q", got, "a")
	}

	out := &modelChain{ids: []string{"a", "b"}}
	out.markAnswered(7)
	if got := out.answered(); got != "a" {
		t.Errorf("out of range index: got %q want the primary %q", got, "a")
	}
	if got := (&modelChain{}).answered(); got != "" {
		t.Errorf("empty chain: got %q want empty", got)
	}
}

func TestModelChainFirstSuccessDoesNotCallTheSecondModel(t *testing.T) {
	var log []string
	second := &chainFake{id: "b", log: &log}
	chain := &modelChain{
		ids:     []string{"a", "b"},
		clients: []toolLoopModel{&chainFake{id: "a", log: &log}, second},
	}
	if _, err := chain.GenerateContent(context.Background(), nil); err != nil {
		t.Fatalf("GenerateContent: %v", err)
	}
	if second.calls != 0 || !slices.Equal(log, []string{"a"}) {
		t.Errorf("models called: got %v, second model calls %d", log, second.calls)
	}
}

// streamedFailureChain returns a two-model chain whose first model fails with
// an eligible error after streaming first (when non-empty), the two fakes, the
// buffer the caller's streaming function appends to, and the call options that
// carry that function.
func streamedFailureChain(first string) (*modelChain, *chainFake, *chainFake, *[]byte, []llms.CallOption) {
	var log []string
	down := errors.New("API returned unexpected status code: 503: down")
	a := &chainFake{id: "a", errs: []error{down}, log: &log, stream: first}
	b := &chainFake{id: "b", log: &log, stream: "second answer"}
	var got []byte
	opts := []llms.CallOption{llms.WithStreamingFunc(func(_ context.Context, chunk []byte) error {
		got = append(got, chunk...)
		return nil
	})}
	chain := &modelChain{ids: []string{"a", "b"}, clients: []toolLoopModel{a, b}}
	return chain, a, b, &got, opts
}

func TestModelChainDoesNotFailOverAfterAByteWasStreamed(t *testing.T) {
	chain, a, b, got, opts := streamedFailureChain("partial")
	_, err := chain.GenerateContent(context.Background(), nil, opts...)
	if err == nil {
		t.Fatal("want the first model's error")
	}
	if b.calls != 0 {
		t.Errorf("second model was called %d times after a byte was streamed", b.calls)
	}
	if a.calls != 1 {
		t.Errorf("first model calls: got %d want 1", a.calls)
	}
	if string(*got) != "partial" {
		t.Errorf("streamed to the caller: got %q want %q", *got, "partial")
	}
	if chain.answered() != "a" {
		t.Errorf("answered after a failed call: got %q", chain.answered())
	}
}

func TestModelChainFailsOverWhenNothingWasStreamed(t *testing.T) {
	chain, _, b, got, opts := streamedFailureChain("")
	resp, err := chain.GenerateContent(context.Background(), nil, opts...)
	if err != nil {
		t.Fatalf("GenerateContent: %v", err)
	}
	if b.calls != 1 {
		t.Errorf("second model calls: got %d want 1", b.calls)
	}
	if resp.Choices[0].Content != "answered by b" {
		t.Errorf("answer: got %q", resp.Choices[0].Content)
	}
	if string(*got) != "second answer" {
		t.Errorf("streamed to the caller: got %q want %q", *got, "second answer")
	}
	if chain.answered() != "b" {
		t.Errorf("answered: got %q want b", chain.answered())
	}
}

func TestModelChainInstallsNoStreamWrapperWithoutACallerStream(t *testing.T) {
	var log []string
	f := &chainFake{id: "a", log: &log}
	chain := &modelChain{ids: []string{"a"}, clients: []toolLoopModel{f}}
	if _, err := chain.GenerateContent(context.Background(), nil, llms.WithMaxTokens(4), llms.WithTemperature(0)); err != nil {
		t.Fatalf("GenerateContent: %v", err)
	}
	if f.gotOpts != 2 || f.gotStream {
		t.Errorf("without a caller stream: got %d options, stream set %v; want 2, false", f.gotOpts, f.gotStream)
	}
	opts := []llms.CallOption{llms.WithMaxTokens(4), llms.WithStreamingFunc(func(context.Context, []byte) error { return nil })}
	if _, err := chain.GenerateContent(context.Background(), nil, opts...); err != nil {
		t.Fatalf("GenerateContent: %v", err)
	}
	if f.gotOpts != 3 || !f.gotStream {
		t.Errorf("with a caller stream: got %d options, stream set %v; want 3, true", f.gotOpts, f.gotStream)
	}
	if len(opts) != 2 {
		t.Errorf("caller's option slice was modified: len %d", len(opts))
	}
}

func TestModelChainWithNoModelsReturnsAnError(t *testing.T) {
	var nilChain *modelChain
	for name, c := range map[string]*modelChain{"nil": nilChain, "empty": {}} {
		resp, err := c.GenerateContent(context.Background(), nil)
		if err == nil || resp != nil {
			t.Errorf("%s chain: got resp %v err %v, want nil response and an error", name, resp, err)
		}
	}
}

func TestModelChainCallsNoModelOnACancelledContext(t *testing.T) {
	var log []string
	chain := &modelChain{
		ids:     []string{"a", "b"},
		clients: []toolLoopModel{&chainFake{id: "a", log: &log}, &chainFake{id: "b", log: &log}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err := chain.GenerateContent(ctx, nil)
	if !errors.Is(err, context.Canceled) || resp != nil {
		t.Errorf("got resp %v err %v, want nil and context.Canceled", resp, err)
	}
	if len(log) != 0 {
		t.Errorf("models called on a cancelled context: %v", log)
	}
}

// cancelFake cancels its context and then fails with an eligible error, the
// way a parent deadline that fires mid-call does.
type cancelFake struct {
	cancel func()
	log    *[]string
}

func (f *cancelFake) GenerateContent(ctx context.Context, msgs []llms.MessageContent, opts ...llms.CallOption) (*llms.ContentResponse, error) {
	*f.log = append(*f.log, "a")
	f.cancel()
	return nil, fmt.Errorf("call: %w", context.DeadlineExceeded)
}

func TestModelChainStopsWhenTheContextDiesBetweenModels(t *testing.T) {
	var log []string
	ctx, cancel := context.WithCancel(context.Background())
	second := &chainFake{id: "b", log: &log}
	chain := &modelChain{ids: []string{"a", "b"}, clients: []toolLoopModel{&cancelFake{cancel: cancel, log: &log}, second}}
	if _, err := chain.GenerateContent(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("error: got %v want context.Canceled", err)
	}
	if second.calls != 0 {
		t.Errorf("second model called %d times on a dead context", second.calls)
	}
}

func TestNewModelChainBuildsOneClientPerIDWithoutNetworkIO(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("OMLX_BASE_URL", srv.URL+"/v1")
	cfg := kbTestCfg()
	ids := []string{"a", "b"}
	chain, err := newModelChain(cfg, ids)
	if err != nil {
		t.Fatalf("newModelChain: %v", err)
	}
	if len(chain.clients) != 2 {
		t.Fatalf("clients: got %d want 2", len(chain.clients))
	}
	if got := chain.primary(); got != "a" {
		t.Errorf("primary: got %q want %q", got, "a")
	}
	for i, c := range chain.clients {
		l, ok := c.(*llmClient)
		if !ok {
			t.Fatalf("client %d: got %T want *llmClient", i, c)
		}
		if l.model != chain.ids[i] {
			t.Errorf("client %d model: got %q want %q", i, l.model, chain.ids[i])
		}
	}
	ids[0] = "mutated"
	if !slices.Equal(chain.ids, []string{"a", "b"}) {
		t.Errorf("chain ids changed with the input slice: %v", chain.ids)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("construction made %d requests, want 0", n)
	}
	if c, err := newModelChain(cfg, nil); err == nil || c != nil {
		t.Errorf("empty ids: got chain %v err %v, want nil and an error", c, err)
	}
}

// toolLoopFailoverChain returns a two-model chain whose first model completes
// one call of the tool "t" and then fails with first, and whose second model
// requests the same call and answers, plus the tool and the second model.
func toolLoopFailoverChain(first error) (*modelChain, *fakeTool, *fakeModel) {
	a := &fakeModel{
		queue: []*llms.ContentResponse{callResp("c1", "t", "{}"), textResp("unreached")},
		errs:  []error{nil, first},
	}
	b := callThenAnswer()
	chain := &modelChain{ids: []string{"a", "b"}, clients: []toolLoopModel{a, b}}
	return chain, okTool(), b
}

// TestFailoverRunsACompletedToolExactlyOnce is the acceptance for the no-replay
// record: the first model completes a tool call and then fails for a reason
// that advances the chain, and the tool must not run again.
func TestFailoverRunsACompletedToolExactlyOnce(t *testing.T) {
	chain, tool, b := toolLoopFailoverChain(errors.New("API returned unexpected status code: 503: down"))
	caps := LoopCaps{MaxRounds: 5, MaxCalls: 5, ToolMemo: newToolMemo()}
	final, _, err := runToolLoopChain(context.Background(), chain, newLoopReg(t, tool), userMsgs(), caps)
	if err != nil {
		t.Fatalf("runToolLoopChain: %v", err)
	}
	if len(tool.ran) != 1 {
		t.Errorf("tool ran %d times across the failover, want 1", len(tool.ran))
	}
	if b.calls == 0 {
		t.Error("the second model was never called after an eligible failure")
	}
	if final == "" {
		t.Error("the second model's answer did not reach the caller")
	}
}

// TestFailoverDoesNotAdvanceOnADenial is the other half: an error that is not
// the model's fault ends the turn, and the tool is not run a second time
// against another model.
func TestFailoverDoesNotAdvanceOnADenial(t *testing.T) {
	chain, tool, b := toolLoopFailoverChain(errors.New("engagement scope refused: target outside scope"))
	caps := LoopCaps{MaxRounds: 5, MaxCalls: 5, ToolMemo: newToolMemo()}
	if _, _, err := runToolLoopChain(context.Background(), chain, newLoopReg(t, tool), userMsgs(), caps); err == nil {
		t.Fatal("a denial was swallowed, want it returned")
	}
	if b.calls != 0 {
		t.Errorf("the second model was called %d times after a denial", b.calls)
	}
	if len(tool.ran) != 1 {
		t.Errorf("tool ran %d times, want 1", len(tool.ran))
	}
}

// TestRunToolLoopChainRefusesAnEmptyChain pins that an empty chain is an error
// rather than a silent empty answer.
func TestRunToolLoopChainRefusesAnEmptyChain(t *testing.T) {
	var nilChain *modelChain
	for name, c := range map[string]*modelChain{"nil": nilChain, "empty": {}} {
		final, _, err := runToolLoopChain(context.Background(), c, newLoopReg(t), userMsgs(), LoopCaps{})
		if err == nil || final != "" {
			t.Errorf("%s chain: got final %q err %v, want an empty answer and an error", name, final, err)
		}
	}
}

// TestRunToolLoopChainRecordsTheModelThatAnswered pins the provenance a turn
// reports: after the first model fails over, the chain must name the second.
func TestRunToolLoopChainRecordsTheModelThatAnswered(t *testing.T) {
	chain, tool, _ := toolLoopFailoverChain(errors.New("API returned unexpected status code: 503: down"))
	caps := LoopCaps{MaxRounds: 5, MaxCalls: 5, ToolMemo: newToolMemo()}
	if _, _, err := runToolLoopChain(context.Background(), chain, newLoopReg(t, tool), userMsgs(), caps); err != nil {
		t.Fatalf("runToolLoopChain: %v", err)
	}
	if got := chain.answered(); got != "b" {
		t.Errorf("answered: got %q want %q", got, "b")
	}
	if got := chain.primary(); got != "a" {
		t.Errorf("primary: got %q want %q", got, "a")
	}
}

// roleCall is one request the role fixture server received: the model id the
// request body carried and the turn stage that sent it.
type roleCall struct {
	model string
	stage string
}

// roleLLM stands in for the model server and records the model id of every
// request it receives, tagged by the stage that sent it. The action classifier
// and the query router are the turn's decisions; a streamed request is its
// answer. Each decision is answered with the one word that keeps the turn on
// the skip route, so the turn makes exactly those three calls.
//
// The body is the oracle because it is what the turn actually sends: a model id
// this code resolved but never used cannot appear here.
func roleLLM(t *testing.T) (*httptest.Server, func() []roleCall) {
	t.Helper()
	var mu sync.Mutex
	var seen []roleCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			http.NotFound(w, r)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "unreadable request", http.StatusBadRequest)
			return
		}
		var body struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			http.Error(w, "unreadable request", http.StatusBadRequest)
			return
		}
		stage, reply := "other", "IRRELEVANT"
		switch {
		case body.Stream:
			stage, reply = "answering", ""
		case strings.Contains(string(raw), "Classify the current user request"):
			stage, reply = "classify", "ADVICE"
		case strings.Contains(string(raw), "You decide how to handle the user's message"):
			stage, reply = "route", "SKIP"
		}
		mu.Lock()
		seen = append(seen, roleCall{model: body.Model, stage: stage})
		mu.Unlock()
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"an answer\"}}]}\n\ndata: [DONE]\n\n")
			return
		}
		content, _ := json.Marshal(reply)
		fmt.Fprintf(w, `{"choices":[{"index":0,"message":{"role":"assistant","content":%s},"finish_reason":"stop"}]}`, content)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []roleCall {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// roleTurnCfg points the LLM stack at srv and returns a config that names a
// different model for each role, with the fallback resolved from the
// environment so no model-list call is made.
func roleTurnCfg(t *testing.T, srv *httptest.Server) ragconfig.Config {
	t.Helper()
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "fallback-model")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "")
	cfg := answerCfg(2)
	cfg.RouterModel = "router-model"
	cfg.AssessmentModel = "assessment-model"
	return cfg
}

// TestATurnDecidesOnTheRouterModelAndAnswersOnTheAssessmentModel is the
// acceptance for the whole plan: the two kinds of call a turn makes reach two
// different models.
func TestATurnDecidesOnTheRouterModelAndAnswersOnTheAssessmentModel(t *testing.T) {
	srv, recorded := roleLLM(t)
	cfg := roleTurnCfg(t, srv)

	ans, _, _, _, _, route, err := adaptiveAnswer(context.Background(), &recSearcher{}, cfg,
		"write a limerick", enabledRoutes{Local: true, Web: false}, false, AnswerOpts{})
	if err != nil {
		t.Fatalf("adaptiveAnswer: %v", err)
	}
	if route != "skip" || ans == "" {
		t.Fatalf("route = %q answer = %q, want an answer on the skip route", route, ans)
	}
	decisions, answers := 0, 0
	for _, c := range recorded() {
		switch c.stage {
		case "classify", "route":
			decisions++
			if c.model != "router-model" {
				t.Errorf("the %s call used model %q, want the router model", c.stage, c.model)
			}
		case "answering":
			answers++
			if c.model != "assessment-model" {
				t.Errorf("the answering call used model %q, want the assessment model", c.model)
			}
		default:
			t.Errorf("unexpected %s call on model %q", c.stage, c.model)
		}
	}
	if decisions != 2 {
		t.Errorf("the turn made %d decision calls, want the action classifier and the query router", decisions)
	}
	if answers != 1 {
		t.Errorf("the turn made %d answering calls, want 1", answers)
	}
}

// TestANamedModelAnswersEveryCallOfTheTurn is the regression test from the
// other side: an operator who names a model gets that model for every call,
// whatever the two roles are configured to be.
func TestANamedModelAnswersEveryCallOfTheTurn(t *testing.T) {
	srv, recorded := roleLLM(t)
	cfg := roleTurnCfg(t, srv)

	ans, _, _, _, _, route, err := adaptiveAnswer(context.Background(), &recSearcher{}, cfg,
		"write a limerick", enabledRoutes{Local: true, Web: false}, false, AnswerOpts{Model: "picked-model"})
	if err != nil {
		t.Fatalf("adaptiveAnswer: %v", err)
	}
	if route != "skip" || ans == "" {
		t.Fatalf("route = %q answer = %q, want an answer on the skip route", route, ans)
	}
	calls := recorded()
	if len(calls) != 3 {
		t.Fatalf("the turn made %d calls, want the classifier, the router and the answer", len(calls))
	}
	for _, c := range calls {
		if c.model != "picked-model" {
			t.Errorf("the %s call used model %q, want the named model", c.stage, c.model)
		}
	}
}

// TestATurnNamesNoModelAndCarriesBothChains pins the contract between
// runNativeTurn and the answer path: the turn builds a chain per role and
// leaves the named model empty, so the resolved default is never read further
// down as an operator's pick.
func TestATurnNamesNoModelAndCarriesBothChains(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	t.Setenv("OMLX_MODEL", "fallback-model")
	old := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = old })
	var got AnswerOpts
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		got = opts
		return "fixture", nil, false, nil, 0, "skip", nil
	}
	cfg := answerCfg(2)
	cfg.RouterModel = "router-model"
	cfg.AssessmentModel = "assessment-model"
	res, err := runNativeTurn(context.Background(), nil, cfg, turnRequest{Question: "a question"})
	if err != nil {
		t.Fatalf("runNativeTurn: %v", err)
	}
	if got.Model != "" {
		t.Errorf("the turn named model %q, want none so the two roles stay apart", got.Model)
	}
	if got.routerChain == nil || got.assessmentChain == nil {
		t.Fatalf("router chain = %v, assessment chain = %v, want a chain for each role", got.routerChain, got.assessmentChain)
	}
	if id := got.routerChain.primary(); id != "router-model" {
		t.Errorf("the router chain leads with %q, want the router model", id)
	}
	if id := got.assessmentChain.primary(); id != "assessment-model" {
		t.Errorf("the assessment chain leads with %q, want the assessment model", id)
	}
	if res.Model != "assessment-model" {
		t.Errorf("the turn reports model %q, want the assessment model", res.Model)
	}
}

// TestTheTUITurnCarriesOnlyTheOperatorsPick drives the TUI's own turn command.
// The TUI calls runNativeTurn directly, so the nearest seam is the AnswerOpts
// the turn hands the answer path: opts.Model is the request's Model trimmed,
// and both chains are built from that same field. It does not cover what the
// status line or the transcript then display.
func TestTheTUITurnCarriesOnlyTheOperatorsPick(t *testing.T) {
	useDeadServices(t)
	t.Setenv("OMLX_MODEL", "fallback-model")
	old := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = old })
	var got AnswerOpts
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		got = opts
		return "fixture", nil, false, nil, 0, "skip", nil
	}
	m := newKeyModel(t)
	m.cfg.RouterModel = "router-model"
	m.cfg.AssessmentModel = "assessment-model"
	m.resolvedModel = "server-default"

	got = AnswerOpts{}
	if done, ok := m.streamCmd(context.Background(), "a question", "", m.turnStart, false)().(streamDoneMsg); !ok || done.err != nil {
		t.Fatalf("turn did not complete: %#v", done)
	}
	if got.Model != "" {
		t.Errorf("with no pick the TUI named model %q, want none", got.Model)
	}
	if got.routerChain.primary() != "router-model" || got.assessmentChain.primary() != "assessment-model" {
		t.Errorf("TUI chains lead with %q and %q, want the router and assessment models",
			got.routerChain.primary(), got.assessmentChain.primary())
	}

	m.ragModel = "  picked-model  "
	got = AnswerOpts{}
	if done, ok := m.streamCmd(context.Background(), "a question", "", m.turnStart, false)().(streamDoneMsg); !ok || done.err != nil {
		t.Fatalf("turn did not complete: %#v", done)
	}
	if got.Model != "picked-model" {
		t.Errorf("with a pick the TUI named model %q, want the pick", got.Model)
	}
	if got.routerChain.primary() != "picked-model" || got.assessmentChain.primary() != "picked-model" {
		t.Errorf("a picked model gave chains %q and %q, want the pick for both roles",
			got.routerChain.primary(), got.assessmentChain.primary())
	}
}
