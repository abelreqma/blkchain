package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"syscall"
	"testing"

	"github.com/tmc/langchaingo/llms"
)

func TestFailoverEligibleRefusesWhatIsNotTheModelsFault(t *testing.T) {
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
		{"context window by code", errors.New("API returned unexpected status code: 400: {\"code\":\"context_length_exceeded\"}")},
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if !failoverEligible(callErr) {
		t.Errorf("a 503 from a real client is not eligible: %v", callErr)
	}
}

// TestFailoverNotEligibleOnARealUnknownModel is the same path for a 404, which
// is the request's own fault and must not advance the chain.
func TestFailoverNotEligibleOnARealUnknownModel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}

func (f *chainFake) GenerateContent(ctx context.Context, msgs []llms.MessageContent, opts ...llms.CallOption) (*llms.ContentResponse, error) {
	i := f.calls
	f.calls++
	*f.log = append(*f.log, f.id)
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
