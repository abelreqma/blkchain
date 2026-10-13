package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
