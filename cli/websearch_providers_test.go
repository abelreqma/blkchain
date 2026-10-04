package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDuckDuckGoHTMLResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "xss & prevention" {
			t.Errorf("query = %q", r.URL.Query().Get("q"))
		}
		w.Write([]byte(`<div class="result web-result"><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fowasp.org%2Fxss&amp;rut=x">XSS &amp; prevention</a><div class="result__snippet">Encode <b>output</b>.</div></div><div class="result web-result"><a href="javascript:alert(1)" class="result__a">Bad</a></div><div class="result web-result"><a href="https://other.example/x" class="result__a">Other</a><div class="result__snippet">Other body</div></div>`))
	}))
	defer srv.Close()
	got, err := duckDuckGoSearchAt(context.Background(), srv.URL, "xss & prevention", 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("results = %+v, err = %v", got, err)
	}
	if got[0].Payload.Path != "https://owasp.org/xss" || got[0].Payload.Section != "XSS & prevention" || got[0].Payload.Text != "Encode output." || got[0].Payload.Source != webSource {
		t.Fatalf("result = %+v", got[0])
	}
}

func TestTavilyRequestAndResultBounds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in tavilySearchRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Error(err)
			return
		}
		if in.MaxResults != 1 || in.APIKey != "test-key" || in.Query != "query" || len(in.IncludeDomains) != 1 {
			t.Errorf("request = %+v", in)
		}
		w.Write([]byte(`{"results":[{"url":"javascript:alert(1)","content":"bad"},{"url":"https://owasp.org/x","content":"first"},{"url":"https://owasp.org/y","content":"second"}]}`))
	}))
	defer srv.Close()
	got, err := tavilySearchAt(context.Background(), srv.URL, "test-key", "query", 1, []string{"owasp.org"})
	if err != nil || len(got) != 1 || got[0].Payload.Text != "first" {
		t.Fatalf("results = %+v, err = %v", got, err)
	}
}

func TestSearchProviderRejectsRedirects(t *testing.T) {
	calls := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.Write([]byte(`{}`)) }))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	if _, err := tavilySearchAt(context.Background(), origin.URL, "secret-test-key", "q", 1, nil); err == nil {
		t.Error("Tavily accepted redirect")
	}
	if _, err := duckDuckGoSearchAt(context.Background(), origin.URL, "q", 1); err == nil {
		t.Error("DuckDuckGo accepted redirect")
	}
	if calls != 0 {
		t.Fatalf("redirect destination received %d requests", calls)
	}
}

func TestDuckDuckGoChallengeIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<form id="challenge-form"><div class="anomaly-modal">challenge</div></form>`))
	}))
	defer srv.Close()
	if _, err := duckDuckGoSearchAt(context.Background(), srv.URL, "q", 5); err == nil {
		t.Fatal("challenge returned as successful empty search")
	}
}

func TestSearchProviderRejectsOversize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[]}` + strings.Repeat(" ", 11<<20)))
	}))
	defer srv.Close()
	if _, err := tavilySearchAt(context.Background(), srv.URL, "k", "q", 1, nil); err == nil {
		t.Fatal("accepted oversized JSON body")
	}
}

type searchRoundTripFunc func(*http.Request) (*http.Response, error)

func (f searchRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAutoProviderFallbackAndExplicitSelection(t *testing.T) {
	authorizeWebTest(t)
	t.Setenv(webProviderEnv, "auto")
	t.Setenv("TAVILY_API_KEY", "")
	original := webHTTPClient
	defer func() { webHTTPClient = original }()
	var hosts []string
	webHTTPClient = &http.Client{Transport: searchRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		hosts = append(hosts, r.URL.Hostname())
		body := `<div class="result"><a class="result__a" href="https://owasp.org/x">XSS</a><div class="result__snippet">Evidence</div></div>`
		status := http.StatusOK
		if r.URL.Hostname() == "api.tavily.com" {
			status = http.StatusUnauthorized
			body = "secret-test-key"
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	results, err := dispatchWebSearch(context.Background(), "secret-test-key", "q", 2, nil)
	if err != nil || len(results) != 1 || len(hosts) != 2 || hosts[0] != "api.tavily.com" || hosts[1] != "html.duckduckgo.com" {
		t.Fatalf("results %+v hosts %v err %v", results, hosts, err)
	}
	t.Setenv(webProviderEnv, "tavily")
	hosts = nil
	_, err = dispatchWebSearch(context.Background(), "secret-test-key", "q", 2, nil)
	if err == nil || len(hosts) != 1 || strings.Contains(err.Error(), "secret-test-key") {
		t.Fatalf("hosts %v err %v", hosts, err)
	}
}

func TestDuckDuckGoDomainFilter(t *testing.T) {
	original := webHTTPClient
	defer func() { webHTTPClient = original }()
	webHTTPClient = &http.Client{Transport: searchRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.Contains(r.URL.Query().Get("q"), "site:owasp.org") {
			t.Errorf("domain filter missing from query")
		}
		body := `<div class="result"><a class="result__a" href="https://owasp.org.evil.test/x">Bad</a></div><div class="result"><a class="result__a" href="https://cheatsheetseries.owasp.org/x">Good</a></div>`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	results, err := duckDuckGoSearch(context.Background(), "", "q", 5, []string{"owasp.org"})
	if err != nil || len(results) != 1 || results[0].Payload.Path != "https://cheatsheetseries.owasp.org/x" {
		t.Fatalf("results %+v err %v", results, err)
	}
}

func TestProviderKeyPriorityAndInvalidSelection(t *testing.T) {
	isolateUserDirs(t)
	t.Setenv("TAVILY_API_KEY", "standard-test-key")
	t.Setenv(tavilyAPIKeyEnv, "alternate-test-key")
	if tavilyKey() != "standard-test-key" {
		t.Fatal("standard key did not take precedence")
	}
	t.Setenv(webProviderEnv, "bogus")
	if _, ok := webProvider(tavilyKey()); ok {
		t.Fatal("unknown provider did not fail closed")
	}
}

func TestSearchCancellationAndQueryBounds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := duckDuckGoSearchAt(ctx, "https://html.duckduckgo.com", "q", 5); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error %v", err)
	}
	for _, query := range []string{"", strings.Repeat("x", webQueryMaxBytes+1)} {
		if _, err := tavilySearchAt(context.Background(), "invalid", "k", query, 5, nil); err == nil {
			t.Fatal("invalid query accepted")
		}
	}
	if got, err := searchLimit("q", 1000000); err != nil || got != 20 {
		t.Fatalf("limit %d err %v", got, err)
	}
}
