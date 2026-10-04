package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestTavilySearchMapsResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"title":"NVD CVE","url":"https://nvd.nist.gov/x","content":"body","score":0.9}]}`))
	}))
	defer srv.Close()
	got, err := tavilySearchAt(context.Background(), srv.URL, "k", "cve-2024-1", 5, []string{"nvd.nist.gov"})
	if err != nil || len(got) != 1 || got[0].Payload.Source != "web" || got[0].Payload.Path != "https://nvd.nist.gov/x" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestTavilyKeyAbsentSkips(t *testing.T) {
	t.Setenv("TAVILY_SETUP_TOKEN", "")
	t.Setenv("TAVILY_API_KEY", "")
	if tavilyKey() != "" {
		t.Errorf("expected empty key")
	}
}

// fnPtr identifies a function value by its code pointer, so a test can assert
// which provider webProvider returned (func values are not == comparable).
func fnPtr(f webSearchFn) uintptr { return reflect.ValueOf(f).Pointer() }

func TestWebProviderSelection(t *testing.T) {
	// A Tavily key selects Tavily and web is available, regardless of the
	// fallback opt-in.
	isolateUserDirs(t)
	t.Setenv(webProviderEnv, "auto")
	t.Setenv("BLKCHAIN_WEB_FALLBACK", "")
	if fn, ok := webProvider("tvly-xxx"); !ok || fnPtr(fn) != fnPtr(tavilySearch) {
		t.Errorf("a Tavily key should select Tavily and be available (ok=%v)", ok)
	}

	// No key and no opt-in: web search stays unavailable so a keyless install
	// makes no outbound request by default.
	if fn, ok := webProvider(""); !ok || fnPtr(fn) != fnPtr(duckDuckGoSearch) {
		t.Error("keyless installs must have DuckDuckGo capability")
	}

	// No key with the DuckDuckGo opt-in: the keyless fallback is selected.
	t.Setenv("BLKCHAIN_WEB_FALLBACK", "duckduckgo")
	if fn, ok := webProvider(""); !ok || fnPtr(fn) != fnPtr(duckDuckGoSearch) {
		t.Errorf("no key with opt-in should select the DuckDuckGo fallback (ok=%v)", ok)
	}
}

func TestActiveWebProvider(t *testing.T) {
	isolateUserDirs(t)
	t.Setenv(webProviderEnv, "auto")
	t.Setenv("TAVILY_API_KEY", "")
	cases := []struct {
		name     string
		tavily   string
		fallback string
		want     string
	}{
		{"tavily key present", "tvly-xxx", "", "tavily"},
		{"tavily key beats fallback", "tvly-xxx", "duckduckgo", "tavily"},
		{"no key, ddg opted in", "", "duckduckgo", "duckduckgo"},
		{"no key, no opt-in", "", "", "duckduckgo"},
		{"no key, unknown fallback value", "", "bing", "duckduckgo"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("TAVILY_SETUP_TOKEN", c.tavily)
			t.Setenv("BLKCHAIN_WEB_FALLBACK", c.fallback)
			if got := activeWebProvider(); got != c.want {
				t.Errorf("activeWebProvider() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestDuckDuckGoSearchMapsUntrustedAndCaps(t *testing.T) {
	const body = `<div class="result"><a class="result__a" href="https://owasp.org/xss">XSS</a><div class="result__snippet">Cross-site scripting overview</div></div>
<div class="result"><a class="result__a" href="https://a.example/1">Reflected XSS</a></div>
<div class="result"><a class="result__a" href="https://a.example/2">Stored XSS</a></div>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	got, err := duckDuckGoSearchAt(context.Background(), srv.URL, "reflected xss", 2)
	if err != nil {
		t.Fatalf("duckDuckGoSearchAt: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("max_results cap not enforced: want 2, got %d (%+v)", len(got), got)
	}
	for i, r := range got {
		if r.Payload.Source != webSource {
			t.Errorf("result %d Source = %q, want %q (web results must stay untrusted)", i, r.Payload.Source, webSource)
		}
	}
	if got[0].Payload.Path != "https://owasp.org/xss" {
		t.Errorf("abstract not mapped first: got %q", got[0].Payload.Path)
	}
}
