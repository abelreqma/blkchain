package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/webacquire"
)

func TestChatWebSearchFiltersModelQueriesAndTracksSources(t *testing.T) {
	authorizeWebTest(t)
	old := webSearch
	t.Cleanup(func() { webSearch = old })
	query := ""
	webSearch = func(_ context.Context, _, q string, _ int, _ []string) ([]retrieval.Result, error) {
		query = q
		return []retrieval.Result{chunk(webSource, "https://owasp.org/www-project-top-ten/", "OWASP", "public result")}, nil
	}
	prov := &chatWebProvenance{urls: map[string]bool{}}
	tool := newChatWebSearchTool(ragconfig.Config{}, "Current web testing guidance", nil, prov)
	if out, err := tool.Call(context.Background(), `{"query":"OWASP web testing guidance"}`); err != nil || query != "OWASP web testing guidance" || !strings.Contains(out, "public result") {
		t.Fatalf("filtered search failed: query=%q out=%q err=%v", query, out, err)
	}
	if !prov.urls["https://owasp.org/www-project-top-ten/"] {
		t.Fatal("search result URL was not retained for extraction")
	}
	for _, q := range []string{"https://internal.example.test/", "10.0.0.7", "api_key=secretvalue", "sk-abcdef1234567890"} {
		before := query
		out, err := tool.Call(context.Background(), `{"query":"`+q+`"}`)
		if err != nil || !strings.Contains(out, "sensitive") || query != before {
			t.Errorf("sensitive query reached provider: query=%q out=%q err=%v", query, out, err)
		}
	}
}

func TestChatWebSearchRejectsResultsWithoutSourceURLs(t *testing.T) {
	old := webSearch
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		return []retrieval.Result{chunk(webSource, "not-a-url", "Unverified", "unsupported claim")}, nil
	}
	t.Cleanup(func() { webSearch = old })
	provenance := &chatWebProvenance{urls: map[string]bool{}}
	tool := newChatWebSearchTool(ragconfig.Config{}, "current guidance", nil, provenance)
	out, err := tool.Call(context.Background(), `{"query":"current guidance"}`)
	if err != nil || !strings.Contains(out, "no valid source URLs") || len(provenance.evidence) != 0 {
		t.Fatalf("unattributed result was accepted: out=%q err=%v", out, err)
	}
}

func TestChatWebExtractBlocksPrivateRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1/private", http.StatusFound)
	}))
	defer server.Close()
	broker := chatPublicBroker()
	broker.Policy.Resolve = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "example.test" {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		return []net.IP{net.ParseIP(host)}, nil
	}
	broker.Policy.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "http://"))
	}
	if _, err := broker.Fetch(context.Background(), webacquire.Request{Method: "GET", URL: "http://example.test/start"}); err == nil || !strings.Contains(err.Error(), "outside scope") {
		t.Fatalf("private redirect was not denied: %v", err)
	}
}

func TestChatWebExtractLivePublicPage(t *testing.T) {
	if os.Getenv("BLKCHAIN_CHAT_WEB_E2E") != "1" {
		t.Skip("set BLKCHAIN_CHAT_WEB_E2E=1 for a live public extraction")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tool := newChatWebExtractTool("Read https://example.com/", &chatWebProvenance{urls: map[string]bool{}})
	out, err := tool.Call(ctx, `{"url":"https://example.com/"}`)
	if err != nil || !strings.Contains(out, "Example Domain") || !strings.Contains(out, "Status: 200") {
		t.Fatalf("public extraction failed: out=%q err=%v", out, err)
	}
}

func TestChatWebExtractRequiresURLProvenanceAndPublicDNS(t *testing.T) {
	prov := &chatWebProvenance{urls: map[string]bool{}}
	tool := newChatWebExtractTool("Read public guidance", prov)
	if out, err := tool.Call(context.Background(), `{"url":"https://example.com/private"}`); err != nil || !strings.Contains(out, "user request or this turn") {
		t.Fatalf("invented URL accepted: out=%q err=%v", out, err)
	}
	secretURL := "https://example.com/sk-abcdef1234567890"
	secretTool := newChatWebExtractTool("Read "+secretURL, prov)
	if out, err := secretTool.Call(context.Background(), `{"url":"`+secretURL+`"}`); err != nil || !strings.Contains(out, "sensitive data") {
		t.Fatalf("secret-shaped path was fetched: out=%q err=%v", out, err)
	}
	policy := chatPublicBroker().Policy
	for _, raw := range []string{"127.0.0.1", "10.0.0.7", "169.254.169.254", "::1", "fc00::1"} {
		if policy.IPAllowed("example.com", net.ParseIP(raw)) {
			t.Errorf("private destination %s allowed", raw)
		}
	}
	if !policy.IPAllowed("example.com", net.ParseIP("1.1.1.1")) {
		t.Fatal("public destination rejected")
	}
	if got := chatHTMLText([]byte(`<html><body><nav>skip</nav><h1>Title</h1><p>Useful text</p><script>secret</script></body></html>`)); !strings.Contains(got, "Title") || !strings.Contains(got, "Useful text") || strings.Contains(got, "secret") || strings.Contains(got, "skip") {
		t.Fatalf("HTML extraction = %q", got)
	}
}
