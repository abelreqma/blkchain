package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"blkchain/cli/internal/retrieval"
	"golang.org/x/net/html"
)

const (
	tavilyAPIKeyEnv       = "TAVILY_SETUP_TOKEN"
	webSource             = "web"
	webFallbackEnv        = "BLKCHAIN_WEB_FALLBACK"
	webFallbackDuckDuckGo = "duckduckgo"
	webProviderTavily     = "tavily"
	webProviderDuckDuckGo = "duckduckgo"
	webProviderNone       = "off"
	webProviderAuto       = "auto"
	webProviderEnv        = "BLKCHAIN_WEB_PROVIDER"
	ddgBaseURL            = "https://html.duckduckgo.com/html/"
	webMaxResponseBytes   = 2 << 20
	webMaxResults         = 20
	webQueryMaxBytes      = 4096
	webRequestTimeout     = 20 * time.Second
)

var webHTTPClient = &http.Client{
	Timeout:       webRequestTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

type tavilySearchRequest struct {
	APIKey         string   `json:"api_key"`
	Query          string   `json:"query"`
	MaxResults     int      `json:"max_results"`
	IncludeDomains []string `json:"include_domains,omitempty"`
}

type tavilySearchResponse struct {
	Results []struct {
		Title   string  `json:"title"`
		URL     string  `json:"url"`
		Content string  `json:"content"`
		Score   float64 `json:"score"`
	} `json:"results"`
}

type webSearchFn func(context.Context, string, string, int, []string) ([]retrieval.Result, error)

func tavilyKey() string {
	if key := strings.TrimSpace(os.Getenv("TAVILY_API_KEY")); key != "" {
		return key
	}
	return strings.TrimSpace(os.Getenv(tavilyAPIKeyEnv))
}

func webProviderSetting(p modelPrefs) string {
	if value := os.Getenv(webProviderEnv); strings.TrimSpace(value) != "" {
		return strings.ToLower(strings.TrimSpace(value))
	}
	if p.WebProvider != "" {
		return p.WebProvider
	}
	if os.Getenv(webFallbackEnv) == webFallbackDuckDuckGo && tavilyKey() == "" {
		return webProviderDuckDuckGo
	}
	return webProviderAuto
}

func webProviderName(apiKey string) string {
	switch webProviderSetting(loadPrefs()) {
	case webProviderAuto:
		if apiKey != "" {
			return webProviderTavily
		}
		return webProviderDuckDuckGo
	case webProviderDuckDuckGo:
		return webProviderDuckDuckGo
	case webProviderTavily:
		if apiKey != "" {
			return webProviderTavily
		}
	}
	return webProviderNone
}

func webProvider(apiKey string) (webSearchFn, bool) {
	switch webProviderName(apiKey) {
	case webProviderTavily:
		return tavilySearch, true
	case webProviderDuckDuckGo:
		return duckDuckGoSearch, true
	}
	return nil, false
}

func activeWebProvider() string { return webProviderName(tavilyKey()) }

func dispatchWebSearch(ctx context.Context, apiKey, query string, maxResults int, includeDomains []string) ([]retrieval.Result, error) {
	if !loadPrefs().Web {
		return nil, errors.New("web: disabled; enable web before searching the internet")
	}
	provider, ok := webProvider(apiKey)
	if !ok {
		return nil, errors.New("web: provider unavailable; select duckduckgo or configure TAVILY_API_KEY")
	}
	results, err := provider(ctx, apiKey, query, maxResults, includeDomains)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if webProviderSetting(loadPrefs()) == webProviderAuto && apiKey != "" && (err != nil || len(results) == 0) {
		fallback, fallbackErr := duckDuckGoSearch(ctx, "", query, maxResults, includeDomains)
		if fallbackErr != nil {
			return nil, errors.Join(err, fallbackErr)
		}
		return fallback, nil
	}
	return results, err
}

func searchLimit(query string, requested int) (int, error) {
	if strings.TrimSpace(query) == "" || len(query) > webQueryMaxBytes {
		return 0, fmt.Errorf("web: query must contain 1 to %d bytes", webQueryMaxBytes)
	}
	if requested <= 0 {
		requested = 5
	}
	return min(requested, webMaxResults), nil
}

func searchBody(ctx context.Context, method, endpoint string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, errors.New("web: invalid search request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "blkChain/1.0")
	resp, err := webHTTPClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("web: search request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("web: provider returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, webMaxResponseBytes+1))
	if err != nil {
		return nil, errors.New("web: cannot read search response")
	}
	if len(data) > webMaxResponseBytes {
		return nil, errors.New("web: search response exceeds size limit")
	}
	return data, nil
}

func tavilySearch(ctx context.Context, apiKey, query string, maxResults int, domains []string) ([]retrieval.Result, error) {
	return tavilySearchAt(ctx, "https://api.tavily.com", apiKey, query, maxResults, domains)
}

func tavilySearchAt(ctx context.Context, baseURL, apiKey, query string, maxResults int, domains []string) ([]retrieval.Result, error) {
	limit, err := searchLimit(query, maxResults)
	if err != nil {
		return nil, err
	}
	if apiKey == "" {
		return nil, errors.New("tavily: set TAVILY_API_KEY or TAVILY_SETUP_TOKEN")
	}
	body, err := json.Marshal(tavilySearchRequest{apiKey, query, limit, domains})
	if err != nil {
		return nil, errors.New("tavily: invalid search request")
	}
	data, err := searchBody(ctx, http.MethodPost, baseURL+"/search", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("tavily: %w", err)
	}
	var parsed tavilySearchResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, errors.New("tavily: invalid search response")
	}
	results := make([]retrieval.Result, 0, limit)
	for _, hit := range parsed.Results {
		if allowedSearchURL(hit.URL, domains) {
			results = append(results, searchResult(hit.Title, hit.URL, hit.Content, hit.Score))
			if len(results) == limit {
				break
			}
		}
	}
	return results, nil
}

func allowedSearchURL(raw string, domains []string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return false
	}
	if len(domains) == 0 {
		return true
	}
	host := strings.ToLower(u.Hostname())
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain != "" && (host == domain || strings.HasSuffix(host, "."+domain)) {
			return true
		}
	}
	return false
}

func searchResult(title, link, text string, score float64) retrieval.Result {
	return retrieval.Result{ID: link, Score: score, Payload: retrieval.Payload{Source: webSource, Path: link, Section: capRunes(title, 500), Type: "doc", Text: capRunes(text, 8000)}}
}

func duckDuckGoSearch(ctx context.Context, _ string, query string, maxResults int, domains []string) ([]retrieval.Result, error) {
	if len(domains) > 0 {
		sites := make([]string, 0, len(domains))
		for _, domain := range domains {
			sites = append(sites, "site:"+domain)
		}
		query += " (" + strings.Join(sites, " OR ") + ")"
	}
	results, err := duckDuckGoSearchAt(ctx, ddgBaseURL, query, maxResults)
	if err != nil {
		return nil, err
	}
	filtered := results[:0]
	for _, r := range results {
		if allowedSearchURL(r.Payload.Path, domains) {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}

func duckDuckGoSearchAt(ctx context.Context, baseURL, query string, maxResults int) ([]retrieval.Result, error) {
	limit, err := searchLimit(query, maxResults)
	if err != nil {
		return nil, err
	}
	data, err := searchBody(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/?"+url.Values{"q": {query}}.Encode(), nil)
	if err != nil {
		if strings.Contains(err.Error(), "HTTP 202") {
			return nil, errors.New("duckduckgo: search requires a CAPTCHA; use Tavily or retry later")
		}
		return nil, fmt.Errorf("duckduckgo: %w", err)
	}
	if bytes.Contains(data, []byte("anomaly-modal")) || bytes.Contains(data, []byte("challenge-form")) {
		return nil, errors.New("duckduckgo: search requires a CAPTCHA; use Tavily or retry later")
	}
	doc, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("duckduckgo: invalid search response")
	}
	results := make([]retrieval.Result, 0, limit)
	seen := map[string]bool{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if len(results) >= limit {
			return
		}
		if htmlClass(n, "result") || htmlClass(n, "web-result") {
			anchor, snippet := htmlFindClass(n, "result__a"), htmlFindClass(n, "result__snippet")
			if anchor != nil {
				link := htmlAttr(anchor, "href")
				if u, err := url.Parse(link); err == nil && (u.Hostname() == "duckduckgo.com" || u.Hostname() == "html.duckduckgo.com" || u.Hostname() == "" && u.Path == "/l/") {
					link = u.Query().Get("uddg")
				}
				if allowedSearchURL(link, nil) && !seen[link] {
					seen[link] = true
					results = append(results, searchResult(htmlText(anchor), link, htmlText(snippet), 0))
				}
			}
			return
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	if len(results) == 0 && !bytes.Contains(data, []byte("no-results")) {
		return nil, errors.New("duckduckgo: no recognizable search results")
	}
	return results, nil
}

func htmlAttr(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}
func htmlClass(n *html.Node, class string) bool {
	for _, value := range strings.Fields(htmlAttr(n, "class")) {
		if value == class {
			return true
		}
	}
	return false
}
func htmlFindClass(n *html.Node, class string) *html.Node {
	if htmlClass(n, class) {
		return n
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if found := htmlFindClass(child, class); found != nil {
			return found
		}
	}
	return nil
}
func htmlText(n *html.Node) string {
	if n == nil {
		return ""
	}
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			b.WriteString(node.Data)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(b.String()), " ")
}
