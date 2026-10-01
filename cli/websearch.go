package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"blkchain/cli/internal/retrieval"
)

// tavilyAPIKeyEnv is the environment variable holding the Tavily API key.
const tavilyAPIKeyEnv = "TAVILY_SETUP_TOKEN"

// webSource is the Source of every web result. buildContext marks it untrusted
// external evidence, and citations from it carry the web tag.
const webSource = "web"

// tavilyMaxResponseBytes bounds how much of a Tavily response body is read,
// to avoid unbounded memory use on a misbehaving or malicious endpoint.
const tavilyMaxResponseBytes = 10 << 20 // 10 MiB

// tavilyRequestTimeout bounds how long a single Tavily request may take, so a
// hung endpoint cannot hang `blk ask` indefinitely.
const tavilyRequestTimeout = 20 * time.Second

// tavilyHTTPClient is the HTTP client used for Tavily requests, with a
// request timeout (see tavilyRequestTimeout) instead of http.DefaultClient's
// unbounded wait.
var tavilyHTTPClient = &http.Client{Timeout: tavilyRequestTimeout}

// tavilySearchRequest is the Tavily /search request body.
type tavilySearchRequest struct {
	APIKey         string   `json:"api_key"`
	Query          string   `json:"query"`
	MaxResults     int      `json:"max_results"`
	IncludeDomains []string `json:"include_domains,omitempty"`
}

// tavilySearchResponse is the subset of the Tavily /search response this
// client consumes.
type tavilySearchResponse struct {
	Results []struct {
		Title   string  `json:"title"`
		URL     string  `json:"url"`
		Content string  `json:"content"`
		Score   float64 `json:"score"`
	} `json:"results"`
}

// tavilyKey reads the Tavily API key. It returns "" when unset so callers can
// skip web search entirely.
func tavilyKey() string {
	return os.Getenv(tavilyAPIKeyEnv)
}

// tavilySearch queries the live Tavily API.
func tavilySearch(ctx context.Context, apiKey, query string, maxResults int, includeDomains []string) ([]retrieval.Result, error) {
	return tavilySearchAt(ctx, "https://api.tavily.com", apiKey, query, maxResults, includeDomains)
}

// tavilySearchAt POSTs a search request to baseURL+"/search" and maps the
// Tavily hits to retrieval.Result, so the answer loop's web fallback can
// treat them like any other retrieval result (tagged Source webSource).
func tavilySearchAt(ctx context.Context, baseURL, apiKey, query string, maxResults int, includeDomains []string) ([]retrieval.Result, error) {
	reqBody := tavilySearchRequest{
		APIKey:     apiKey,
		Query:      query,
		MaxResults: maxResults,
	}
	if len(includeDomains) > 0 {
		reqBody.IncludeDomains = includeDomains
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("tavily: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/search", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("tavily: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := tavilyHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tavily: request failed: %w", err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, tavilyMaxResponseBytes)

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, limited)
		return nil, fmt.Errorf("tavily: unexpected status %d", resp.StatusCode)
	}

	var parsed tavilySearchResponse
	if err := json.NewDecoder(limited).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("tavily: decode response: %w", err)
	}

	results := make([]retrieval.Result, 0, len(parsed.Results))
	for _, hit := range parsed.Results {
		results = append(results, retrieval.Result{
			ID:    hit.URL,
			Score: hit.Score,
			Payload: retrieval.Payload{
				Source:  webSource,
				Path:    hit.URL,
				Section: hit.Title,
				Type:    "doc",
				Text:    hit.Content,
			},
		})
	}
	return results, nil
}

// webSearchFn is the shape of a web-search provider: given a query, a result
// cap, and optional include-domains, it returns web results tagged webSource.
// Both tavilySearch and duckDuckGoSearch satisfy it so the answer loop can pick
// one behind the webSearch seam.
type webSearchFn func(ctx context.Context, apiKey, query string, maxResults int, includeDomains []string) ([]retrieval.Result, error)

// webFallbackEnv is the opt-in for the keyless DuckDuckGo fallback. blkChain is
// offline by default, so when no Tavily key is set the web path stays off and
// makes no outbound request unless this is set to webFallbackDuckDuckGo.
const webFallbackEnv = "BLKCHAIN_WEB_FALLBACK"

// webFallbackDuckDuckGo is the webFallbackEnv value that opts into the keyless
// DuckDuckGo Instant Answer fallback.
const webFallbackDuckDuckGo = "duckduckgo"

// Web-search provider labels. These are the values webProviderName and
// activeWebProvider return and the names the UI renders.
const (
	webProviderTavily     = "tavily"
	webProviderDuckDuckGo = "duckduckgo"
	webProviderNone       = "off"
)

// webProviderName is the single source of truth for which web-search provider a
// given Tavily key selects: Tavily when the key is set, else the keyless
// DuckDuckGo fallback when opted in via BLKCHAIN_WEB_FALLBACK, else none. Both
// webProvider (func + availability) and activeWebProvider (label) derive from
// it, so the selection logic lives in exactly one place.
func webProviderName(apiKey string) string {
	if apiKey != "" {
		return webProviderTavily
	}
	if os.Getenv(webFallbackEnv) == webFallbackDuckDuckGo {
		return webProviderDuckDuckGo
	}
	return webProviderNone
}

// webProvider picks the web-search provider for the given Tavily key and reports
// whether web search is available at all. Tavily is primary whenever its key is
// configured. With no key, the keyless DuckDuckGo fallback is used only when
// explicitly opted in via BLKCHAIN_WEB_FALLBACK, so a keyless install stays
// offline (ok=false) by default. The key flows through the apiKey argument the
// call site already passes (tavilyKey()), so selection needs no extra env read.
func webProvider(apiKey string) (webSearchFn, bool) {
	switch webProviderName(apiKey) {
	case webProviderTavily:
		return tavilySearch, true
	case webProviderDuckDuckGo:
		return duckDuckGoSearch, true
	default:
		return nil, false
	}
}

// activeWebProvider reports which web-search provider `blk ask` would use, by
// Tavily key and opt-in alone: "tavily", "duckduckgo", or "off". It is
// capability-only and does NOT fold in the /models web switch (opts.NoWeb /
// p.Web); the UI composes the final on/off from its own switch over this label.
// It reads the live Tavily key, so the reported provider tracks the environment.
func activeWebProvider() string {
	return webProviderName(tavilyKey())
}

// dispatchWebSearch is the default of the webSearch seam in rag.go. It routes
// each request to the provider webProvider picks for the given key, so the loop
// transparently uses Tavily when configured and the opted-in DuckDuckGo
// fallback otherwise. With no provider available it returns no results, and the
// loop falls through to its rewrite-and-re-retrieve path.
func dispatchWebSearch(ctx context.Context, apiKey, query string, maxResults int, includeDomains []string) ([]retrieval.Result, error) {
	provider, ok := webProvider(apiKey)
	if !ok {
		return nil, nil
	}
	return provider(ctx, apiKey, query, maxResults, includeDomains)
}

// --- DuckDuckGo keyless fallback ---

// ddgBaseURL is the DuckDuckGo Instant Answer API host. It is a fixed,
// hardcoded endpoint with no user-controlled component, so the fallback adds no
// SSRF surface: only the query string varies, and it is URL-encoded.
const ddgBaseURL = "https://api.duckduckgo.com"

// ddgMaxResponseBytes bounds how much of a DuckDuckGo response body is read, to
// avoid unbounded memory use on a misbehaving or malicious endpoint.
const ddgMaxResponseBytes = 10 << 20 // 10 MiB

// ddgRequestTimeout bounds a single DuckDuckGo request so a hung endpoint
// cannot hang `blk ask` indefinitely.
const ddgRequestTimeout = 20 * time.Second

// ddgDefaultMaxResults caps results when the caller passes a non-positive
// maxResults, so the fallback never returns an unbounded list.
const ddgDefaultMaxResults = 5

// ddgHTTPClient is the HTTP client for DuckDuckGo requests, with a bounded
// request timeout instead of http.DefaultClient's unbounded wait.
var ddgHTTPClient = &http.Client{Timeout: ddgRequestTimeout}

// ddgTopic is one Instant Answer related topic. The API nests topics: a leaf
// carries Text and FirstURL, while a category group carries nested Topics.
type ddgTopic struct {
	Text     string     `json:"Text"`
	FirstURL string     `json:"FirstURL"`
	Topics   []ddgTopic `json:"Topics"`
}

// ddgResponse is the subset of the DuckDuckGo Instant Answer response consumed.
type ddgResponse struct {
	Heading       string     `json:"Heading"`
	AbstractText  string     `json:"AbstractText"`
	AbstractURL   string     `json:"AbstractURL"`
	RelatedTopics []ddgTopic `json:"RelatedTopics"`
}

// duckDuckGoSearch queries the keyless DuckDuckGo Instant Answer API. The
// apiKey and includeDomains arguments satisfy the webSearchFn shape but are
// unused: DuckDuckGo needs no key, and the Instant Answer API has no domain
// filter.
func duckDuckGoSearch(ctx context.Context, _ string, query string, maxResults int, _ []string) ([]retrieval.Result, error) {
	return duckDuckGoSearchAt(ctx, ddgBaseURL, query, maxResults)
}

// duckDuckGoSearchAt GETs an Instant Answer request from baseURL and maps the
// hits to retrieval.Result tagged Source webSource, so the answer loop treats
// them exactly like Tavily results (untrusted external evidence). It reads at
// most ddgMaxResponseBytes and returns at most maxResults hits.
func duckDuckGoSearchAt(ctx context.Context, baseURL, query string, maxResults int) ([]retrieval.Result, error) {
	limit := maxResults
	if limit <= 0 {
		limit = ddgDefaultMaxResults
	}

	q := url.Values{}
	q.Set("q", query)
	q.Set("format", "json")
	q.Set("no_html", "1")
	q.Set("no_redirect", "1")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("duckduckgo: build request: %w", err)
	}

	resp, err := ddgHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("duckduckgo: request failed: %w", err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, ddgMaxResponseBytes)

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, limited)
		return nil, fmt.Errorf("duckduckgo: unexpected status %d", resp.StatusCode)
	}

	var parsed ddgResponse
	if err := json.NewDecoder(limited).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("duckduckgo: decode response: %w", err)
	}

	results := make([]retrieval.Result, 0, limit)
	add := func(title, link, text string) bool {
		if link == "" || len(results) >= limit {
			return len(results) < limit
		}
		results = append(results, retrieval.Result{
			ID: link,
			Payload: retrieval.Payload{
				Source:  webSource,
				Path:    link,
				Section: title,
				Type:    "doc",
				Text:    text,
			},
		})
		return len(results) < limit
	}

	// The abstract is the API's best single answer; map it first, then the
	// related topics (flattening the one level of nesting the API uses).
	if !add(parsed.Heading, parsed.AbstractURL, parsed.AbstractText) {
		return results, nil
	}
	if !ddgAppendTopics(parsed.RelatedTopics, add) {
		return results, nil
	}
	return results, nil
}

// ddgAppendTopics walks related topics (one level of nesting) and feeds each
// leaf to add. It returns false as soon as add reports the result cap is full,
// so the walk stops early.
func ddgAppendTopics(topics []ddgTopic, add func(title, link, text string) bool) bool {
	for _, t := range topics {
		if len(t.Topics) > 0 {
			if !ddgAppendTopics(t.Topics, add) {
				return false
			}
			continue
		}
		if !add(t.Text, t.FirstURL, t.Text) {
			return false
		}
	}
	return true
}
