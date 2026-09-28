package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"blkchain/cli/internal/retrieval"
)

// tavilyAPIKeyEnv is the environment variable holding the Tavily API key,
// matching the Python side's config.TAVILY_API_KEY_ENV / tavily_api_key().
const tavilyAPIKeyEnv = "TAVILY_SETUP_TOKEN"

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

// tavilyKey reads the Tavily API key from the same environment variable the
// Python engine uses (config.tavily_api_key()). It returns "" when unset so
// callers can skip web search entirely.
func tavilyKey() string {
	return os.Getenv(tavilyAPIKeyEnv)
}

// tavilySearch queries the live Tavily API.
func tavilySearch(ctx context.Context, apiKey, query string, maxResults int, includeDomains []string) ([]retrieval.Result, error) {
	return tavilySearchAt(ctx, "https://api.tavily.com", apiKey, query, maxResults, includeDomains)
}

// tavilySearchAt POSTs a search request to baseURL+"/search" and maps the
// Tavily hits to retrieval.Result, so the answer loop's web fallback can
// treat them like any other retrieval result (tagged Source: "web").
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
				Source:  "web",
				Path:    hit.URL,
				Section: hit.Title,
				Type:    "doc",
				Text:    hit.Content,
			},
		})
	}
	return results, nil
}
