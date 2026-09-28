// Package client is a thin HTTP client for the blkChain RAG API.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// defaultBaseURL is used when BLKCHAIN_API_URL is not set.
const defaultBaseURL = "http://127.0.0.1:8200"

// maxResponseBytes bounds how much of a response body we will read.
const maxResponseBytes = 10 << 20 // 10 MiB

// defaultTimeout is generous because `ask` waits on local LLM synthesis, which
// is slow on a memory-constrained machine. Override with BLKCHAIN_TIMEOUT_SECONDS.
const defaultTimeout = 300 * time.Second

// requestTimeout resolves the per-request timeout from BLKCHAIN_TIMEOUT_SECONDS
// (a positive integer number of seconds), falling back to defaultTimeout.
func requestTimeout() time.Duration {
	if v := os.Getenv("BLKCHAIN_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return defaultTimeout
}

// Client is a thin HTTP client over the blkChain API.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient builds a Client using BLKCHAIN_API_URL, falling back to the
// documented default. This is the only place that reads the env var.
func NewClient() *Client {
	base := os.Getenv("BLKCHAIN_API_URL")
	if base == "" {
		base = defaultBaseURL
	}
	return &Client{
		BaseURL:    base,
		HTTPClient: &http.Client{Timeout: requestTimeout()},
	}
}

// UnreachableError indicates the API could not be reached at all.
type UnreachableError struct {
	URL string
}

func (e *UnreachableError) Error() string {
	return fmt.Sprintf("blkChain API not reachable at %s — is it running?", e.URL)
}

// HealthResponse is the response body of GET /health. The API reports not just
// its own liveness but whether each dependency answered, so a caller can tell
// "up" from "up but /search would 500".
type HealthResponse struct {
	Status      string `json:"status"`
	Qdrant      bool   `json:"qdrant"`
	EmbedServer bool   `json:"embed_server"`
}

// Payload describes a search result's underlying document chunk.
type Payload struct {
	Source  string `json:"source"`
	Path    string `json:"path"`
	Section string `json:"section"`
	Type    string `json:"type"`
	Text    string `json:"text"`
}

// SearchResult is a single ranked result from POST /search.
type SearchResult struct {
	ID      string  `json:"id"`
	Score   float64 `json:"score"`
	Payload Payload `json:"payload"`
}

// SearchRequest is the request body of POST /search.
type SearchRequest struct {
	Query   string                 `json:"query"`
	TopK    int                    `json:"top_k,omitempty"`
	Filters map[string]interface{} `json:"filters,omitempty"`
}

// SearchResponse is the response body of POST /search.
type SearchResponse struct {
	Results []SearchResult `json:"results"`
}

// Citation is a single source citation from POST /answer.
type Citation struct {
	Source  string `json:"source"`
	Path    string `json:"path"`
	Section string `json:"section"`
}

// AnswerRequest is the request body of POST /answer.
type AnswerRequest struct {
	Query string `json:"query"`
}

// AnswerResponse is the response body of POST /answer. Results carries the
// retrieved chunks the answer was synthesized from, so callers can show the
// evidence behind an answer, not just the citation list.
type AnswerResponse struct {
	Answer    string         `json:"answer"`
	Citations []Citation     `json:"citations"`
	UsedWeb   bool           `json:"used_web"`
	Results   []SearchResult `json:"results,omitempty"`
}

// Health calls GET /health.
func (c *Client) Health() (*HealthResponse, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/health", nil)
	if err != nil {
		return nil, err
	}
	var out HealthResponse
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Search calls POST /search.
func (c *Client) Search(query string, topK int, filters map[string]interface{}) (*SearchResponse, error) {
	body, err := json.Marshal(SearchRequest{Query: query, TopK: topK, Filters: filters})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/search", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	var out SearchResponse
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Answer calls POST /answer.
func (c *Client) Answer(query string) (*AnswerResponse, error) {
	body, err := json.Marshal(AnswerRequest{Query: query})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/answer", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	var out AnswerResponse
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// do executes req and decodes a JSON response into out. Connection-level
// failures are reported as *UnreachableError.
func (c *Client) do(req *http.Request, out interface{}) error {
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return &UnreachableError{URL: c.BaseURL}
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("reading response from %s: %w", req.URL, err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("blkChain API returned %s: %s", resp.Status, string(data))
	}

	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decoding response from %s: %w", req.URL, err)
	}
	return nil
}
