package retrieval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// maxResponseBytes bounds how much of an embed_server response body we will
// read, the same as the server's default 32 MiB body cap.
const maxResponseBytes = 32 << 20 // 32 MiB

// maxErrorBodyBytes is how much of a failed response's body an error quotes.
const maxErrorBodyBytes = 512

// httpClient is shared across embed/rerank calls. It carries no fixed Timeout:
// a whole-client cap would override the configured request_timeout_seconds and
// silently cut a slow call at 60s. Every call runs under a context deadline
// (Search derives one from cfg.RequestTimeout when the caller set none), so the
// context is the only bound.
var httpClient = &http.Client{}

// embedRequest is the request body of embed_server's POST /embed.
type embedRequest struct {
	Texts []string `json:"texts"`
}

// embedResponse is the response body of embed_server's POST /embed.
type embedResponse struct {
	Embeddings [][]float32 `json:"embeddings"`
	Dim        int         `json:"dim"`
}

// rerankRequest is the request body of embed_server's POST /rerank.
type rerankRequest struct {
	Query     string   `json:"query"`
	Documents []string `json:"documents"`
}

// rerankResponse is the response body of embed_server's POST /rerank.
type rerankResponse struct {
	Scores []*float64 `json:"scores"`
}

// embedQuery embeds a single query string via embed_server's POST /embed and
// returns its embedding vector.
func embedQuery(ctx context.Context, embedURL, query string) ([]float32, error) {
	body, err := json.Marshal(embedRequest{Texts: []string{query}})
	if err != nil {
		return nil, fmt.Errorf("marshaling embed request: %w", err)
	}

	var out embedResponse
	if err := postJSON(ctx, embedURL+"/embed", body, &out); err != nil {
		return nil, err
	}
	if len(out.Embeddings) == 0 {
		return nil, fmt.Errorf("embed_server returned no embeddings for query")
	}
	return out.Embeddings[0], nil
}

// rerank scores docs against query via embed_server's POST /rerank.
func rerank(ctx context.Context, embedURL, query string, docs []string) ([]float64, error) {
	body, err := json.Marshal(rerankRequest{Query: query, Documents: docs})
	if err != nil {
		return nil, fmt.Errorf("marshaling rerank request: %w", err)
	}

	var out rerankResponse
	if err := postJSON(ctx, embedURL+"/rerank", body, &out); err != nil {
		return nil, err
	}
	scores := make([]float64, len(out.Scores))
	for i, score := range out.Scores {
		scores[i] = -1
		if score != nil {
			scores[i] = *score
		}
	}
	return scores, nil
}

// postJSON POSTs body as application/json to url and decodes the JSON
// response into out. It honors ctx cancellation and bounds the response body.
func postJSON(ctx context.Context, url string, body []byte, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request to %s: %w", url, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling %s: %w", url, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("reading response from %s: %w", url, err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s: %s", url, resp.Status, string(data[:min(len(data), maxErrorBodyBytes)]))
	}

	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decoding response from %s: %w", url, err)
	}
	return nil
}
