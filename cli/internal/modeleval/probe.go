package modeleval

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// errUnreachable is the shared "the stack is down" error, in the existing CLI
// voice (see client.UnreachableError / `blk up`).
var errUnreachable = errors.New("unreachable — try `blk up`")

// ErrUnreachable returns the shared unreachable error for callers that render it.
func ErrUnreachable() error { return errUnreachable }

// waitReady polls GET url until it returns a 2xx or the timeout elapses,
// returning the elapsed time to ready. It returns errUnreachable if the timeout
// is reached without a 2xx. This is the readiness phase; the perf-phase timeout
// clock starts only after this returns nil.
func waitReady(ctx context.Context, client *http.Client, url string, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	deadline := start.Add(timeout)
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				return time.Since(start), nil
			}
		}
		if time.Now().After(deadline) {
			return time.Since(start), errUnreachable
		}
		select {
		case <-ctx.Done():
			return time.Since(start), ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
}

// postJSON sends body as JSON to url and decodes the response into out. It is
// the small shared POST helper for the embed/rerank/chat probes.
func postJSON(ctx context.Context, client *http.Client, url string, body any, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

// ProbeEmbed runs the embed model's readiness then perf phase. Perf: one timed
// embed of a fixed short text; asserts dim==1024 (the collection's dimension).
func ProbeEmbed(ctx context.Context, cfg Config) ModelReport {
	rep := ModelReport{Kind: KindEmbed}
	client := cfg.httpClient()

	elapsed, err := waitReady(ctx, client, cfg.EmbedHealthURL, cfg.ReadyTimeout)
	rep.ReadyElapsed = elapsed
	if err != nil {
		rep.Err = err
		return rep
	}
	rep.Ready = true

	// perf phase: timeout clock starts now.
	pctx, cancel := context.WithTimeout(ctx, cfg.ProbeTimeout)
	defer cancel()
	var out struct {
		Embeddings [][]float64 `json:"embeddings"`
		Dim        int         `json:"dim"`
	}
	start := time.Now()
	if err := postJSON(pctx, client, cfg.EmbedURL, map[string]any{"texts": []string{"readiness probe sentence"}}, &out); err != nil {
		rep.Err = fmt.Errorf("probe: %w", err)
		return rep
	}
	ms := float64(time.Since(start).Microseconds()) / 1000.0
	dim := out.Dim
	if dim == 0 && len(out.Embeddings) > 0 {
		dim = len(out.Embeddings[0])
	}
	rep.Perf = &PerfResult{Dim: dim, MsPerVector: ms}
	if dim != 1024 {
		rep.Err = fmt.Errorf("embed dim %d, expected 1024 (model mismatch?)", dim)
	}
	return rep
}

// ProbeRerank runs the rerank model's readiness then perf phase. Perf: one timed
// rerank of a fixed small pool; runs the score-sanity check (non-finite /
// out-of-range) so the SP-1 defect is visible.
func ProbeRerank(ctx context.Context, cfg Config) ModelReport {
	rep := ModelReport{Kind: KindRerank}
	client := cfg.httpClient()

	elapsed, err := waitReady(ctx, client, cfg.EmbedHealthURL, cfg.ReadyTimeout)
	rep.ReadyElapsed = elapsed
	if err != nil {
		rep.Err = err
		return rep
	}
	rep.Ready = true

	pctx, cancel := context.WithTimeout(ctx, cfg.ProbeTimeout)
	defer cancel()
	docs := []string{
		"SSRF to cloud metadata endpoint 169.254.169.254",
		"SQL injection via UNION SELECT",
		"cross-site scripting in a search field",
		"path traversal with ../ sequences",
		"open redirect via unvalidated next parameter",
	}
	var out struct {
		Scores []*float64 `json:"scores"`
	}
	start := time.Now()
	if err := postJSON(pctx, client, cfg.RerankURL, map[string]any{"query": "server-side request forgery", "documents": docs}, &out); err != nil {
		rep.Err = fmt.Errorf("probe: %w", err)
		return rep
	}
	ms := float64(time.Since(start).Microseconds()) / 1000.0
	nf, oor := ScoreSanity(out.Scores)
	rep.Perf = &PerfResult{PoolSize: len(docs), Ms: ms, NonFinite: nf, OutOfRange: oor}
	return rep
}

// discoverChatModel returns the first model id from GET {baseURL}/models, or ""
// on any failure (the caller then uses cfg.ChatModel or a default label).
func discoverChatModel(ctx context.Context, client *http.Client, baseURL, apiKey string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/models", nil)
	if err != nil {
		return ""
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out) == nil && len(out.Data) > 0 {
		return out.Data[0].ID
	}
	return ""
}

// ProbeChat runs the chat model's readiness (GET /models) then a streamed perf
// probe. tokens/sec is computed from actual generated tokens: the server's
// reported usage.completion_tokens when present, else a count of streamed
// content deltas (marked UsageReported=false). TTFT is time to the first
// content delta.
func ProbeChat(ctx context.Context, cfg Config) ModelReport {
	rep := ModelReport{Kind: KindChat}
	client := cfg.httpClient()

	readyURL := strings.TrimRight(cfg.ChatBaseURL, "/") + "/models"
	elapsed, err := waitReady(ctx, client, readyURL, cfg.ReadyTimeout)
	rep.ReadyElapsed = elapsed
	if err != nil {
		rep.Err = err
		return rep
	}
	rep.Ready = true

	model := cfg.ChatModel
	if model == "" {
		model = discoverChatModel(ctx, client, cfg.ChatBaseURL, cfg.ChatAPIKey)
	}

	pctx, cancel := context.WithTimeout(ctx, cfg.ProbeTimeout)
	defer cancel()

	body := map[string]any{
		"model":          model,
		"messages":       []map[string]string{{"role": "user", "content": "In one short sentence, name a common web vulnerability."}},
		"max_tokens":     64,
		"temperature":    0,
		"stream":         true,
		"stream_options": map[string]any{"include_usage": true},
		// mirror llm.go: keep the model out of a runaway reasoning channel.
		"chat_template_kwargs": map[string]any{"enable_thinking": false},
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(pctx, http.MethodPost, strings.TrimRight(cfg.ChatBaseURL, "/")+"/chat/completions", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if cfg.ChatAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.ChatAPIKey)
	}
	probeStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		rep.Err = fmt.Errorf("probe: %w", err)
		return rep
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		rep.Err = fmt.Errorf("probe: status %d", resp.StatusCode)
		return rep
	}

	perf := &PerfResult{ModelID: model}
	var firstAt, lastAt time.Time
	deltaCount := 0
	usageTokens := 0

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			break
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
			Usage *struct {
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal([]byte(data), &chunk) != nil {
			continue
		}
		if chunk.Usage != nil && chunk.Usage.CompletionTokens > 0 {
			usageTokens = chunk.Usage.CompletionTokens
		}
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			now := time.Now()
			if firstAt.IsZero() {
				firstAt = now
			}
			lastAt = now
			deltaCount++
		}
	}
	if firstAt.IsZero() {
		rep.Err = fmt.Errorf("probe: no tokens generated within %s", cfg.ProbeTimeout)
		return rep
	}
	perf.TTFT = firstAt.Sub(probeStart)
	perf.GenDuration = lastAt.Sub(firstAt)
	if usageTokens > 0 {
		perf.GenTokens = usageTokens
		perf.UsageReported = true
	} else {
		perf.GenTokens = deltaCount
		perf.UsageReported = false
	}
	perf.TokensPerSec = TokensPerSec(perf.GenTokens, perf.GenDuration)
	rep.Perf = perf
	return rep
}
