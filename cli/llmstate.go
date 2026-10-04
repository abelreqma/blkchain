package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/structgen"
	"github.com/tmc/langchaingo/callbacks"
	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/cache"
	"github.com/tmc/langchaingo/llms/openai"
)

type llmCallStats struct {
	Stage            string `json:"stage"`
	Model            string `json:"model"`
	ModelTruncated   bool   `json:"model_truncated,omitempty"`
	Status           string `json:"status"`
	Cached           bool   `json:"cached"`
	DurationMS       int64  `json:"duration_ms"`
	UsageReported    bool   `json:"usage_reported"`
	PromptTokens     int    `json:"prompt_tokens,omitempty"`
	CompletionTokens int    `json:"completion_tokens,omitempty"`
}

type callMetrics struct {
	mu      sync.Mutex
	calls   []llmCallStats
	partial bool
}

type metricsKey struct{}
type stageKey struct{}
type callStateKey struct{}

func withCallMetrics(ctx context.Context) (context.Context, *callMetrics) {
	metrics := &callMetrics{}
	return context.WithValue(ctx, metricsKey{}, metrics), metrics
}

func (m *callMetrics) snapshot() ([]llmCallStats, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]llmCallStats(nil), m.calls...), m.partial
}

func withLLMStage(ctx context.Context, stage string) context.Context {
	return context.WithValue(ctx, stageKey{}, stage)
}

type llmCallState struct {
	stats     llmCallStats
	started   time.Time
	namespace string
}

type usageCallback struct{ callbacks.SimpleHandler }

func (usageCallback) HandleLLMGenerateContentEnd(ctx context.Context, response *llms.ContentResponse) {
	state, _ := ctx.Value(callStateKey{}).(*llmCallState)
	if state == nil || response == nil || len(response.Choices) == 0 || response.Choices[0] == nil {
		return
	}
	info := response.Choices[0].GenerationInfo
	prompt, completion := asInt(info["PromptTokens"]), asInt(info["CompletionTokens"])
	if prompt >= 0 && completion >= 0 && (prompt > 0 || completion > 0) {
		state.stats.UsageReported = true
		state.stats.PromptTokens, state.stats.CompletionTokens = prompt, completion
	}
}

type llmClient struct {
	raw       *openai.LLM
	cached    *cache.Cacher
	cfg       ragconfig.Config
	model     string
	namespace string
}

func (m *llmClient) Call(ctx context.Context, prompt string, opts ...llms.CallOption) (string, error) {
	return llms.GenerateFromSinglePrompt(ctx, m, prompt, opts...)
}

func (m *llmClient) ForSchema(s structgen.Schema) (structgen.Generator, error) {
	format, err := s.ResponseFormat()
	if err != nil {
		return nil, err
	}
	return newOMLXFormat(m.cfg, m.model, format)
}

func (m *llmClient) GenerateContent(ctx context.Context, msgs []llms.MessageContent, options ...llms.CallOption) (response *llms.ContentResponse, err error) {
	opts := append([]llms.CallOption{llms.WithModel(m.model)}, options...)
	var settings llms.CallOptions
	for _, opt := range opts {
		opt(&settings)
	}
	stage, _ := ctx.Value(stageKey{}).(string)
	if stage == "" {
		stage = "generation"
	}
	samp, _ := ctx.Value(samplingKey{}).(sampling)
	ns, namespaceErr := json.Marshal(struct {
		Namespace, Model, Stage string
		Thinking                bool
		TopP                    float64
		TopK                    int
	}{m.namespace, settings.Model, stage, os.Getenv("BLK_ENABLE_THINKING") == "1", samp.topP, samp.topK})
	sum := sha256.Sum256(ns)
	requestedModel := settings.Model
	if requestedModel == "" {
		requestedModel = m.model
	}
	reportedModel := capRunes(requestedModel, 256)
	state := &llmCallState{stats: llmCallStats{Stage: stage, Model: reportedModel, ModelTruncated: reportedModel != requestedModel, Status: "ok"}, started: time.Now(), namespace: hex.EncodeToString(sum[:])}
	ctx = context.WithValue(ctx, callStateKey{}, state)
	defer func() {
		state.stats.DurationMS = time.Since(state.started).Milliseconds()
		if err != nil {
			state.stats.Status = "error"
			if errors.Is(err, context.Canceled) {
				state.stats.Status = "canceled"
			}
			if errors.Is(err, context.DeadlineExceeded) {
				state.stats.Status = "timeout"
			}
		}
		if state.stats.Cached {
			state.stats.UsageReported = false
			state.stats.PromptTokens = 0
			state.stats.CompletionTokens = 0
		}
		if response != nil && len(response.Choices) > 0 && response.Choices[0] != nil {
			if response.Choices[0].GenerationInfo == nil {
				response.Choices[0].GenerationInfo = map[string]any{}
			}
			response.Choices[0].GenerationInfo["CallStats"] = state.stats
		}
		if metrics, _ := ctx.Value(metricsKey{}).(*callMetrics); metrics != nil {
			metrics.mu.Lock()
			if len(metrics.calls) < 64 {
				metrics.calls = append(metrics.calls, state.stats)
			} else {
				metrics.partial = true
			}
			metrics.mu.Unlock()
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if namespaceErr == nil && (stage == "routing" || stage == "grading") && settings.Temperature == 0 && settings.StreamingFunc == nil && len(settings.Tools) == 0 && len(settings.Functions) == 0 {
		return m.cached.GenerateContent(ctx, msgs, opts...)
	}
	return m.raw.GenerateContent(ctx, msgs, opts...)
}

type decisionEntry struct {
	data    []byte
	expires time.Time
	used    uint64
}

type decisionResponses struct {
	mu      sync.Mutex
	entries map[string]decisionEntry
	bytes   int
	clock   uint64
}

var sharedDecisions = &decisionResponses{entries: map[string]decisionEntry{}}

func (c *decisionResponses) Get(ctx context.Context, key string) *llms.ContentResponse {
	state, _ := ctx.Value(callStateKey{}).(*llmCallState)
	if state == nil || ctx.Err() != nil {
		return nil
	}
	key = state.namespace + key
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}
	if !time.Now().Before(entry.expires) {
		c.bytes -= len(entry.data)
		delete(c.entries, key)
		return nil
	}
	var response llms.ContentResponse
	if json.Unmarshal(entry.data, &response) != nil {
		return nil
	}
	c.clock++
	entry.used = c.clock
	c.entries[key] = entry
	for _, choice := range response.Choices {
		if choice != nil {
			choice.GenerationInfo = nil
		}
	}
	state.stats.Cached = true
	return &response
}

func (c *decisionResponses) Put(ctx context.Context, key string, response *llms.ContentResponse) {
	state, _ := ctx.Value(callStateKey{}).(*llmCallState)
	if state == nil || ctx.Err() != nil || !cacheableDecision(state.stats.Stage, response) {
		return
	}
	data, err := json.Marshal(response)
	if err != nil || len(data) > 32<<10 {
		return
	}
	key = state.namespace + key
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, e := range c.entries {
		if !now.Before(e.expires) {
			c.bytes -= len(e.data)
			delete(c.entries, k)
		}
	}
	if prior, ok := c.entries[key]; ok {
		c.bytes -= len(prior.data)
		delete(c.entries, key)
	}
	for len(c.entries) >= 128 || c.bytes+len(data) > 2<<20 {
		oldest := ""
		var stamp uint64
		for k, e := range c.entries {
			if oldest == "" || e.used < stamp {
				oldest, stamp = k, e.used
			}
		}
		c.bytes -= len(c.entries[oldest].data)
		delete(c.entries, oldest)
	}
	c.clock++
	c.entries[key] = decisionEntry{data: data, expires: now.Add(5 * time.Minute), used: c.clock}
	c.bytes += len(data)
}

func cacheableDecision(stage string, r *llms.ContentResponse) bool {
	if r == nil || len(r.Choices) != 1 || r.Choices[0] == nil {
		return false
	}
	choice := r.Choices[0]
	if choice.StopReason != "stop" || len(choice.ToolCalls) > 0 || choice.FuncCall != nil {
		return false
	}
	if stage == "routing" {
		switch strings.ToUpper(strings.TrimSpace(choice.Content)) {
		case "GROUND", "SKIP", "ADVISE":
			return true
		}
		return false
	}
	var verdict struct {
		Sufficient *bool   `json:"sufficient"`
		Rewrite    *string `json:"rewrite"`
		UseWeb     *bool   `json:"use_web"`
	}
	return stage == "grading" && json.Unmarshal([]byte(choice.Content), &verdict) == nil && verdict.Sufficient != nil && verdict.Rewrite != nil && verdict.UseWeb != nil
}
