// Package modeleval probes the running local models (chat, embed, rerank) for
// readiness and live performance. It is presentation-free: no theme, no
// package main import, so every probe and metric is unit-testable against an
// httptest server. Rendering lives in package main (cli/models.go).
package modeleval

import (
	"net/http"
	"time"
)

// ModelKind identifies one of the three local models.
type ModelKind int

const (
	KindChat ModelKind = iota
	KindEmbed
	KindRerank
)

func (k ModelKind) String() string {
	switch k {
	case KindChat:
		return "chat"
	case KindEmbed:
		return "embed"
	case KindRerank:
		return "rerank"
	default:
		return "unknown"
	}
}

// Config carries everything the probes need. URLs and creds are resolved by the
// caller (package main) from env; HTTPClient is injectable for tests.
type Config struct {
	ChatBaseURL    string // e.g. http://127.0.0.1:8000/v1
	ChatAPIKey     string
	ChatModel      string // "" -> discover via GET {ChatBaseURL}/models
	EmbedHealthURL string // e.g. http://127.0.0.1:8100/health
	EmbedURL       string // e.g. http://127.0.0.1:8100/embed
	RerankURL      string // e.g. http://127.0.0.1:8100/rerank
	ReadyTimeout   time.Duration
	ProbeTimeout   time.Duration
	HTTPClient     *http.Client
}

// PerfResult holds the perf-phase measurements. Only the fields relevant to the
// probed kind are set (chat: TTFT/GenTokens/GenDuration/TokensPerSec/
// UsageReported/ModelID; embed: Dim/MsPerVector; rerank: PoolSize/Ms/NonFinite/
// OutOfRange).
type PerfResult struct {
	ModelID       string
	TTFT          time.Duration
	GenDuration   time.Duration
	GenTokens     int
	TokensPerSec  float64
	UsageReported bool
	Dim           int
	MsPerVector   float64
	PoolSize      int
	Ms            float64
	NonFinite     int
	OutOfRange    int
}

// ModelReport is one model's full result: readiness, its elapsed ready time, the
// perf result (nil if the perf phase did not run), and any error.
type ModelReport struct {
	Kind         ModelKind
	Ready        bool
	ReadyElapsed time.Duration
	Perf         *PerfResult
	Err          error
}

// httpClient returns the configured client or a default with ProbeTimeout.
func (c Config) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: c.ProbeTimeout}
}
