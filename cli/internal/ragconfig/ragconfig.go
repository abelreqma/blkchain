// Package ragconfig loads the shared RAG configuration contract (rag.json),
// with environment overrides on top.
//
// Precedence: environment > blkchain/contract/rag.json (if found) > built-in
// fallback. The built-in fallback must always match rag.json byte-for-byte
// (enforced by TestBuiltinDefaultsMatchContractFile), so a standalone binary
// behaves identically to one run from inside the repo.
package ragconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config holds the RAG tunables. Field order and types mirror
// blkchain/contract/rag.json; the json tags let loadFromFile unmarshal rag.json
// directly onto a Config value, so keys absent from the file keep whatever the
// value already held (the built-in default) instead of zeroing out.
type Config struct {
	TopK                  int      `json:"top_k"`
	PoolSize              int      `json:"pool_size"`
	MaxLoops              int      `json:"max_loops"`
	AnswerMaxChunks       int      `json:"answer_max_chunks"`
	ContextCharsPerChunk  int      `json:"context_chars_per_chunk"`
	AnswerMaxTokens       int      `json:"answer_max_tokens"`
	GradeMaxTokens        int      `json:"grade_max_tokens"`
	SynthTemperature      float64  `json:"synth_temperature"`
	GradeTemperature      float64  `json:"grade_temperature"`
	RequestTimeoutSeconds int      `json:"request_timeout_seconds"`
	DefaultModel          string   `json:"default_model"`
	DenseVectorName       string   `json:"dense_vector_name"`
	SparseVectorName      string   `json:"sparse_vector_name"`
	SparseModel           string   `json:"sparse_model"`
	QdrantGRPCURL         string   `json:"qdrant_grpc_url"`
	EmbedServerURL        string   `json:"embed_server_url"`
	TavilyMaxResults      int      `json:"tavily_max_results"`
	ReputableDomains      []string `json:"reputable_domains"`
}

// contractRelPath is where rag.json lives relative to the project root.
const contractRelPath = "blkchain/contract/rag.json"

// builtinDefaults returns the compiled-in fallback values. These must stay in
// sync with blkchain/contract/rag.json; TestBuiltinDefaultsMatchContractFile
// enforces that.
func builtinDefaults() Config {
	return Config{
		TopK:                  5,
		PoolSize:              50,
		MaxLoops:              2,
		AnswerMaxChunks:       4,
		ContextCharsPerChunk:  1200,
		AnswerMaxTokens:       700,
		GradeMaxTokens:        200,
		SynthTemperature:      0.2,
		GradeTemperature:      0.0,
		RequestTimeoutSeconds: 300,
		DefaultModel:          "supergemma4-26b-uncensored-mlx-4bit-v2",
		DenseVectorName:       "dense",
		SparseVectorName:      "sparse",
		SparseModel:           "Qdrant/bm25",
		QdrantGRPCURL:         "127.0.0.1:6334",
		EmbedServerURL:        "http://127.0.0.1:8100",
		TavilyMaxResults:      5,
		ReputableDomains: []string{
			"nvd.nist.gov", "cve.mitre.org", "cwe.mitre.org", "attack.mitre.org",
			"owasp.org", "exploit-db.com", "portswigger.net",
		},
	}
}

// loadFromFile reads and parses rag.json at path into a Config. It unmarshals
// onto a copy of builtinDefaults() rather than a zero Config, so a key absent
// from the file (partial or hand-edited rag.json) keeps its built-in default
// instead of zeroing out.
func loadFromFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg := builtinDefaults()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// findContractFile locates blkchain/contract/rag.json by walking up from the
// resolved binary directory and from the working directory. It is
// self-contained (no import of package main) so ragconfig has no dependency
// on the cli binary's own root-finding logic; the walk pattern mirrors
// cli/paths.go's candidateRoots.
func findContractFile() (string, bool) {
	var starts []string
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		d := filepath.Dir(exe)
		starts = append(starts, filepath.Dir(d), d)
	}
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	for _, start := range starts {
		for dir := start; ; {
			candidate := filepath.Join(dir, contractRelPath)
			if _, err := os.Stat(candidate); err == nil {
				return candidate, true
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "", false
}

// envOverrides applies BLKCHAIN_*/OMLX_*/QDRANT_* environment variables onto
// cfg in place, ignoring unset or unparsable values.
func envOverrides(cfg *Config) {
	if v, ok := os.LookupEnv("BLKCHAIN_ANSWER_MAX_CHUNKS"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.AnswerMaxChunks = n
		}
	}
	if v, ok := os.LookupEnv("BLKCHAIN_CONTEXT_CHARS_PER_CHUNK"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.ContextCharsPerChunk = n
		}
	}
	if v, ok := os.LookupEnv("BLKCHAIN_ANSWER_MAX_TOKENS"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.AnswerMaxTokens = n
		}
	}
	if v, ok := os.LookupEnv("BLKCHAIN_GRADE_MAX_TOKENS"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.GradeMaxTokens = n
		}
	}
	if v, ok := os.LookupEnv("OMLX_MODEL"); ok && v != "" {
		cfg.DefaultModel = v
	}
	if v, ok := os.LookupEnv("BLKCHAIN_REPUTABLE_DOMAINS"); ok && v != "" {
		parts := strings.Split(v, ",")
		domains := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				domains = append(domains, p)
			}
		}
		if len(domains) > 0 {
			cfg.ReputableDomains = domains
		}
	}
	if v, ok := os.LookupEnv("QDRANT_GRPC_URL"); ok && v != "" {
		cfg.QdrantGRPCURL = v
	}
	if v, ok := os.LookupEnv("BLKCHAIN_TIMEOUT_SECONDS"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RequestTimeoutSeconds = n
		}
	}
}

// Load returns the effective Config: built-in defaults, overlaid by
// blkchain/contract/rag.json when found, overlaid by environment variables.
func Load() Config {
	cfg := builtinDefaults()
	if path, ok := findContractFile(); ok {
		if fromFile, err := loadFromFile(path); err == nil {
			cfg = fromFile
		}
	}
	envOverrides(&cfg)
	return cfg
}

// RequestTimeout is the bound on one search or answer turn. A value that is
// not positive falls back to the built-in default, so a turn is never
// unbounded.
func (c Config) RequestTimeout() time.Duration {
	if c.RequestTimeoutSeconds > 0 {
		return time.Duration(c.RequestTimeoutSeconds) * time.Second
	}
	return time.Duration(builtinDefaults().RequestTimeoutSeconds) * time.Second
}
