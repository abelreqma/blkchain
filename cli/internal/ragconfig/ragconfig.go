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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	SynthTopP             float64  `json:"synth_top_p"`
	SynthTopK             int      `json:"synth_top_k"`
	SynthPresencePenalty  float64  `json:"synth_presence_penalty"`
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
	RouteMaxTokens        int      `json:"route_max_tokens"`
	PocDomains            []string `json:"poc_domains"`
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
		AnswerMaxChunks:       6,
		ContextCharsPerChunk:  1200,
		AnswerMaxTokens:       1800,
		GradeMaxTokens:        200,
		SynthTemperature:      0.7,
		SynthTopP:             0.95,
		SynthTopK:             64,
		SynthPresencePenalty:  0.5,
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
		RouteMaxTokens: 8,
		PocDomains:     []string{"github.com", "exploit-db.com", "sploitus.com"},
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
// cfg in place, ignoring unset or unparsable values. An unparsable synthesis
// sampling value also writes a note.
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
	envFloat("BLKCHAIN_SYNTH_TEMPERATURE", &cfg.SynthTemperature)
	envFloat("BLKCHAIN_SYNTH_TOP_P", &cfg.SynthTopP)
	if v, ok := os.LookupEnv("BLKCHAIN_SYNTH_TOP_K"); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.SynthTopK = n
		} else {
			warnf("ignoring BLKCHAIN_SYNTH_TOP_K=%q: not a whole number", v)
		}
	}
	envFloat("BLKCHAIN_SYNTH_PRESENCE_PENALTY", &cfg.SynthPresencePenalty)
	if v, ok := os.LookupEnv("BLKCHAIN_ROUTE_MAX_TOKENS"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RouteMaxTokens = n
		}
	}
	if v, ok := os.LookupEnv("BLKCHAIN_POC_DOMAINS"); ok && v != "" {
		parts := strings.Split(v, ",")
		domains := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				domains = append(domains, p)
			}
		}
		if len(domains) > 0 {
			cfg.PocDomains = domains
		}
	}
}

// envFloat sets *dst from the float in environment variable name. An empty or
// unset variable is skipped; an unparsable one is ignored with a note.
func envFloat(name string, dst *float64) {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		warnf("ignoring %s=%q: not a number", name, v)
		return
	}
	*dst = f
}

// validateSampling replaces each synthesis sampling value that is out of range
// with its built-in default, with a note. NaN and Inf fail every range check.
func validateSampling(cfg *Config) {
	def := builtinDefaults()
	reset := func(key string, v *float64, ok bool, fallback float64) {
		if !ok {
			warnf("ignoring %s=%v: out of range, using %v", key, *v, fallback)
			*v = fallback
		}
	}
	c := *cfg
	reset("synth_temperature", &cfg.SynthTemperature,
		c.SynthTemperature >= 0 && c.SynthTemperature <= 2, def.SynthTemperature)
	reset("synth_top_p", &cfg.SynthTopP,
		c.SynthTopP > 0 && c.SynthTopP <= 1, def.SynthTopP)
	reset("synth_presence_penalty", &cfg.SynthPresencePenalty,
		c.SynthPresencePenalty >= -2 && c.SynthPresencePenalty <= 2, def.SynthPresencePenalty)
	if k := cfg.SynthTopK; k < 0 || k > 1000 {
		warnf("ignoring synth_top_k=%d: out of range, using %d", k, def.SynthTopK)
		cfg.SynthTopK = def.SynthTopK
	}
}

// validateInts replaces each bounded integer tunable that is out of range with
// its built-in default, with a note. These are caps: a non-positive value would
// either crash a turn (a negative chunk cap indexes results[:negative]) or make
// no sense, and an absurdly large one risks a duration overflow on the timeout.
// It covers both rag.json values and environment overrides, since Load calls it
// after both are applied.
func validateInts(cfg *Config) {
	def := builtinDefaults()
	check := func(key string, v *int, lo, hi, fallback int) {
		if *v < lo || *v > hi {
			// The value may have come from the env var key or from rag.json;
			// name both so the note is not misleading for a bad file value.
			warnf("ignoring %s=%d (env or rag.json): out of range [%d,%d], using %d", key, *v, lo, hi, fallback)
			*v = fallback
		}
	}
	check("BLKCHAIN_ANSWER_MAX_CHUNKS", &cfg.AnswerMaxChunks, 1, 1000, def.AnswerMaxChunks)
	check("BLKCHAIN_CONTEXT_CHARS_PER_CHUNK", &cfg.ContextCharsPerChunk, 1, 1_000_000, def.ContextCharsPerChunk)
	check("BLKCHAIN_ANSWER_MAX_TOKENS", &cfg.AnswerMaxTokens, 1, 1_000_000, def.AnswerMaxTokens)
	check("BLKCHAIN_GRADE_MAX_TOKENS", &cfg.GradeMaxTokens, 1, 1_000_000, def.GradeMaxTokens)
	check("BLKCHAIN_TIMEOUT_SECONDS", &cfg.RequestTimeoutSeconds, 1, 86_400, def.RequestTimeoutSeconds)
	check("BLKCHAIN_ROUTE_MAX_TOKENS", &cfg.RouteMaxTokens, 1, 1_000_000, def.RouteMaxTokens)
}

// warnOut receives the load notes; tests swap it.
var warnOut io.Writer = os.Stderr

var (
	warnMu sync.Mutex
	warned = map[string]bool{}
)

// warnf writes one note line to warnOut, once per process for each distinct
// line, since the config is loaded more than once per run.
func warnf(format string, args ...any) {
	line := "blk: " + fmt.Sprintf(format, args...)
	warnMu.Lock()
	defer warnMu.Unlock()
	if warned[line] {
		return
	}
	warned[line] = true
	fmt.Fprintln(warnOut, line)
}

// loadContract reads rag.json at path. On success it returns the parsed Config
// and ok=true. On a read or parse failure it writes one note naming the file
// and returns the built-in defaults with ok=false, so a malformed or unreadable
// contract falls back visibly instead of being silently discarded.
func loadContract(path string) (Config, bool) {
	cfg, err := loadFromFile(path)
	if err != nil {
		warnf("ignoring rag.json at %s: %v; using built-in defaults", path, err)
		return builtinDefaults(), false
	}
	return cfg, true
}

// Load returns the effective Config: built-in defaults, overlaid by
// blkchain/contract/rag.json when found, overlaid by environment variables,
// with any out-of-range sampling value reset to its default.
func Load() Config {
	cfg := builtinDefaults()
	if path, ok := findContractFile(); ok {
		if fromFile, loaded := loadContract(path); loaded {
			cfg = fromFile
		}
	}
	envOverrides(&cfg)
	validateSampling(&cfg)
	validateInts(&cfg)
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
