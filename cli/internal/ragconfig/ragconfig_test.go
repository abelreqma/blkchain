package ragconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBuiltinDefaultsMatchContractFile(t *testing.T) {
	// The built-in fallback must equal the committed rag.json so a standalone
	// binary behaves identically to one run from the repo.
	//
	// Config.ReputableDomains is a []string, so the struct is not comparable
	// with == (Go rejects that at compile time); reflect.DeepEqual is the
	// equivalent field-by-field check.
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("repo root not found")
	}
	fromFile, err := loadFromFile(filepath.Join(root, "blkchain", "contract", "rag.json"))
	if err != nil {
		t.Fatalf("load rag.json: %v", err)
	}
	if !reflect.DeepEqual(fromFile, builtinDefaults()) {
		t.Errorf("builtin defaults drifted from rag.json:\n file=%+v\n code=%+v", fromFile, builtinDefaults())
	}
}

func TestLoadFromFilePartialFallsBackToDefaults(t *testing.T) {
	// A rag.json missing keys (hand-edited, or a future field code doesn't
	// know about yet) must not zero out those fields: loadFromFile should
	// overlay the file onto builtinDefaults(), not a zero Config.
	dir := t.TempDir()
	path := filepath.Join(dir, "rag.json")
	if err := os.WriteFile(path, []byte(`{"top_k": 7}`), 0o644); err != nil {
		t.Fatalf("write temp rag.json: %v", err)
	}
	cfg, err := loadFromFile(path)
	if err != nil {
		t.Fatalf("loadFromFile: %v", err)
	}
	want := builtinDefaults()
	if cfg.TopK != 7 {
		t.Errorf("TopK: got %d want 7 (from file)", cfg.TopK)
	}
	if cfg.PoolSize != want.PoolSize {
		t.Errorf("PoolSize: got %d want %d (builtin default, absent from file)", cfg.PoolSize, want.PoolSize)
	}
	if cfg.DefaultModel != want.DefaultModel {
		t.Errorf("DefaultModel: got %q want %q (builtin default, absent from file)", cfg.DefaultModel, want.DefaultModel)
	}
}

func TestEnvOverridesFileAndDefault(t *testing.T) {
	t.Setenv("BLKCHAIN_ANSWER_MAX_CHUNKS", "9")
	c := Load()
	if c.AnswerMaxChunks != 9 {
		t.Errorf("env override not applied: got %d want 9", c.AnswerMaxChunks)
	}
}

func TestEmbeddingHostPortOverrideRetrievalURL(t *testing.T) {
	for _, tc := range []struct {
		host, port, want string
	}{
		{"localhost", "8199", "http://localhost:8199"},
		{"127.0.0.1", "8198", "http://127.0.0.1:8198"},
		{"", "8197", "http://127.0.0.1:8197"},
		{"localhost", "", "http://localhost:8100"},
		{"::1", "8196", "http://[::1]:8196"},
		{"localhost", "99999", "http://localhost:8100"},
		{"localhost", "bad", "http://localhost:8100"},
	} {
		t.Run(tc.host+":"+tc.port, func(t *testing.T) {
			t.Setenv("BLKCHAIN_EMBED_HOST", tc.host)
			t.Setenv("BLKCHAIN_EMBED_PORT", tc.port)
			if got := Load().EmbedServerURL; got != tc.want {
				t.Fatalf("embedding URL = %q; want %q", got, tc.want)
			}
		})
	}
}

// repoRootForTest walks up to the dir containing blkchain/contract/rag.json.
func repoRootForTest() (string, error) {
	d, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(d, "blkchain", "contract", "rag.json")); err == nil {
			return d, nil
		}
		p := filepath.Dir(d)
		if p == d {
			return "", os.ErrNotExist
		}
		d = p
	}
}

// intField reads one of the six clamped integer fields of c by its env-var name.
func intField(c Config, env string) int {
	switch env {
	case "BLKCHAIN_ANSWER_MAX_CHUNKS":
		return c.AnswerMaxChunks
	case "BLKCHAIN_CONTEXT_CHARS_PER_CHUNK":
		return c.ContextCharsPerChunk
	case "BLKCHAIN_ANSWER_MAX_TOKENS":
		return c.AnswerMaxTokens
	case "BLKCHAIN_GRADE_MAX_TOKENS":
		return c.GradeMaxTokens
	case "BLKCHAIN_TIMEOUT_SECONDS":
		return c.RequestTimeoutSeconds
	case "BLKCHAIN_ROUTE_MAX_TOKENS":
		return c.RouteMaxTokens
	}
	return 0
}

// defaultIntField is intField over builtinDefaults().
func defaultIntField(env string) int { return intField(builtinDefaults(), env) }

// A non-positive or absurdly large integer env override cannot reach a turn: it
// is rejected with one note and the built-in default stands. This closes the
// crash where a negative AnswerMaxChunks indexed results[:negative].
func TestIntEnvOverridesAreValidated(t *testing.T) {
	envs := []string{
		"BLKCHAIN_ANSWER_MAX_CHUNKS",
		"BLKCHAIN_CONTEXT_CHARS_PER_CHUNK",
		"BLKCHAIN_ANSWER_MAX_TOKENS",
		"BLKCHAIN_GRADE_MAX_TOKENS",
		"BLKCHAIN_TIMEOUT_SECONDS",
		"BLKCHAIN_ROUTE_MAX_TOKENS",
	}
	for _, env := range envs {
		for _, bad := range []string{"0", "-1", "999999999999"} {
			t.Run(env+"="+bad, func(t *testing.T) {
				warn := captureWarnings(t)
				t.Setenv(env, bad)
				c := Load()
				if got, want := intField(c, env), defaultIntField(env); got != want {
					t.Errorf("%s=%s: field = %d, want the default %d", env, bad, got, want)
				}
				assertOneNote(t, warn, env)
			})
		}
	}
}

// A valid integer env override in range is applied, with no note.
func TestIntEnvOverrideInRangeApplied(t *testing.T) {
	warn := captureWarnings(t)
	t.Setenv("BLKCHAIN_ANSWER_MAX_CHUNKS", "7")
	t.Setenv("BLKCHAIN_TIMEOUT_SECONDS", "45")
	c := Load()
	if c.AnswerMaxChunks != 7 {
		t.Errorf("AnswerMaxChunks = %d, want 7", c.AnswerMaxChunks)
	}
	if c.RequestTimeoutSeconds != 45 {
		t.Errorf("RequestTimeoutSeconds = %d, want 45", c.RequestTimeoutSeconds)
	}
	if warn.Len() != 0 {
		t.Errorf("valid values wrote a note: %q", warn.String())
	}
}

// A malformed rag.json is not silently discarded: loadContract writes one note
// naming the file and returns ok=false so the caller keeps its built-in
// defaults visibly, not silently.
func TestLoadContractMalformedWarnsAndFallsBack(t *testing.T) {
	warn := captureWarnings(t)
	path := filepath.Join(t.TempDir(), "rag.json")
	if err := os.WriteFile(path, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, ok := loadContract(path)
	if ok {
		t.Error("malformed rag.json reported ok=true, want false")
	}
	if !reflect.DeepEqual(cfg, builtinDefaults()) {
		t.Error("fallback is not the built-in defaults")
	}
	assertOneNote(t, warn, path)
}

// An unreadable rag.json (e.g. a stat/read race or permissions) also warns and
// falls back, rather than being swallowed.
func TestLoadContractUnreadableWarnsAndFallsBack(t *testing.T) {
	warn := captureWarnings(t)
	path := filepath.Join(t.TempDir(), "does-not-exist", "rag.json")
	if _, ok := loadContract(path); ok {
		t.Error("missing rag.json reported ok=true, want false")
	}
	assertOneNote(t, warn, path)
}

// A well-formed rag.json loads with no note.
func TestLoadContractValidNoNote(t *testing.T) {
	warn := captureWarnings(t)
	path := filepath.Join(t.TempDir(), "rag.json")
	if err := os.WriteFile(path, []byte(`{"top_k": 3}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, ok := loadContract(path)
	if !ok || cfg.TopK != 3 {
		t.Errorf("valid rag.json: ok=%v TopK=%d, want true 3", ok, cfg.TopK)
	}
	if warn.Len() != 0 {
		t.Errorf("valid rag.json wrote a note: %q", warn.String())
	}
}

// A turn is always bounded: a timeout that is not positive falls back to the
// built-in default.
func TestRouterDefaults(t *testing.T) {
	cfg := builtinDefaults()
	if cfg.RouteMaxTokens != 8 {
		t.Errorf("RouteMaxTokens = %d, want 8", cfg.RouteMaxTokens)
	}
	want := []string{"github.com", "exploit-db.com", "sploitus.com"}
	if !reflect.DeepEqual(cfg.PocDomains, want) {
		t.Errorf("PocDomains = %v, want %v", cfg.PocDomains, want)
	}
}

func TestRouteMaxTokensEnvOverride(t *testing.T) {
	t.Setenv("BLKCHAIN_ROUTE_MAX_TOKENS", "16")
	cfg := builtinDefaults()
	envOverrides(&cfg)
	if cfg.RouteMaxTokens != 16 {
		t.Errorf("RouteMaxTokens = %d, want 16", cfg.RouteMaxTokens)
	}
}

func TestRequestTimeoutIsAlwaysBounded(t *testing.T) {
	def := time.Duration(builtinDefaults().RequestTimeoutSeconds) * time.Second
	for secs, want := range map[int]time.Duration{30: 30 * time.Second, 0: def, -5: def} {
		if got := (Config{RequestTimeoutSeconds: secs}).RequestTimeout(); got != want {
			t.Errorf("RequestTimeout(%d) = %s, want %s", secs, got, want)
		}
	}
}

// captureWarnings points the load notes at a buffer and forgets the notes
// already written, so a test sees exactly the lines its own loads write.
func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevSeen := warnOut, warned
	warnOut, warned = &buf, map[string]bool{}
	t.Cleanup(func() { warnOut, warned = prevOut, prevSeen })
	return &buf
}

// Each synthesis sampling variable wins over rag.json and the default.
func TestSamplingEnvOverridesWinOverFile(t *testing.T) {
	warn := captureWarnings(t)
	t.Setenv("BLKCHAIN_SYNTH_TEMPERATURE", "1.2")
	t.Setenv("BLKCHAIN_SYNTH_TOP_P", "0.8")
	t.Setenv("BLKCHAIN_SYNTH_TOP_K", "40")
	t.Setenv("BLKCHAIN_SYNTH_PRESENCE_PENALTY", "-1.5")
	c := Load()
	if c.SynthTemperature != 1.2 || c.SynthTopP != 0.8 || c.SynthTopK != 40 || c.SynthPresencePenalty != -1.5 {
		t.Errorf("got temperature %v top_p %v top_k %v presence_penalty %v, want 1.2 0.8 40 -1.5",
			c.SynthTemperature, c.SynthTopP, c.SynthTopK, c.SynthPresencePenalty)
	}
	if warn.Len() != 0 {
		t.Errorf("valid values wrote a note: %q", warn.String())
	}
}

// samplingOf reads one sampling field of c by its rag.json key.
func samplingOf(c Config, key string) float64 {
	switch key {
	case "synth_temperature":
		return c.SynthTemperature
	case "synth_top_p":
		return c.SynthTopP
	case "synth_top_k":
		return float64(c.SynthTopK)
	}
	return c.SynthPresencePenalty
}

// assertOneNote checks that two loads wrote exactly one line, naming want.
func assertOneNote(t *testing.T, warn *bytes.Buffer, want ...string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(warn.String(), "\n"), "\n")
	if warn.Len() == 0 || len(lines) != 1 {
		t.Fatalf("notes = %q, want exactly one line", warn.String())
	}
	for _, w := range want {
		if !strings.Contains(lines[0], w) {
			t.Errorf("note %q does not name %q", lines[0], w)
		}
	}
}

// An unparsable value is ignored, so the rag.json value stays, and one note is
// written however often the config loads.
func TestSamplingEnvUnparsableIsIgnoredWithOneNote(t *testing.T) {
	for env, key := range map[string]string{
		"BLKCHAIN_SYNTH_TEMPERATURE":      "synth_temperature",
		"BLKCHAIN_SYNTH_TOP_P":            "synth_top_p",
		"BLKCHAIN_SYNTH_TOP_K":            "synth_top_k",
		"BLKCHAIN_SYNTH_PRESENCE_PENALTY": "synth_presence_penalty",
	} {
		t.Run(env, func(t *testing.T) {
			warn := captureWarnings(t)
			t.Setenv(env, "abc")
			Load()
			c := Load()
			if got, want := samplingOf(c, key), samplingOf(builtinDefaults(), key); got != want {
				t.Errorf("%s = %v, want %v", key, got, want)
			}
			assertOneNote(t, warn, env, "abc")
		})
	}
}

// A value out of range, NaN, or Inf is replaced by the built-in default, with
// one note naming the field and the rejected value.
func TestSamplingEnvOutOfRangeFallsBackWithOneNote(t *testing.T) {
	cases := []struct{ env, key, value string }{
		{"BLKCHAIN_SYNTH_TEMPERATURE", "synth_temperature", "2.5"},
		{"BLKCHAIN_SYNTH_TEMPERATURE", "synth_temperature", "-0.1"},
		{"BLKCHAIN_SYNTH_TEMPERATURE", "synth_temperature", "NaN"},
		{"BLKCHAIN_SYNTH_TEMPERATURE", "synth_temperature", "Inf"},
		{"BLKCHAIN_SYNTH_TOP_P", "synth_top_p", "0"},
		{"BLKCHAIN_SYNTH_TOP_P", "synth_top_p", "1.01"},
		{"BLKCHAIN_SYNTH_TOP_P", "synth_top_p", "NaN"},
		{"BLKCHAIN_SYNTH_TOP_P", "synth_top_p", "+Inf"},
		{"BLKCHAIN_SYNTH_TOP_K", "synth_top_k", "-1"},
		{"BLKCHAIN_SYNTH_TOP_K", "synth_top_k", "1001"},
		{"BLKCHAIN_SYNTH_PRESENCE_PENALTY", "synth_presence_penalty", "2.5"},
		{"BLKCHAIN_SYNTH_PRESENCE_PENALTY", "synth_presence_penalty", "-Inf"},
		{"BLKCHAIN_SYNTH_PRESENCE_PENALTY", "synth_presence_penalty", "nan"},
	}
	for _, tc := range cases {
		t.Run(tc.env+"="+tc.value, func(t *testing.T) {
			warn := captureWarnings(t)
			t.Setenv(tc.env, tc.value)
			Load()
			c := Load()
			if got, want := samplingOf(c, tc.key), samplingOf(builtinDefaults(), tc.key); got != want {
				t.Errorf("%s = %v, want the default %v", tc.key, got, want)
			}
			assertOneNote(t, warn, tc.key)
		})
	}
}

// The edges of each range are accepted.
func TestSamplingRangeEdgesAreAccepted(t *testing.T) {
	warn := captureWarnings(t)
	c := Config{SynthTemperature: 2, SynthTopP: 1, SynthTopK: 1000, SynthPresencePenalty: -2}
	validateSampling(&c)
	if c.SynthTemperature != 2 || c.SynthTopP != 1 || c.SynthTopK != 1000 || c.SynthPresencePenalty != -2 {
		t.Errorf("edges changed: %+v", c)
	}
	c = Config{SynthTemperature: 0, SynthTopP: 1e-9, SynthTopK: 0, SynthPresencePenalty: 2}
	validateSampling(&c)
	if c.SynthTemperature != 0 || c.SynthTopP != 1e-9 || c.SynthTopK != 0 || c.SynthPresencePenalty != 2 {
		t.Errorf("edges changed: %+v", c)
	}
	if warn.Len() != 0 {
		t.Errorf("edges wrote a note: %q", warn.String())
	}
}

// A value out of range in rag.json is replaced by the built-in default too.
func TestSamplingFileOutOfRangeFallsBack(t *testing.T) {
	warn := captureWarnings(t)
	path := filepath.Join(t.TempDir(), "rag.json")
	if err := os.WriteFile(path, []byte(`{"synth_top_p": 1.5}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := loadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	validateSampling(&c)
	if c.SynthTopP != builtinDefaults().SynthTopP {
		t.Errorf("synth_top_p = %v, want the default", c.SynthTopP)
	}
	assertOneNote(t, warn, "synth_top_p", "1.5")
}

func TestAnswerBudgetDefaults(t *testing.T) {
	d := builtinDefaults()
	if d.AnswerMaxTokens != 1800 {
		t.Errorf("AnswerMaxTokens default = %d, want 1800 (augmented-generation budget)", d.AnswerMaxTokens)
	}
	if d.AnswerMaxChunks != 6 {
		t.Errorf("AnswerMaxChunks default = %d, want 6", d.AnswerMaxChunks)
	}
}
