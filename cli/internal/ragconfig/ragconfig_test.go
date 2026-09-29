package ragconfig

import (
	"os"
	"path/filepath"
	"reflect"
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

// A turn is always bounded: a timeout that is not positive falls back to the
// built-in default.
func TestRequestTimeoutIsAlwaysBounded(t *testing.T) {
	def := time.Duration(builtinDefaults().RequestTimeoutSeconds) * time.Second
	for secs, want := range map[int]time.Duration{30: 30 * time.Second, 0: def, -5: def} {
		if got := (Config{RequestTimeoutSeconds: secs}).RequestTimeout(); got != want {
			t.Errorf("RequestTimeout(%d) = %s, want %s", secs, got, want)
		}
	}
}
