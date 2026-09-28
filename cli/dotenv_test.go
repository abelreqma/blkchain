package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDotenvPairs(t *testing.T) {
	data := []byte("\n# a comment\nexport FOO=1\nBAR=\"baz\"\nQ='x'\n\n# trailing comment\n")
	pairs := parseDotenvPairs(data)
	want := map[string]string{"FOO": "1", "BAR": "baz", "Q": "x"}
	if len(pairs) != len(want) {
		t.Fatalf("got %d pairs %v, want %d %v", len(pairs), pairs, len(want), want)
	}
	for k, v := range want {
		if pairs[k] != v {
			t.Errorf("pairs[%q] = %q, want %q", k, pairs[k], v)
		}
	}
}

func TestLoadProjectEnvRealEnvWins(t *testing.T) {
	// Register cleanup for both keys before mutating them, so the process
	// environment is restored exactly regardless of what applyEnvFile sets.
	t.Setenv("DOTENV_TEST_PRESET", "real-value")
	t.Setenv("DOTENV_TEST_FRESH", "")

	dir := t.TempDir()
	envContent := "DOTENV_TEST_PRESET=dotenv-value\nDOTENV_TEST_FRESH=fresh-value\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0o600); err != nil {
		t.Fatal(err)
	}

	applyEnvFile(dir)

	if got := os.Getenv("DOTENV_TEST_PRESET"); got != "real-value" {
		t.Errorf("DOTENV_TEST_PRESET = %q, want %q (real env must win)", got, "real-value")
	}
	if got := os.Getenv("DOTENV_TEST_FRESH"); got != "fresh-value" {
		t.Errorf("DOTENV_TEST_FRESH = %q, want %q", got, "fresh-value")
	}
}

func TestOMLXAPIAlias(t *testing.T) {
	t.Run("sets alias when unset", func(t *testing.T) {
		t.Setenv("OMLX_API_KEY", "")
		applyPairs(map[string]string{"OMLX_API": "the-key"})
		if got := os.Getenv("OMLX_API_KEY"); got != "the-key" {
			t.Errorf("OMLX_API_KEY = %q, want %q", got, "the-key")
		}
	})

	t.Run("real env still wins", func(t *testing.T) {
		t.Setenv("OMLX_API_KEY", "preset-key")
		applyPairs(map[string]string{"OMLX_API": "other-key"})
		if got := os.Getenv("OMLX_API_KEY"); got != "preset-key" {
			t.Errorf("OMLX_API_KEY = %q, want %q", got, "preset-key")
		}
	})
}
