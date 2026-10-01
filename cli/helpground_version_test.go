package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveBinVersionStableAndChanges(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho one\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	v1 := resolveBinVersion(bin)
	if v1 == "unknown" || len(v1) != 16 {
		t.Fatalf("absolute-path binary should fingerprint: %q", v1)
	}
	if resolveBinVersion(bin) != v1 {
		t.Fatal("same contents must give the same fingerprint")
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho two\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if resolveBinVersion(bin) == v1 {
		t.Fatal("changed contents must change the fingerprint")
	}
}

func TestResolveBinVersionUnknownOnMissing(t *testing.T) {
	if got := resolveBinVersion("/nonexistent/path/to/nothing-xyz"); got != "unknown" {
		t.Fatalf("missing binary should be 'unknown', got %q", got)
	}
}

func TestResolveBinVersionUnknownOnBareNameNotOnPath(t *testing.T) {
	// A bare name that exec.LookPath cannot resolve on PATH fingerprints as
	// "unknown" (the cache then keys on the name alone).
	if got := resolveBinVersion("blkchain-no-such-tool-xyz"); got != "unknown" {
		t.Fatalf("unresolvable bare name should be 'unknown', got %q", got)
	}
}
