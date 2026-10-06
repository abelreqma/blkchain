package main

import (
	"blkchain/cli/internal/secgate"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEngageMigrationPreviewsWithoutBroadeningOrOverwriting(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir(filepath.Join(dir, ".blkchain"), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, ".blkchain", "config.yaml")
	if err := os.WriteFile(config, []byte("denied_binaries: [rm]\nallowed_binaries: [nmap]\nengage_max_actions: 12\n"), 0600); err != nil {
		t.Fatal(err)
	}
	original := "## In Scope\n10.20.0.5\n## Allowed Actions\ncommand\n"
	roePath := filepath.Join(dir, "ROE.md")
	if err := os.WriteFile(roePath, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	preview := captureStdout(t, func() {
		if err := migrateEngagePolicy(nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(preview, "max_actions: 12") || !strings.Contains(preview, "binary: rm") || strings.Contains(preview, "- command") {
		t.Fatalf("preview broadened policy: %q", preview)
	}
	if _, err := os.Stat(roePath + ".migrated"); !os.IsNotExist(err) {
		t.Fatal("preview wrote a candidate")
	}
	if err := migrateEngagePolicy([]string{"--write"}); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(roePath)
	if err != nil || string(current) != original {
		t.Fatalf("operator RoE overwritten: %q %v", current, err)
	}
	if _, err := os.Stat(config); err != nil {
		t.Fatalf("operator configuration removed: %v", err)
	}
	if _, err := ParseRoE(strings.NewReader(preview)); err != nil {
		t.Fatalf("preview is not a valid RoE: %v", err)
	}
	if err := migrateEngagePolicy([]string{"--write"}); err == nil {
		t.Fatal("migration overwrote an existing candidate")
	}
}

func TestEngageMigrationCreatesNewPolicyWithoutActions(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir(filepath.Join(dir, ".blkchain"), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, ".blkchain", "config.yaml")
	if err := os.WriteFile(config, []byte("denied_binaries: [rm]\nallowed_binaries: [nmap]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := migrateEngagePolicy([]string{"--write"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "ROE.md"))
	if err != nil {
		t.Fatal(err)
	}
	roe, err := ParseRoE(strings.NewReader(string(data)))
	if err != nil || len(roe.Policy.Allowed) != 0 || !roe.Policy.Denies(secgate.Command{Binary: "rm"}) {
		t.Fatalf("unsafe migrated policy: %+v %v", roe, err)
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatal("old policy remained active")
	}
	if _, err := os.Stat(config + ".migrated"); err != nil {
		t.Fatalf("legacy policy archive missing: %v", err)
	}
}
