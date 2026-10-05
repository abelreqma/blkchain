package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEngageConfigWorkBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, "engage_max_actions: 240\nengage_wall_seconds: 3600\n")
	cfg, err := loadEngageConfig(path)
	if err != nil || cfg.MaxActions != 240 || cfg.WallSeconds != 3600 {
		t.Fatalf("config=%+v err=%v", cfg, err)
	}
	for _, content := range []string{"engage_max_actions: -1\n", "engage_max_actions: 10001\n", "engage_wall_seconds: -1\n", "engage_wall_seconds: 86401\n"} {
		writeFile(t, path, content)
		if _, err := loadEngageConfig(path); err == nil {
			t.Fatalf("accepted invalid budget: %q", content)
		}
	}
}

func TestResolvedEngagePolicyCarriesWorkBudget(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".blkchain", "config.yaml"), "engage_max_actions: 240\nengage_wall_seconds: 3600\n")
	policy, err := resolveEngageConfigPolicy(engageOpts{}, root)
	if err != nil || policy.MaxActions != 240 || policy.WallSeconds != 3600 {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
}

func TestLoadEngageConfigAllKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, p, "denied_binaries: [nc, ncat]\nallowed_binaries: [nmap, curl]\nallow_interpreter_poc: true\n")
	cfg, err := loadEngageConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DeniedBinaries) != 2 || cfg.DeniedBinaries[0] != "nc" {
		t.Errorf("denied_binaries wrong: %v", cfg.DeniedBinaries)
	}
	if cfg.AllowedBinaries.All || len(cfg.AllowedBinaries.List) != 2 || cfg.AllowedBinaries.List[1] != "curl" {
		t.Errorf("allowed_binaries wrong: %+v", cfg.AllowedBinaries)
	}
	if !cfg.AllowInterpreterPoC {
		t.Error("allow_interpreter_poc should be true")
	}
}

func TestLoadEngageConfigAllowedBinariesTrue(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, p, "allowed_binaries: true\n")
	cfg, err := loadEngageConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowedBinaries.All {
		t.Error("allowed_binaries: true must set All")
	}
	if len(cfg.AllowedBinaries.List) != 0 {
		t.Errorf("allowed_binaries: true must have no explicit list, got %v", cfg.AllowedBinaries.List)
	}
}

func TestLoadEngageConfigAllowedBinariesFalse(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, p, "allowed_binaries: false\n")
	cfg, err := loadEngageConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AllowedBinaries.All {
		t.Error("allowed_binaries: false must not set All")
	}
}

func TestLoadEngageConfigAllowedBinariesBadScalar(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, p, "allowed_binaries: maybe\n")
	if _, err := loadEngageConfig(p); err == nil {
		t.Error("a non-bool scalar allowed_binaries must fail closed")
	}
}

func TestLoadEngageConfigDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, p, "")
	cfg, err := loadEngageConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AllowInterpreterPoC {
		t.Error("allow_interpreter_poc must default to false")
	}
	if len(cfg.DeniedBinaries) != 0 || cfg.AllowedBinaries.All || len(cfg.AllowedBinaries.List) != 0 {
		t.Errorf("empty config must have empty lists, got %+v", cfg)
	}
}

func TestLoadEngageConfigUnknownKeyFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, p, "denied_binaries: [nc]\nunexpected_key: oops\n")
	if _, err := loadEngageConfig(p); err == nil {
		t.Error("an unknown config key must fail closed (error)")
	}
}

func TestLoadEngageConfigMalformedYAMLError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, p, "denied_binaries: [nc\n  bad: : :\n")
	if _, err := loadEngageConfig(p); err == nil {
		t.Error("malformed YAML must error")
	}
}

func TestAutodetectEngageConfigFound(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".blkchain", "config.yaml"), "allowed_binaries: [nmap]\n")
	cfg, path, err := autodetectEngageConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || len(cfg.AllowedBinaries.List) != 1 {
		t.Errorf("autodetect should load the config: %+v", cfg)
	}
	if filepath.Base(path) != "config.yaml" {
		t.Errorf("path should point at the config file, got %q", path)
	}
}

func TestAutodetectEngageConfigAbsent(t *testing.T) {
	cfg, path, err := autodetectEngageConfig(t.TempDir())
	if err != nil {
		t.Fatalf("absent config is not an error: %v", err)
	}
	if cfg != nil || path != "" {
		t.Errorf("absent config must return (nil, \"\"), got (%+v, %q)", cfg, path)
	}
}

// TestLoadEngageConfigExploitTools: the exploit_tools key is in the known
// schema (KnownFields is fail-closed, so an unknown key would error) and parses.
func TestLoadEngageConfigExploitTools(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, "exploit_tools:\n  - customexploit\n  - sqlmap\n")
	cfg, err := loadEngageConfig(path)
	if err != nil {
		t.Fatalf("loadEngageConfig: %v", err)
	}
	if len(cfg.ExploitTools) != 2 || cfg.ExploitTools[0] != "customexploit" || cfg.ExploitTools[1] != "sqlmap" {
		t.Fatalf("ExploitTools = %v, want [customexploit sqlmap]", cfg.ExploitTools)
	}
}

func TestLocalUnattendedBinariesAreOnlyAConfigBound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".blkchain", "config.yaml")
	writeFile(t, path, "local_unattended_binaries: [id, uname]\n")
	policy, err := resolveEngageConfigPolicy(engageOpts{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.LocalUnattendedReady || !policy.LocalUnattendedAllow.Permits("id") || policy.AutoActions != nil {
		t.Fatalf("config policy=%+v", policy)
	}
	writeFile(t, path, "local_unattended_binaries: true\n")
	if _, err := loadEngageConfig(path); err == nil {
		t.Fatal("unbounded LOCAL binary switch accepted")
	}
	writeFile(t, path, "local_unattended_binaries: [/tmp/id]\n")
	if _, err := loadEngageConfig(path); err == nil {
		t.Fatal("path-qualified LOCAL binary accepted")
	}
}
