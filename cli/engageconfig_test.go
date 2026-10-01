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
