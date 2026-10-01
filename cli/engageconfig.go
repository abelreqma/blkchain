package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// engageConfig is the parsed .blkchain/config.yaml.
type engageConfig struct {
	DeniedBinaries      []string        `yaml:"denied_binaries"`
	AllowedBinaries     allowedBinaries `yaml:"allowed_binaries"`
	AllowInterpreterPoC bool            `yaml:"allow_interpreter_poc"`

	ExploitTools []string `yaml:"exploit_tools"`
}

// allowedBinaries is the unattended-/auto bound. In YAML it is either a list of
// binary names (bounds unattended /auto to those) or the scalar `true`, which
// means everything is allowed unattended (no HITL bound). The scalar `false` is
// the same as an empty list (every Auto command falls back to HITL).
type allowedBinaries struct {
	All  bool
	List []string
}

// UnmarshalYAML accepts either a sequence (the explicit list) or a bool scalar.
func (a *allowedBinaries) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var b bool
		if err := value.Decode(&b); err != nil {
			return fmt.Errorf("allowed_binaries: a scalar must be true or false (or use a list of binary names): %w", err)
		}
		a.All = b
		return nil
	case yaml.SequenceNode:
		return value.Decode(&a.List)
	default:
		return fmt.Errorf("allowed_binaries must be a list of binary names or the scalar true/false")
	}
}

// loadEngageConfig reads and parses a .blkchain/config.yaml file. Unknown keys
// are rejected (KnownFields), so a typo or a stray key fails closed rather than
// being silently ignored. An empty file is a valid empty config.
func loadEngageConfig(path string) (*engageConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var cfg engageConfig
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return &engageConfig{}, nil // empty file -> empty config
		}
		return nil, fmt.Errorf("engage config %s: %w", path, err)
	}
	return &cfg, nil
}

// autodetectEngageConfig looks for <dir>/.blkchain/config.yaml. A missing file
// returns (nil, "", nil); a present-but-malformed file returns the parse error.
func autodetectEngageConfig(dir string) (*engageConfig, string, error) {
	path := filepath.Join(dir, ".blkchain", "config.yaml")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, "", nil
		}
		return nil, "", err
	}
	cfg, err := loadEngageConfig(path)
	if err != nil {
		return nil, path, err
	}
	return cfg, path, nil
}
