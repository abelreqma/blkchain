// Package skillcat is the deterministic, code-routed catalog of security skills
// parsed from SKILL.md files (frontmatter + markdown body). It never lets the
// model choose a skill; routing is by domain, in code.
package skillcat

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Skill is one parsed SKILL.md.
type Skill struct {
	Name        string
	Description string
	Verified    string
	Body        string
	Digest      string
	Domain      string
	Path        string
}

// frontmatter is the YAML header of a SKILL.md.
type frontmatter struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Verified    string `yaml:"verified"`
}

// ParseSkill parses one SKILL.md's raw bytes (frontmatter + body) from path.
// It errors when there is no `---` frontmatter block or when name or
// description is missing or empty. Digest is the hex sha256 of raw.
func ParseSkill(path string, raw []byte) (Skill, error) {
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	fm, body, err := splitFrontmatter(raw)
	if err != nil {
		return Skill{}, fmt.Errorf("skillcat: %s: %w", path, err)
	}
	var f frontmatter
	if err := yaml.Unmarshal(fm, &f); err != nil {
		return Skill{}, fmt.Errorf("skillcat: %s: bad frontmatter: %w", path, err)
	}
	if strings.TrimSpace(f.Name) == "" {
		return Skill{}, fmt.Errorf("skillcat: %s: missing name", path)
	}
	if strings.TrimSpace(f.Description) == "" {
		return Skill{}, fmt.Errorf("skillcat: %s: missing description", path)
	}
	return Skill{
		Name:        strings.TrimSpace(f.Name),
		Description: strings.TrimSpace(f.Description),
		Verified:    strings.TrimSpace(f.Verified),
		Body:        string(body),
		Digest:      digest,
		Path:        path,
	}, nil
}

// splitFrontmatter returns the YAML frontmatter bytes and the body. The file
// must begin with a `---` line and have a closing `---` line.
func splitFrontmatter(raw []byte) (fm, body []byte, err error) {
	s := raw
	// Real files start with "---"; leading blank lines are not allowed.
	if !bytes.HasPrefix(s, []byte("---")) {
		return nil, nil, fmt.Errorf("no frontmatter block")
	}
	// Find the end of the opening delimiter line.
	nl := bytes.IndexByte(s, '\n')
	if nl < 0 {
		return nil, nil, fmt.Errorf("no frontmatter block")
	}
	rest := s[nl+1:]
	// Find the closing "---" on its own line.
	idx := bytes.Index(rest, []byte("\n---"))
	if idx < 0 {
		return nil, nil, fmt.Errorf("no closing frontmatter delimiter")
	}
	fm = rest[:idx]
	after := rest[idx+1:] // starts at the closing "---" line
	// Skip the closing delimiter line.
	if nl2 := bytes.IndexByte(after, '\n'); nl2 >= 0 {
		body = after[nl2+1:]
	}
	return fm, body, nil
}
