package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"blkchain/cli/internal/secgate"
)

// roeTemplate is the pre-formatted ROE.md written into an engagement workspace
// when none is detected. HTML comments carry the fill-in guidance so the empty
// template still parses as a valid (empty-scope) RoE. Out of scope always wins.
const roeTemplate = `# Rules of Engagement
<!-- Authorized engagement scope. Fill in each section below. -->

## Summary
Describe the authorized engagement here.

## Targets
<!-- domains, systems, users, or accounts in the engagement, one per line -->

## In Scope
<!-- hosts, IPs, or CIDRs allowed, one per line, e.g. 10.0.0.0/24 -->

## Out of Scope
<!-- hosts, IPs, or CIDRs explicitly forbidden; out of scope always wins -->

## Rate
10/s

## Autonomous Actions
<!-- phase/surface target, e.g. exploit/network 192.0.2.1 or recon/local local -->
`

// writeRoETemplate writes roeTemplate to <dir>/ROE.md when that file does not
// already exist. It never overwrites an existing ROE.md (idempotent); it returns
// whether it wrote the file.
func writeRoETemplate(dir string) (bool, error) {
	path := filepath.Join(dir, "ROE.md")
	// O_EXCL makes the create atomic: an existing file is left untouched.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	if _, err := f.WriteString(roeTemplate); err != nil {
		return false, err
	}
	return true, nil
}

// roe.go parses an optional ROE.md (Rules of Engagement) into the extended
// secgate.Scope. ROE.md is the primary scope source for an engagement; the
// older line-based --scope file remains for back-compat. Parsing fails closed:
// a malformed scope entry or rate yields an error, never a silent permissive
// scope. The ctrl+g RoE editor UI is a separate session; this file is parse and
// template only.

// RoE is a parsed ROE.md. Summary and Targets are informational (for the
// report); Scope carries the enforced In/Out matchers and the optional Rate.
type RoE struct {
	Summary     string
	Targets     []string
	Scope       *secgate.Scope
	AutoActions *autoActionPolicy
}

// ParseRoE reads an ROE.md. Recognized level-2+ sections are Summary, Targets,
// In Scope, Out of Scope, and Rate (heading match is case-insensitive). Within a
// section, bullet lines (- / * / +) and bare non-empty lines are entries. An
// UNRECOGNIZED level-2+ heading is a parse error (fail closed): silently dropping
// a typo'd or synonym heading would discard an operator's exclusions and defeat
// the gate. A level-1 heading is treated as a document title (ignored). An empty
// file yields an RoE with an empty scope (the no-RoE floor applies downstream).
func ParseRoE(r io.Reader) (*RoE, error) {
	var summary []string
	var spec secgate.ScopeSpec
	var autoEntries []string
	section := ""
	inComment := false

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if inComment {
			if strings.Contains(line, "-->") {
				inComment = false
			}
			continue
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "<!--") {
			if !strings.Contains(line, "-->") {
				inComment = true // multi-line comment; skip until its close
			}
			continue // template guidance
		}
		if h, level, ok := headingText(line); ok {
			if level == 1 {
				section = "" // document title, not a section
				continue
			}
			key := normalizeSection(h)
			if !isKnownSection(key) {
				return nil, fmt.Errorf("ROE.md: unrecognized section heading %q (expected: Summary, Targets, In Scope, Out of Scope, Rate, Autonomous Actions)", h)
			}
			section = key
			continue
		}
		entry := stripBullet(line)
		if entry == "" {
			continue
		}
		switch section {
		case "summary":
			summary = append(summary, entry)
		case "targets":
			spec.Targets = append(spec.Targets, entry)
		case "in scope":
			if strings.EqualFold(entry, "local") {
				spec.Local = true
			} else {
				spec.In = append(spec.In, entry)
			}
		case "out of scope":
			spec.Out = append(spec.Out, entry)
		case "rate":
			if spec.Rate == "" { // first entry wins
				spec.Rate = entry
			}
		case "autonomous actions":
			autoEntries = append(autoEntries, entry)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	scope, err := secgate.BuildScope(spec)
	if err != nil {
		return nil, err
	}
	autoActions, err := buildAutoActionPolicy(autoEntries, scope)
	if err != nil {
		return nil, err
	}
	return &RoE{
		Summary:     strings.Join(summary, "\n"),
		Targets:     spec.Targets,
		Scope:       scope,
		AutoActions: autoActions,
	}, nil
}

// headingText returns the text and level of a markdown ATX heading (one or more
// leading '#' then whitespace), and whether the line is a heading.
func headingText(line string) (text string, level int, ok bool) {
	if !strings.HasPrefix(line, "#") {
		return "", 0, false
	}
	t := strings.TrimLeft(line, "#")
	level = len(line) - len(t)
	if t == "" || (t[0] != ' ' && t[0] != '\t') {
		return "", 0, false // "###" alone or "#notaheading" is not a usable heading
	}
	return strings.TrimSpace(t), level, true
}

// isKnownSection reports whether a normalized heading is one of the recognized
// ROE.md sections.
func isKnownSection(key string) bool {
	switch key {
	case "summary", "targets", "in scope", "out of scope", "rate", "autonomous actions":
		return true
	}
	return false
}

// normalizeSection lowercases and collapses internal whitespace of a heading so
// "In  Scope" and "in scope" match the same section key.
func normalizeSection(h string) string {
	return strings.Join(strings.Fields(strings.ToLower(h)), " ")
}

// stripBullet removes a single leading markdown bullet marker (-, *, +) and the
// following space from an entry line.
func stripBullet(line string) string {
	if len(line) >= 2 && (line[0] == '-' || line[0] == '*' || line[0] == '+') && (line[1] == ' ' || line[1] == '\t') {
		return strings.TrimSpace(line[1:])
	}
	return strings.TrimSpace(line)
}
