package main

import (
	"blkchain/cli/internal/secgate"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var roeImagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$`)

func addRoEDenial(p *secgate.Policy, entry string) error {
	kind, value, ok := strings.Cut(entry, ":")
	if !ok {
		return fmt.Errorf("ROE.md: denied command needs binary: NAME or argument: NAME TOKEN")
	}
	fields := strings.Fields(value)
	if len(fields) == 0 || filepath.Base(fields[0]) != fields[0] || strings.ContainsAny(fields[0], "\x00/\\") {
		return fmt.Errorf("ROE.md: invalid denied executable")
	}
	rule := secgate.CommandDenial{Binary: strings.ToLower(fields[0])}
	switch strings.TrimSpace(kind) {
	case "binary":
		if len(fields) != 1 {
			return fmt.Errorf("ROE.md: binary denial needs one name")
		}
	case "argument":
		if len(fields) != 2 {
			return fmt.Errorf("ROE.md: argument denial needs executable and one argv token")
		}
		rule.Arg = fields[1]
	default:
		return fmt.Errorf("ROE.md: unknown command denial %q", kind)
	}
	for _, old := range p.Commands {
		if old == rule {
			return fmt.Errorf("ROE.md: duplicate command denial")
		}
	}
	p.Commands = append(p.Commands, rule)
	return nil
}

func setRoEValue(p *secgate.Policy, section, entry string, seen map[string]bool) error {
	key, value, ok := strings.Cut(entry, ":")
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if !ok || seen[section+":"+key] {
		return fmt.Errorf("ROE.md: invalid or duplicate %s value", section)
	}
	seen[section+":"+key] = true
	if section == "runner" {
		switch key {
		case "id":
			p.RunnerID = value
		case "image":
			if !roeImagePattern.MatchString(value) {
				return fmt.Errorf("ROE.md: runner image must be pinned by sha256 digest")
			}
			p.RunnerImage = value
		default:
			return fmt.Errorf("ROE.md: unknown runner key %q", key)
		}
		return nil
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("ROE.md: %s needs a bounded positive integer", key)
	}
	switch key {
	case "max_commands":
		p.MaxCommands = n
	case "max_actions":
		p.MaxActions = n
	case "wall_seconds":
		p.WallSeconds = n
	case "command_seconds":
		p.CommandSeconds = n
	case "output_bytes":
		p.OutputBytes = n
	case "total_bytes":
		p.TotalBytes = n
	case "parallel":
		p.Parallel = n
	default:
		return fmt.Errorf("ROE.md: unknown cap %q", key)
	}
	return nil
}
