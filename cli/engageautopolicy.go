package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

func checkpointAutoActions(wsDir string) (*autoActionPolicy, error) {
	checkpoint, err := loadEngageCheckpoint(wsDir)
	if err != nil {
		return nil, err
	}
	if checkpoint.ScopeKind != "roe" {
		return nil, nil
	}
	data, err := checkpointScopeBytes(wsDir, checkpoint)
	if err != nil {
		return nil, err
	}
	roe, err := ParseRoE(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return roe.AutoActions, nil
}

type autoActionRule struct {
	phase   secgate.Phase
	surface secgate.Surface
	target  string
}

type autoActionPolicy struct {
	scope *secgate.Scope
	rules []autoActionRule
}

func (p *autoActionPolicy) hasLocalRule() bool {
	if p == nil {
		return false
	}
	for _, rule := range p.rules {
		if rule.surface == secgate.SurfaceLocal {
			return true
		}
	}
	return false
}

func buildAutoActionPolicy(entries []string, scope *secgate.Scope) (*autoActionPolicy, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	if len(entries) > 128 {
		return nil, errors.New("ROE.md: too many autonomous action rules")
	}
	p := &autoActionPolicy{scope: scope}
	for _, entry := range entries {
		fields := strings.Fields(strings.ToLower(entry))
		if len(fields) != 2 {
			return nil, fmt.Errorf("ROE.md: invalid autonomous action %q", entry)
		}
		parts := strings.Split(fields[0], "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("ROE.md: invalid autonomous action class %q", fields[0])
		}
		rule := autoActionRule{phase: secgate.Phase(parts[0]), surface: secgate.Surface(parts[1]), target: fields[1]}
		if !validAutoClass(rule.phase, rule.surface) {
			return nil, fmt.Errorf("ROE.md: unsupported autonomous action class %q", fields[0])
		}
		if rule.surface == secgate.SurfaceLocal {
			if rule.target != "local" || scope == nil || !scope.Local() {
				return nil, fmt.Errorf("ROE.md: local autonomous action requires an in-scope local directive")
			}
		} else {
			host, ok := autoTargetHost(rule.target)
			if !ok || host != rule.target || scope == nil || !scope.InScope(host) {
				return nil, fmt.Errorf("ROE.md: autonomous action target %q is not an exact in-scope host", rule.target)
			}
		}
		p.rules = append(p.rules, rule)
	}
	return p, nil
}

func validAutoClass(phase secgate.Phase, surface secgate.Surface) bool {
	if phase != secgate.PhaseExploit && phase != secgate.PhasePostEx && !(phase == secgate.PhaseRecon && surface == secgate.SurfaceLocal) {
		return false
	}
	switch surface {
	case secgate.SurfaceLocal, secgate.SurfaceNetwork, secgate.SurfaceWeb, secgate.SurfaceAD,
		secgate.SurfaceCloud, secgate.SurfaceCloudAWS, secgate.SurfaceCloudGCP, secgate.SurfaceCloudAzure,
		secgate.SurfaceContainer, secgate.SurfaceAISecurity:
		return true
	}
	return false
}

func autoTargetHost(target string) (string, bool) {
	targets, ok := secgate.ExtractTargets(secgate.Command{Binary: "nmap", Args: []string{target}})
	return firstAutoHost(targets, ok)
}

func firstAutoHost(targets []string, ok bool) (string, bool) {
	if !ok || len(targets) != 1 {
		return "", false
	}
	return targets[0], true
}

func (p *autoActionPolicy) permits(phase secgate.Phase, surface secgate.Surface, target string) bool {
	if p == nil || p.scope == nil {
		return false
	}
	if surface == secgate.SurfaceLocal {
		if !p.scope.Local() {
			return false
		}
		target = "local"
	} else {
		host, ok := autoTargetHost(target)
		if !ok || !p.scope.InScope(host) {
			return false
		}
		target = host
	}
	for _, rule := range p.rules {
		if rule.phase == phase && rule.surface == surface && rule.target == target {
			return true
		}
	}
	return false
}

func (p *autoActionPolicy) permitsTask(task engagement.Task) bool {
	if !task.CodeCandidate || task.CoverageGap || task.Status == engagement.StatusBlocked || (task.Phase != engagement.PhaseExploit && task.Phase != engagement.PhasePostEx) {
		return false
	}
	return p.permits(secgate.Phase(task.Phase), secgate.Surface(task.Surface), task.Target)
}

func (p *autoActionPolicy) permitsCommand(c secgate.Command) bool {
	if c.Phase == secgate.PhaseExploit || c.Phase == secgate.PhasePostEx {
		if !c.Armed {
			return false
		}
	}
	if !p.permits(c.Phase, c.Surface, c.Target) {
		return false
	}
	if c.Surface == secgate.SurfaceLocal {
		targets, ok := secgate.ExtractTargets(c)
		return ok && len(targets) == 0
	}
	targets, ok := secgate.ExtractTargets(c)
	if !ok || len(targets) == 0 {
		return false
	}
	host, _ := autoTargetHost(c.Target)
	for _, target := range targets {
		if target != host {
			return false
		}
	}
	return true
}
