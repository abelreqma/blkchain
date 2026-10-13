package secgate

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

func (g *Gate) PolicyUsage() int { g.mu.Lock(); defer g.mu.Unlock(); return g.policyCount }

func (g *Gate) PolicyActionUsage() int { g.mu.Lock(); defer g.mu.Unlock(); return g.policyActions }

func (g *Gate) PolicyCapReason() string { g.mu.Lock(); defer g.mu.Unlock(); return g.policyCapDenied }

func (g *Gate) PolicyStopReason() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.policyCapDenied != "" {
		return g.policyCapDenied
	}
	return g.policyStall
}

func budgetExempt(c Command) bool {
	if path.Base(c.Binary) == "sudo" && sudoListOnly(c.Args) {
		return true
	}
	if !c.InternalProbe {
		return false
	}
	return len(c.Args) == 1 && (c.Args[0] == "--help" || c.Args[0] == "help")
}

func BudgetExempt(c Command) bool { return budgetExempt(c) }

func (g *Gate) PolicyByteUsage() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.policyBytes
}

func (g *Gate) PolicyBytesRemaining() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.Policy == nil {
		return 0
	}
	remaining := int64(g.Policy.TotalBytes) - g.policyBytes
	if remaining < 0 {
		return 0
	}
	return int(remaining)
}

func (g *Gate) ClaimPolicyBytes(n int) error {
	if g == nil || g.Policy == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if n < 0 || int64(n) > int64(g.Policy.TotalBytes)-g.policyBytes {
		g.audit("deny:cap", "engagement byte cap reached")
		return fmt.Errorf("engagement byte cap reached")
	}
	g.policyBytes += int64(n)
	return nil
}

func (g *Gate) ClaimPolicyAction(action string) error {
	if g == nil || g.Policy == nil {
		return fmt.Errorf("engagement policy missing")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.Policy.Allows(action) {
		return fmt.Errorf("engagement action %s is not allowed", action)
	}
	if !g.policyDeadline.IsZero() && !time.Now().Before(g.policyDeadline) {
		return fmt.Errorf("engagement deadline reached")
	}
	if g.policyActions >= g.Policy.MaxActions || action == "command" && g.policyCount >= g.Policy.MaxCommands {
		g.policyCapDenied = "engagement action cap reached"
		if g.policyCount >= g.Policy.MaxCommands && action == "command" {
			g.policyCapDenied = "engagement command cap reached"
		}
		return errors.New(g.policyCapDenied)
	}
	g.policyActions++
	if action == "command" {
		g.policyCount++
	}
	return nil
}

func (g *Gate) RestorePolicyUsage(count int, deadline time.Time, bytes ...int64) error {
	return g.RestorePolicyUsageCounts(count, count, deadline, bytes...)
}

func (g *Gate) RestorePolicyUsageCounts(commands, actions int, deadline time.Time, bytes ...int64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	byteCount := int64(0)
	if len(bytes) > 0 {
		byteCount = bytes[0]
	}
	if g.Policy == nil || commands < 0 || commands > g.Policy.MaxCommands || actions < commands || actions > g.Policy.MaxActions || len(bytes) > 1 || byteCount < 0 || byteCount > int64(g.Policy.TotalBytes) {
		return fmt.Errorf("invalid checkpoint policy usage")
	}
	g.policyCount = commands
	g.policyActions = actions
	g.policyBytes = byteCount
	g.policyDeadline = deadline
	return nil
}

func (s *Scope) PinNetwork(in, out []string) error {
	for _, group := range []struct {
		entries  []string
		excluded bool
	}{{in, false}, {out, true}} {
		for _, entry := range group.entries {
			matcher, err := parseMatcher(entry)
			if err != nil {
				return err
			}
			matcher.pinned = true
			if group.excluded {
				s.out = append(s.out, matcher)
			} else {
				s.in = append(s.in, matcher)
			}
		}
	}
	return nil
}

func (g *Gate) policyApprovalCommand(c Command) Command {
	if g.Policy != nil {
		c.Binary = g.Policy.Hash + ":" + g.Policy.RunnerID + ":" + c.Operation + ":" + c.PoCHash + ":" + c.Binary
	}
	return c
}

func (g *Gate) checkPolicyLocked(c Command) Decision {
	p := g.Policy
	scope := g.scopeFor(c)
	if g.Scope == nil || (g.Scope.Empty() && !g.Scope.Local()) {
		return g.deny("scope", c, "ROE.md has no usable scope", "")
	}
	if !g.policyDeadline.IsZero() && !time.Now().Before(g.policyDeadline) {
		return g.deny("cap", c, "engagement deadline reached", "")
	}
	exempt := budgetExempt(c)
	if !exempt && (g.policyCount >= p.MaxCommands || g.policyActions >= p.MaxActions) {
		g.policyCapDenied = "engagement action cap reached"
		if g.policyCount >= p.MaxCommands {
			g.policyCapDenied = "engagement command cap reached"
		}
		return g.deny("cap", c, g.policyCapDenied, "")
	}
	if !exempt {
		g.policyCount++
		g.policyActions++
	}
	if strings.TrimSpace(c.Binary) == "" || len(c.Binary) > 4096 || len(c.Args) > 1024 {
		return g.deny("input", c, "invalid or oversized command", "")
	}
	n := len(c.Binary)
	for _, a := range c.Args {
		n += len(a)
		if strings.ContainsRune(a, 0) {
			return g.deny("input", c, "NUL in command argument", "")
		}
	}
	if n > 65536 {
		return g.deny("input", c, "command arguments exceed 64 KiB", "")
	}
	action := c.Operation
	if action == "" {
		action = "command"
		if g.Scope.Local() {
			action = "local"
		}
	}
	if !p.Allows(action) {
		return g.deny("roe-action", c, "operation "+action+" is not authorized by ROE.md", "")
	}
	if p.Denies(c) {
		return g.deny("roe-command", c, "command is denied by ROE.md", "")
	}
	if policyRedirectViolation(c) {
		return g.deny("redirect", c, "command redirect following is not scope-checked; use the gated browser or API path", "")
	}
	if _, bad := TargetSelfExecViolation(c, g.Scratch, g.execOffHost(c)); bad {
		return g.deny("target-self-exec", c, "an inspection task cannot execute its analysis target", TargetSelfExecSuggestion)
	}
	if targets, nets, ok := ExtractTargetSet(c); ok {
		for _, target := range targets {
			if !scope.InScope(target) && !g.pivotWebHostCandidate(scope, target) {
				return g.deny("scope", c, "target out of scope: "+target, "")
			}
		}
		for _, n := range nets {
			if !scope.NetworkInScope(n) {
				return g.deny("scope", c, "network out of scope: "+n.String(), "")
			}
		}
	} else {
		return g.deny("scope", c, "unverifiable explicit target", "")
	}
	if ip, bad := ScopeViolation(scope, c); bad {
		return g.deny("scope", c, "target out of scope: "+ip, "")
	}
	// The rate window is consumed by the shared tail in checkLocked, after the
	// structural layers, so only an otherwise-admissible command takes a slot.
	return Decision{Allowed: true}
}
