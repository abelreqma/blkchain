package secgate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Gate composes every security layer. It performs no execution.
type Gate struct {
	mu        sync.Mutex // serializes Authorize and Start: the Episode budget and Approvals are shared state
	Mode      Mode
	Scope     *Scope                      // may be nil in Safe; must be non-nil and non-empty in Auto
	Allow     *Allowlist                  // nil permits nothing (fail closed)
	Confirm   Confirmer                   // used in Safe; nil denies in Safe
	Approvals *SessionApprovals           // nil remembers no repeats
	Episode   *Episode                    // nil gets a default-caps episode
	Audit     func(action, detail string) // nil is a no-op

	Protected []string
	Scratch   string

	Now      func() time.Time
	rateHits []time.Time

	ConfigDenied        []string
	UnattendedAllow     *Allowlist
	AllowInterpreterPoC bool

	AutoScopeOverride bool
}

// Start validates the gate for its mode. Auto refuses without a non-empty scope.
func (g *Gate) Start() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.Mode != Safe && g.Mode != Auto {
		return fmt.Errorf("secgate: unknown mode %d", int(g.Mode))
	}
	if g.Mode == Auto {
		if g.Scope == nil || (g.Scope.Empty() && !g.Scope.Local()) {
			if !g.AutoScopeOverride {
				return errors.New("secgate: /auto requires a scope with in-scope targets or a local directive, or an explicit override")
			}
			// Logged override: auto with no scope. Record it once; the gate still
			// fails closed on any targeted command (checkLocked).
			g.audit("override", "auto started without a scope (logged operator override)")
		}
	}
	if g.Episode == nil {
		g.Episode = NewEpisode(Caps{}, nil)
	}
	return nil
}

func (g *Gate) audit(action, detail string) {
	if g.Audit != nil {
		g.Audit(action, detail)
	}
}

// Authorize runs the fail-closed pipeline for one command and audits the
// outcome. Order: episode caps and breaker, classifier, allowlist, scope
// (every extracted target in scope), confirmation (Safe, unless already
// session-approved). A scope with a local directive selects the LOCAL profile
// instead: the classifier is ClassifyLocal (enforceability denials only) and
// there is no binary allowlist. Because the LOCAL profile drops the allowlist,
// it requires per-command human confirmation in EVERY mode, including Auto: the
// human is the positive control that bounds arbitrary code execution, and with
// no confirmer available a local command fails closed (deny). EXTERNAL /auto is
// unchanged and does not prompt. It never executes anything.
//
// The human confirmation (g.Confirm.Confirm) runs OUTSIDE g.mu: the mutex is
// released for the duration of the prompt and re-acquired afterward, so a slow
// human approving one command does not serialize concurrent Authorize calls
// behind the prompt and a bounded-parallel executor pool cannot deadlock. Every
// Episode, Approvals, and audit access stays under g.mu.
func (g *Gate) Authorize(ctx context.Context, c Command) Decision {
	g.mu.Lock()
	if g.Episode == nil {
		g.Episode = NewEpisode(Caps{}, nil)
	}
	if g.Mode != Safe && g.Mode != Auto {
		d := g.deny("mode", c, "unknown mode", "")
		g.mu.Unlock()
		return d
	}
	if d := g.checkLocked(c); !d.Allowed {
		g.mu.Unlock()
		return d
	}
	// Deny-layers passed. Run the confirmation tail, which releases g.mu for the
	// human prompt and re-acquires it before touching Approvals or the audit log.
	// The exec-time rechecks run AFTER confirmation, off g.mu, so a resolution
	// change during the human prompt is still caught.
	d := g.confirmTailLocked(ctx, c)
	if !d.Allowed {
		return d
	}
	return g.recheck(c)
}

// Check runs the deny-layers for one command (episode caps and breaker, the
// classifier, allowlist, and scope checks of the selected profile) and then the
// exec-time rechecks (Gate.recheck), and returns the Decision WITHOUT confirming
// and WITHOUT auditing an allow. Like Authorize it consumes one budget slot per
// call, so a 3-stage pipeline that calls Check once per stage consumes 3 slots.
// A pipeline confirms ONCE via ConfirmCommand, then calls Check per stage so the
// authoritative rechecks run after confirmation, immediately before exec. The
// deny-layers run under g.mu; g.mu is released before the rechecks, which do DNS.
func (g *Gate) Check(ctx context.Context, c Command) Decision {
	g.mu.Lock()
	if g.Episode == nil {
		g.Episode = NewEpisode(Caps{}, nil)
	}
	if g.Mode != Safe && g.Mode != Auto {
		d := g.deny("mode", c, "unknown mode", "")
		g.mu.Unlock()
		return d
	}
	d := g.checkLocked(c)
	g.mu.Unlock()
	if !d.Allowed {
		return d
	}
	return g.recheck(c)
}

// ConfirmCommand runs only the confirmation tail for one command: in Safe it
// asks g.Confirm (outside g.mu) unless c is already session-approved, remembers
// an approval, and audits the final allow or deny; in Auto it is a no-op that
// audits allow. It runs no deny-layer and consumes no budget slot. A pipeline
// calls it once with a synthetic command that stands for the whole pipeline,
// before Check clears every stage, so a /safe pipeline prompts once.
func (g *Gate) ConfirmCommand(ctx context.Context, c Command) Decision {
	g.mu.Lock()
	return g.confirmTailLocked(ctx, c)
}

// checkLocked runs the fail-closed deny-layers for c and audits any denial. It
// assumes g.mu is held. A returned Decision{Allowed:true} means every deny-layer
// passed; the command is NOT yet confirmed and no "allow" is audited. It touches
// only g.mu-protected state (the Episode budget and the audit log).
func (g *Gate) checkLocked(c Command) Decision {
	// 1. caps and circuit breaker
	if ok, reason := g.Episode.AllowCommand(); !ok {
		return g.deny("cap", c, reason, "")
	}

	if deniedByConfig(c.Binary, g.ConfigDenied) {
		return g.deny("config-denylist", c, "binary "+c.Binary+" is denied by .blkchain/config.yaml", "")
	}

	if c.Phase.requiresArm() && !c.Armed {
		return g.deny("tier", c, "exploit/post-ex phase requires an armed task", "arm the task before running an exploit or post-exploitation command")
	}
	if g.Scope != nil && g.Scope.Local() {
		// LOCAL profile: no binary allowlist. Only the structural denials that
		// keep gating enforceable (raw-shell metacharacters, shells,
		// interpreters, exec-wrappers, find exec predicates).
		if d := ClassifyLocal(c); !d.Allowed {
			return g.deny("classifier", c, d.Reason, d.Suggestion)
		}
		if err := DestructiveViolation(c); err != nil {
			return g.deny("destructive", c, err.Error(), "")
		}
		if arg, bad := SensitivePathViolation(c, g.Protected, g.Scratch); bad {
			return g.deny("sensitive-path", c, "argument references a protected harness path: "+arg, "")
		}
		// A local command has no remote target to scope. A scope that also lists
		// in-scope network targets still scopes a command that names one.
		if !g.Scope.Empty() {
			targets, ok := ExtractTargets(c)
			if !ok {
				return g.deny("scope", c, "command has an unverifiable target (cannot confirm it is in scope)", "")
			}
			for _, tgt := range targets {
				if !g.Scope.InScope(tgt) {
					return g.deny("scope", c, "target out of scope: "+tgt, "")
				}
			}
		}
	} else {
		// EXTERNAL profile.
		// 2. structural classifier
		if d := Classify(c); !d.Allowed {
			return g.deny("classifier", c, d.Reason, d.Suggestion)
		}
		// 3. binary allowlist
		if g.Allow == nil || !g.Allow.Permits(c.Binary) {
			return g.deny("allowlist", c, fmt.Sprintf("binary %q is not on the allowlist", c.Binary), "")
		}
		// 4. scope.
		emptyScope := g.Scope == nil || g.Scope.Empty()
		switch {
		case g.Mode == Auto && emptyScope && !g.AutoScopeOverride:
			// Auto without a usable scope is denied even if Start was skipped.
			return g.deny("scope", c, "auto mode requires a non-empty scope", "")
		case g.Mode == Auto && emptyScope && g.AutoScopeOverride:
			// Logged no-scope override: fail closed on any network target (nothing
			// can be confirmed in scope), permit only no-target recon.
			targets, ok := ExtractTargets(c)
			if !ok {
				return g.deny("scope", c, "command has an unverifiable target (cannot confirm it is in scope)", "")
			}
			if len(targets) > 0 {
				return g.deny("scope", c, "no scope defined; target cannot be confirmed in scope: "+targets[0], "")
			}

			if a, bad := gluedShortFlag(c.Args, ""); bad {
				return g.deny("scope", c, "no scope defined; a glued or bundled short flag may hide a target that cannot be confirmed in scope: "+a, "")
			}
		case g.Scope != nil:
			targets, ok := ExtractTargets(c)
			if !ok {
				return g.deny("scope", c, "command has an unverifiable target (cannot confirm it is in scope)", "")
			}
			if len(targets) == 0 {
				return g.deny("scope", c, "no verifiable target to check against the scope", "")
			}
			for _, tgt := range targets {
				if !g.Scope.InScope(tgt) {
					return g.deny("scope", c, "target out of scope: "+tgt, "")
				}
			}
		}
	}
	// RoE rate limit is the last deny-layer: only an otherwise-admissible command
	// consumes a slot in the sliding window.
	if d := g.rateAllowLocked(c); !d.Allowed {
		return d
	}
	return Decision{Allowed: true}
}

// rateAllowLocked enforces the scope's optional "## Rate" policy. It assumes
// g.mu is held (it mutates g.rateHits). It prunes timestamps older than the
// window, denies when the window is already full, and otherwise records the
// admitted command's time. A nil scope or no rate policy is a no-op allow.
func (g *Gate) rateAllowLocked(c Command) Decision {
	if g.Scope == nil {
		return Decision{Allowed: true}
	}
	rl, ok := g.Scope.Rate()
	if !ok {
		return Decision{Allowed: true}
	}
	now := time.Now()
	if g.Now != nil {
		now = g.Now()
	}
	cutoff := now.Add(-rl.Per)
	kept := g.rateHits[:0]
	for _, t := range g.rateHits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	g.rateHits = kept
	if len(g.rateHits) >= rl.N {
		return g.deny("rate", c, fmt.Sprintf("rate limit exceeded: at most %d command(s) per %s", rl.N, rl.Per), "")
	}
	g.rateHits = append(g.rateHits, now)
	return Decision{Allowed: true}
}

// confirmTailLocked runs the confirmation step and audits the final decision. It
// is called with g.mu HELD and unlocks it on every return path. The ONLY work
// done outside the lock is the g.Confirm.Confirm call: needConfirm is decided
// under the lock (Approvals is g.mu-protected), the lock is released for the
// human prompt, then re-acquired before Remember and the audit. In Auto no
// confirmation is needed and it audits allow directly.
func (g *Gate) confirmTailLocked(ctx context.Context, c Command) Decision {
	localProfile := g.Scope != nil && g.Scope.Local()
	// Exploit and post-ex are the per-action-confirm tier: confirm every command
	// regardless of mode (Safe, Auto, local or external).
	force := c.Phase.perActionConfirm()
	needConfirm := g.Mode != Auto || localProfile || force

	if !needConfirm && g.UnattendedAllow != nil && !g.UnattendedAllow.Permits(c.Binary) {
		needConfirm = true
	}
	// Session-approval memoization is skipped for the per-action-confirm tier:
	// "per-action" means EVERY exploit/post-ex command is confirmed, even a repeat
	// of an identical binary+args. Signature omits phase/armed and Approvals is
	// shared across tasks, so without this a prior recon-context approval of the
	// same command line would suppress a later exploit-tier prompt.
	needConfirm = needConfirm && (force || g.Approvals == nil || !g.Approvals.Approved(c))
	if !needConfirm {
		g.audit("allow", Signature(c))
		g.mu.Unlock()
		return Decision{Allowed: true}
	}
	g.mu.Unlock()
	ok := g.Confirm != nil && g.Confirm.Confirm(ctx, c)
	g.mu.Lock()
	if !ok {
		d := g.deny("confirm", c, "command not confirmed by the operator", "")
		g.mu.Unlock()
		return d
	}
	if g.Approvals != nil {
		g.Approvals.Remember(c)
	}
	g.audit("allow", Signature(c))
	g.mu.Unlock()
	return Decision{Allowed: true}
}

// deniedByConfig reports whether c's binary base name matches any entry in the
// config denied_binaries list (case-insensitive base-name match, so a planted
// path to a denied name is caught too).
func deniedByConfig(binary string, denied []string) bool {
	if len(denied) == 0 {
		return false
	}
	b := strings.ToLower(baseName(strings.TrimSpace(binary)))
	if b == "" {
		return false
	}
	for _, d := range denied {
		if strings.ToLower(baseName(strings.TrimSpace(d))) == b {
			return true
		}
	}
	return false
}

func (g *Gate) deny(layer string, c Command, reason, suggestion string) Decision {
	g.audit("deny:"+layer, Signature(c)+" :: "+reason)
	return Decision{Allowed: false, Reason: reason, Suggestion: suggestion}
}
