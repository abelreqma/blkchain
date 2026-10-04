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

	// Now returns the current time for the RoE rate limiter. A nil Now uses
	// time.Now; tests inject a controllable clock. rateHits is the sliding window
	// of admitted-command timestamps, guarded by g.mu.
	Now      func() time.Time
	rateHits []time.Time

	// .blkchain/config.yaml gate policy.
	//
	// ConfigDenied is the per-project denied_binaries list, matched by lowercased
	// base name in BOTH profiles and always respected (arming never relaxes it).
	//
	// UnattendedAllow is the unattended-/auto allowlist bound (config
	// allowed_binaries). A nil UnattendedAllow runs Auto unattended. A non-nil
	// UnattendedAllow (even empty) means a command whose binary it does not permit
	// must be confirmed (HITL) in Auto non-local; a present-but-empty bound forces
	// confirmation for every Auto command, the no-allowlist floor.
	//
	// AllowInterpreterPoC is plumbed from config for the interpreter-PoC HITL
	// exception; this policy layer does not act on it.
	ConfigDenied        []string
	UnattendedAllow     *Allowlist
	AllowInterpreterPoC bool

	// AutoScopeOverride is the explicit, logged operator override that relaxes
	// "/auto requires a scope" to "/auto requires scope OR an override". It
	// permits Auto to start with no scope; a one-time `override`
	// audit line records it. Even under the override every command naming a
	// network target still fails closed (no scope can confirm it is in scope), so
	// only no-target recon proceeds autonomously.
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
	run := d.Command
	if run.Binary == "" {
		run = c // defensive: a confirmer that did not set the authorized command
	}
	if !sameCommand(run, c) {
		// Operator-edited substitute: re-run the FULL deny pipeline on it (fresh
		// classifier, scope, denylists, tier) with the inherited tier context. The
		// operator authored it, so no second confirmation; a failed deny-layer
		// returns the denial for the caller to surface and let the operator edit again.
		g.mu.Lock()
		rc := g.checkLocked(run)
		g.mu.Unlock()
		if !rc.Allowed {
			return rc
		}
	}
	fin := g.recheck(run)
	fin.Command = run
	return fin
}

// sameCommand reports whether two commands have the same binary and literal args
// (the fields an operator edit may change); Phase/Surface/Armed are inherited on
// an edit, so they never differ here.
func sameCommand(a, b Command) bool {
	if a.Binary != b.Binary || len(a.Args) != len(b.Args) {
		return false
	}
	for i := range a.Args {
		if a.Args[i] != b.Args[i] {
			return false
		}
	}
	return true
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
	fin := g.recheck(c)
	if fin.Allowed {
		fin.Command = c
	}
	return fin
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
	// Config denylist: always respected, in both profiles, before the profile
	// split. Arming never relaxes it.
	if deniedByConfig(c.Binary, g.ConfigDenied) {
		return g.deny("config-denylist", c, "binary "+c.Binary+" is denied by .blkchain/config.yaml", "")
	}
	// Phase tier: exploit and post-ex require an armed task, in both profiles
	// and both modes. Arming is a precondition the operator sets; it never relaxes
	// the denylists below (they all still run). An empty/unknown phase fails safe
	// to recon (no arm requirement).
	if c.Phase.requiresArm() && !c.Armed {
		return g.deny("tier", c, "exploit/post-ex phase requires an armed task", "arm the task before running an exploit or post-exploitation command")
	}
	// A target-analysis task must never EXECUTE its own analysis target.
	// Always-on structural denial, placed before the human-governed-path relaxation
	// and the LOCAL/EXTERNAL split, so it runs on every path (Authorize, Check, and
	// the operator-edit re-validation) and arming, mode, profile, and the
	// human-confirmed classifier relaxations never reach it. Inert for any
	// non-target-analysis Kind and for an empty Target, so it moves no other verdict.
	if tgt, bad := TargetSelfExecViolation(c, g.Scratch); bad {
		return g.deny("target-self-exec", c, "a target-analysis task must not execute its own analysis target: "+tgt, "inspect the target read-only (file, stat, nm, readelf, objdump, strings, ldd, getcap) instead of executing it")
	}
	// Human-governed paths (LOCAL always-confirm, Safe, the Auto HITL-fallback)
	// relax the structural shell/interpreter/exec-wrapper/metacharacter/exec-flag
	// denials: the operator approves the exact argv. Unattended paths (Auto with the
	// binary permitted by allowed_binaries, no HITL) keep the structural denials -
	// the deny-list-only-unattended invariant. The non-structural denials (empty
	// binary, resource bounds, enumeration scope-evasion/credential/config-file) and
	// the destructive, sensitive-path, scope, config-denylist, and tier layers below
	// hold on every path.
	confirmed := g.humanGovernedPath(c)
	if g.Scope != nil && g.Scope.Local() {
		// LOCAL profile: no binary allowlist. The structural denials keep gating
		// enforceable when unattended; a confirmed path relaxes them (empty-binary
		// check only), leaving destructive/sensitive-path/scope below.
		classify := ClassifyLocal
		if confirmed {
			classify = ClassifyLocalConfirmed
		}
		if d := classify(c); !d.Allowed {
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
		// 2. structural classifier (relaxed to the non-structural denials on a
		// confirmed path; the allowlist below is a separate, always-enforced control).
		classify := Classify
		if confirmed {
			classify = ClassifyExternalConfirmed
		}
		if d := classify(c); !d.Allowed {
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
			// Backstop: a glued or bundled single-dash short flag (-h10.0.0.5,
			// -sx10.0.0.5) can hide a host the extractor drops. Under a real scope
			// such a command is denied as "no verifiable target"; with no scope we
			// cannot verify it either, so deny it here rather than let it run as
			// "no-target recon". This closes the override-path reach of the known
			// glued-flag extractor gap for allowlisted tools whose per-tool
			// classifier audit does not cover the flag.
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

// humanGovernedPath reports whether command c will be put to a human confirmer:
// LOCAL (always-confirm), Safe mode, or the Auto HITL-fallback (a binary not
// permitted by the unattended allowed_binaries bound, or an exploit/post-ex
// per-action-confirm command). Only on such a path are the structural code-exec
// denials relaxed; an UNATTENDED Auto command (binary permitted unattended, or a
// nil bound) stays strict. It fails closed: with no confirmer there is no
// human, so it returns false and the structural denials hold. It assumes g.mu is
// held (it reads config fields set at construction). It is deliberately consistent
// with confirmTailLocked's needConfirm, minus the session-approval memoization - a
// remembered approval was still a human decision and does not make a path
// unattended.
func (g *Gate) humanGovernedPath(c Command) bool {
	if g.Confirm == nil {
		return false
	}
	if g.Mode != Auto || (g.Scope != nil && g.Scope.Local()) {
		return true
	}
	if c.Phase.perActionConfirm() {
		return true
	}
	if g.UnattendedAllow != nil && !g.UnattendedAllow.Permits(c.Binary) {
		return true
	}
	return false
}

// confirmTailLocked runs the confirmation step and audits the final decision. It
// is called with g.mu HELD and unlocks it on every return path. The ONLY work
// done outside the lock is the g.Confirm.Confirm call: needConfirm is decided
// under the lock (Approvals is g.mu-protected), the lock is released for the
// human prompt, then re-acquired before Remember and the audit. In Auto no
// confirmation is needed and it audits allow directly.
func (g *Gate) confirmTailLocked(ctx context.Context, c Command) Decision {
	localProfile := g.Scope != nil && g.Scope.Local()
	// Exploit and post-ex commands require per-action confirmation, except for
	// code-authorized web actions in Auto after their task is armed.
	force := c.Phase.perActionConfirm() && !(g.Mode == Auto && c.Surface == SurfaceWeb && c.AutonomousWeb)
	needConfirm := g.Mode != Auto || localProfile || force
	// Unattended-/auto bound: in Auto non-local, a command whose binary is
	// not permitted by the config allowed_binaries list must be confirmed (HITL).
	// A nil UnattendedAllow adds no extra confirmation. A present-but-empty
	// bound forces confirmation for every Auto command (the no-allowlist floor).
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
		return Decision{Allowed: true, Command: c}
	}
	g.mu.Unlock()
	// The confirmation runs outside g.mu. An EditConfirmer may also return an
	// operator-edited substitute; a plain Confirmer returns only allow/deny. A nil
	// g.Confirm matches neither case and fails closed (deny).
	var ok bool
	var edited *Command
	switch cf := g.Confirm.(type) {
	case EditConfirmer:
		ok, edited = cf.ConfirmOrEdit(ctx, c)
	case Confirmer:
		ok = cf.Confirm(ctx, c)
	}
	g.mu.Lock()
	if !ok {
		d := g.deny("confirm", c, "command not confirmed by the operator", "")
		g.mu.Unlock()
		return d
	}
	// An edit substitutes only Binary+Args; it INHERITS the original's Phase/Surface/
	// Armed so the operator cannot change the tier via the edit. The caller
	// re-validates the substitute through the full deny pipeline before running it.
	run := c
	if edited != nil {
		run = Command{Binary: edited.Binary, Args: edited.Args, Phase: c.Phase, Surface: c.Surface, Armed: c.Armed}
	}
	// Memoize only an un-edited approval; a one-off edit is not remembered.
	if edited == nil && g.Approvals != nil {
		g.Approvals.Remember(c)
	}
	g.audit("allow", Signature(run))
	g.mu.Unlock()
	return Decision{Allowed: true, Command: run}
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
