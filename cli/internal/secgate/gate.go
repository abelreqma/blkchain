package secgate

import (
	"context"
	"errors"
	"fmt"
)

// Gate composes every security layer. It performs no execution.
type Gate struct {
	Mode      Mode
	Scope     *Scope                      // may be nil in Safe; must be non-nil and non-empty in Auto
	Allow     *Allowlist                  // nil permits nothing (fail closed)
	Confirm   Confirmer                   // used in Safe; nil denies in Safe
	Approvals *SessionApprovals           // nil remembers no repeats
	Episode   *Episode                    // nil gets a default-caps episode
	Audit     func(action, detail string) // nil is a no-op
}

// Start validates the gate for its mode. Auto refuses without a non-empty scope.
func (g *Gate) Start() error {
	if g.Mode != Safe && g.Mode != Auto {
		return fmt.Errorf("secgate: unknown mode %d", int(g.Mode))
	}
	if g.Mode == Auto {
		if g.Scope == nil || g.Scope.Empty() {
			return errors.New("secgate: /auto requires a valid non-empty scope file")
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
// session-approved). It never executes anything.
func (g *Gate) Authorize(ctx context.Context, c Command) Decision {
	if g.Episode == nil {
		g.Episode = NewEpisode(Caps{}, nil)
	}
	if g.Mode != Safe && g.Mode != Auto {
		return g.deny("mode", c, "unknown mode", "")
	}
	// 1. caps and circuit breaker
	if ok, reason := g.Episode.AllowCommand(); !ok {
		return g.deny("cap", c, reason, "")
	}
	// 2. structural classifier
	if d := Classify(c); !d.Allowed {
		return g.deny("classifier", c, d.Reason, d.Suggestion)
	}
	// 3. binary allowlist
	if g.Allow == nil || !g.Allow.Permits(c.Binary) {
		return g.deny("allowlist", c, fmt.Sprintf("binary %q is not on the allowlist", c.Binary), "")
	}
	// 4. scope. Auto without a usable scope is denied even if Start was skipped.
	if g.Mode == Auto && (g.Scope == nil || g.Scope.Empty()) {
		return g.deny("scope", c, "auto mode requires a non-empty scope", "")
	}
	if g.Scope != nil {
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
	// 5. confirmation (every mode except Auto, so an unknown mode fails strict)
	if g.Mode != Auto {
		if g.Approvals == nil || !g.Approvals.Approved(c) {
			if g.Confirm == nil || !g.Confirm.Confirm(ctx, c) {
				return g.deny("confirm", c, "command not confirmed by the operator", "")
			}
			if g.Approvals != nil {
				g.Approvals.Remember(c)
			}
		}
	}
	g.audit("allow", Signature(c))
	return Decision{Allowed: true}
}

func (g *Gate) deny(layer string, c Command, reason, suggestion string) Decision {
	g.audit("deny:"+layer, Signature(c)+" :: "+reason)
	return Decision{Allowed: false, Reason: reason, Suggestion: suggestion}
}
