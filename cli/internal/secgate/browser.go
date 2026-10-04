package secgate

import (
	"context"
	"net/url"
	"strings"
)

// browser.go adds the single-gate authorization entrypoints for browser
// automation and API testing. Both are target-touching actions but neither is a subprocess, so they
// use the same Gate as command execution. The subprocess allowlist and shell/argv
// classifier do not apply. The phase tier (active actions require an armed task),
// scope check, RoE rate window, audit log, and Auto unattended-allowlist policy
// still apply. Redirects are checked through AuthorizeWebRedirect. The gate does
// no browser/network I/O and triggers no driver download.

// BrowserAction is a browser action presented to the gate: the absolute
// http/https URL to act on, whether it is Active (injects or changes state, vs a
// passive navigation or read), and whether the task is Armed.
type BrowserAction struct {
	URL    string
	Active bool
	Armed  bool
}

// APIRequest is an API request presented to the gate: the HTTP method, the
// absolute http/https URL, and whether the task is Armed. A read-only method is
// recon; any state-changing method is exploit-tiered.
type APIRequest struct {
	Method string
	URL    string
	Armed  bool
}

// apiMethodActive reports whether an HTTP method is state-changing (exploit
// tier). Read-only methods (GET, HEAD, OPTIONS) are passive (recon);
// every other method, including an unknown one (fail-safe to the stricter tier),
// is active.
func apiMethodActive(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "OPTIONS":
		return false
	}
	return true
}

// webActionCommand represents a web action as a Command for the gate's scope
// extraction, tier, confirmation display, recheck, rate, and audit. It is NEVER
// executed as a subprocess: Binary is a non-executable label and the allowlist
// and shell/argv classifier are deliberately not run for it. An active action is
// PhaseExploit (requiresArm); a passive one is PhaseRecon. The gate's Auto
// policy decides whether to prompt after scope and tier checks pass.
func webActionCommand(label, url string, active, armed bool) Command {
	phase := PhaseRecon
	if active {
		phase = PhaseExploit
	}
	return Command{Binary: label, Args: []string{url}, Phase: phase, Surface: SurfaceWeb, Armed: armed, AutonomousWeb: true}
}

// AuthorizeBrowser authorizes one browser action through the single gate.
func (g *Gate) AuthorizeBrowser(ctx context.Context, a BrowserAction) Decision {
	label := "web-browser:navigate"
	if a.Active {
		label = "web-browser:active"
	}
	return g.authorizeWebAction(ctx, webActionCommand(label, a.URL, a.Active, a.Armed))
}

// AuthorizeAPIRequest authorizes one API request through the single gate.
func (g *Gate) AuthorizeAPIRequest(ctx context.Context, r APIRequest) Decision {
	active := apiMethodActive(r.Method)
	label := "web-api:" + strings.ToUpper(strings.TrimSpace(r.Method))
	return g.authorizeWebAction(ctx, webActionCommand(label, r.URL, active, r.Armed))
}

// authorizeWebAction runs the shared deny pipeline for a web action: mode, caps,
// phase tier, scope, and rate (all under g.mu), then the confirmation tail (which
// releases g.mu), then the exec-time scope recheck. It mirrors
// Gate.Authorize but omits the binary allowlist and the shell/argv classifier,
// which do not apply to a non-subprocess action. Everything else - the tier arm
// requirement, mode-specific confirmation, scope, RoE rate, audit, and
// resolve-and-recheck - is identical to the command path.
func (g *Gate) authorizeWebAction(ctx context.Context, c Command) Decision {
	g.mu.Lock()
	if g.Episode == nil {
		g.Episode = NewEpisode(Caps{}, nil)
	}
	if g.Mode != Safe && g.Mode != Auto {
		d := g.deny("mode", c, "unknown mode", "")
		g.mu.Unlock()
		return d
	}
	if ok, reason := g.Episode.AllowCommand(); !ok {
		d := g.deny("cap", c, reason, "")
		g.mu.Unlock()
		return d
	}
	// Phase tier: an active (state-changing or injecting) web action is exploit
	// and requires an armed task, in both modes. Arming is a precondition the
	// operator sets; it relaxes no denylist.
	if c.Phase.requiresArm() && !c.Armed {
		d := g.deny("tier", c, "active web action (injection or state-changing) requires an armed task", "arm the task before an injecting or state-changing browser or API action")
		g.mu.Unlock()
		return d
	}
	if d := g.webScopeCheck(c); !d.Allowed {
		g.mu.Unlock()
		return d
	}
	if d := g.rateAllowLocked(c); !d.Allowed {
		g.mu.Unlock()
		return d
	}
	// Confirmation tail applies Safe-mode confirmation and the Auto-mode
	// unattended allowlist policy. An armed web action does not force a prompt in
	// Auto solely because it is active.
	d := g.confirmTailLocked(ctx, c)
	if !d.Allowed {
		return d
	}
	run := d.Command
	if run.Binary == "" {
		run = c
	}
	fin := g.recheck(run)
	fin.Command = run
	return fin
}

// webScopeCheck runs the scope deny-layer for a web action. It reads only
// immutable gate state (Scope, Mode, AutoScopeOverride) and the concurrency-safe
// audit func, so it is safe both under g.mu (authorizeWebAction) and without it
// (AuthorizeWebRedirect). An empty or absent scope in Auto, without the explicit
// override, is denied; otherwise the URL host is extracted and must be InScope.
func (g *Gate) webScopeCheck(c Command) Decision {
	emptyScope := g.Scope == nil || g.Scope.Empty()
	if emptyScope {
		return g.deny("scope", c, "web actions require an explicit non-empty network scope", "")
	}
	targets, ok := ExtractTargets(c)
	if !ok {
		return g.deny("scope", c, "web action url has an unverifiable host (cannot confirm it is in scope)", "")
	}
	if len(targets) == 0 {
		return g.deny("scope", c, "web action url has no verifiable host to scope-check", "")
	}
	for _, t := range targets {
		if !g.Scope.InScope(t) {
			return g.deny("scope", c, "web action target out of scope: "+t, "")
		}
	}
	return Decision{Allowed: true}
}

// AuthorizeWebRedirect re-validates a redirect hop of an already-authorized web
// action: the new location's host must still be in scope and resolve in scope. It
// applies NO tier, confirmation, or rate (the action was already authorized); it
// exists so a 30x cannot carry the browser or API client to an out-of-scope or
// internal host (for example cloud metadata at 169.254.169.254). The driver MUST
// call it for every redirect hop and abort the navigation on a deny.
func (g *Gate) AuthorizeWebRedirect(location string) Decision {
	c := webActionCommand("web-redirect", location, false, false)
	u, err := url.Parse(location)
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return g.deny("scope", c, "web redirect has an invalid or credential-bearing URL", "")
	}
	if d := g.webScopeCheck(c); !d.Allowed {
		return d
	}
	return g.recheck(c)
}
