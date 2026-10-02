package secgate

import (
	"context"
	"strings"
	"testing"
)

// okConfirmer approves every command; a nil Confirmer is absent (deny in the confirm tier).
type okConfirmer struct {
	called bool
	calls  int
}

func (c *okConfirmer) Confirm(ctx context.Context, cmd Command) bool {
	c.called = true
	c.calls++
	return true
}

// tierGate builds an Auto gate on an in-scope network scope with nmap allowed, so
// recon commands pass the deny-layers and only the tier logic is under test.
func tierGate(t *testing.T, confirm Confirmer) *Gate {
	t.Helper()
	s, err := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Auto, Scope: s, Allow: NewAllowlist("nmap"), Confirm: confirm, Approvals: NewSessionApprovals()}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestTierMatrixArmRequirement(t *testing.T) {
	for _, ph := range []Phase{PhaseExploit, PhasePostEx} {
		// Unarmed exploit/post-ex is refused regardless of mode.
		g := tierGate(t, &okConfirmer{})
		c := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}, Phase: ph, Armed: false}
		if d := g.Authorize(context.Background(), c); d.Allowed {
			t.Errorf("phase %q unarmed: Authorize allowed, want deny", ph)
		}
		// Armed exploit/post-ex forces per-action confirmation even in Auto.
		cf := &okConfirmer{}
		g2 := tierGate(t, cf)
		c.Armed = true
		if d := g2.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("phase %q armed+confirmed: Authorize denied: %s", ph, d.Reason)
		}
		if !cf.called {
			t.Errorf("phase %q armed: confirmer was not called (per-action confirm not forced in Auto)", ph)
		}
		// Armed exploit/post-ex with NO confirmer fails closed.
		g3 := tierGate(t, nil)
		if d := g3.Authorize(context.Background(), c); d.Allowed {
			t.Errorf("phase %q armed, no confirmer: allowed, want deny (fail closed)", ph)
		}
	}
}

// Surface is informational for the tier, so ad/cloud/per-CSP/container/ai-security
// do not perturb it. For every surface, recon stays auto and unarmed exploit stays
// refused.
func TestTierMatrixSurfaceAgnostic(t *testing.T) {
	surfaces := []Surface{
		SurfaceLocal, SurfaceNetwork, SurfaceWeb, SurfaceAD,
		SurfaceCloud, SurfaceCloudAWS, SurfaceCloudGCP, SurfaceCloudAzure,
		SurfaceContainer, SurfaceAISecurity,
	}
	for _, sf := range surfaces {
		// recon stays auto-tier regardless of surface.
		cf := &okConfirmer{}
		g := tierGate(t, cf)
		rc := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}, Surface: sf, Phase: PhaseRecon}
		if d := g.Authorize(context.Background(), rc); !d.Allowed {
			t.Errorf("surface %q recon: denied: %s", sf, d.Reason)
		}
		if cf.called {
			t.Errorf("surface %q recon: confirmer called (recon must stay auto-tier)", sf)
		}
		// unarmed exploit stays refused regardless of surface.
		g2 := tierGate(t, &okConfirmer{})
		ec := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}, Surface: sf, Phase: PhaseExploit, Armed: false}
		if d := g2.Authorize(context.Background(), ec); d.Allowed {
			t.Errorf("surface %q unarmed exploit: allowed, want deny", sf)
		}
	}
}

func TestTierMatrixReconReportAuto(t *testing.T) {
	// recon and report are auto-tier: allowed in Auto with no confirmation, no arm needed.
	for _, ph := range []Phase{PhaseRecon, PhaseReport, Phase("")} {
		cf := &okConfirmer{}
		g := tierGate(t, cf)
		c := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}, Phase: ph, Armed: false}
		if d := g.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("phase %q: Authorize denied: %s", ph, d.Reason)
		}
		if cf.called {
			t.Errorf("phase %q: confirmer called in Auto recon/report (should be auto-tier)", ph)
		}
	}
}

func TestArmingNeverRelaxesDenylists(t *testing.T) {
	// Each denylist still denies when armed in post-ex.
	armed := func(bin string, args ...string) Command {
		return Command{Binary: bin, Args: args, Phase: PhasePostEx, Armed: true}
	}
	// out-of-scope target: armed does not relax scope.
	g := tierGate(t, &okConfirmer{})
	if d := g.Authorize(context.Background(), armed("nmap", "-p", "80", "9.9.9.9")); d.Allowed {
		t.Errorf("armed post-ex out-of-scope target allowed, want deny")
	}
	// destructive binary denylist (LOCAL profile where rm is reachable).
	s, _ := ParseScope(strings.NewReader("local\n"))
	lg := &Gate{Mode: Auto, Scope: s, Confirm: &okConfirmer{}, Approvals: NewSessionApprovals()}
	if err := lg.Start(); err != nil {
		t.Fatal(err)
	}
	if d := lg.Authorize(context.Background(), armed("rm", "-rf", "/")); d.Allowed {
		t.Errorf("armed post-ex destructive command allowed, want deny")
	}
}

// I-1 regression: the per-action-confirm tier (exploit/post-ex) must NOT be
// suppressed by session-approval memoization. An identical command re-prompts
// every time, and a prior recon-context approval of the same binary+args must
// not suppress a later exploit-tier prompt (cross-phase bleed).
func TestPerActionConfirmIgnoresSessionApprovals(t *testing.T) {
	s, err := ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Repeat: an armed post-ex command confirmed once still prompts on an identical
	// second invocation. (Local profile always confirms, so this isolates the
	// approval short-circuit.)
	cf := &okConfirmer{}
	g := &Gate{Mode: Auto, Scope: s, Confirm: cf, Approvals: NewSessionApprovals()}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	cmd := Command{Binary: "id", Phase: PhasePostEx, Armed: true}
	if d := g.Authorize(context.Background(), cmd); !d.Allowed {
		t.Fatalf("first exploit confirm denied: %s", d.Reason)
	}
	if d := g.Authorize(context.Background(), cmd); !d.Allowed {
		t.Fatalf("second exploit confirm denied: %s", d.Reason)
	}
	if cf.calls < 2 {
		t.Errorf("per-action confirm: confirmer called %d times for 2 identical exploit commands, want 2", cf.calls)
	}

	// Cross-phase bleed: approve a recon command (remembered), then an identical
	// armed post-ex command must still prompt.
	cf2 := &okConfirmer{}
	g2 := &Gate{Mode: Auto, Scope: s, Confirm: cf2, Approvals: NewSessionApprovals()}
	if err := g2.Start(); err != nil {
		t.Fatal(err)
	}
	if d := g2.Authorize(context.Background(), Command{Binary: "id", Phase: PhaseRecon}); !d.Allowed {
		t.Fatalf("recon confirm denied: %s", d.Reason)
	}
	before := cf2.calls
	if d := g2.Authorize(context.Background(), Command{Binary: "id", Phase: PhasePostEx, Armed: true}); !d.Allowed {
		t.Fatalf("post-ex after recon approval denied: %s", d.Reason)
	}
	if cf2.calls <= before {
		t.Errorf("cross-phase bleed: identical armed post-ex after a recon approval did not re-prompt (calls stayed %d)", cf2.calls)
	}
}
