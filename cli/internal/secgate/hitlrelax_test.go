package secgate

import (
	"context"
	"strings"
	"testing"
)

// declineConfirmer refuses every command (and counts calls).
type declineConfirmer struct{ calls int }

func (c *declineConfirmer) Confirm(ctx context.Context, cmd Command) bool { c.calls++; return false }

// unattendedAutoGate is Auto on an in-scope network scope where `bin` is both
// allowlisted and permitted unattended, with a confirmer present. This is the
// UNATTENDED path: humanGovernedPath is false, so structural denials must stay.
func unattendedAutoGate(t *testing.T, bin string, confirm Confirmer) *Gate {
	t.Helper()
	s, err := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{
		Mode: Auto, Scope: s,
		Allow:           NewAllowlist(bin),
		UnattendedAllow: NewAllowlist(bin),
		Confirm:         confirm,
		Approvals:       NewSessionApprovals(),
	}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	return g
}

// localConfirmGate is a LOCAL (always-confirm) gate with the given confirmer.
func localConfirmGate(t *testing.T, confirm Confirmer) *Gate {
	t.Helper()
	s, err := ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Auto, Scope: s, Confirm: confirm, Approvals: NewSessionApprovals()}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	return g
}

// --- KEEP: structural denials stay on the UNATTENDED path ---

func TestUnattendedAutoStillDeniesShell(t *testing.T) {
	// bash is allowlisted AND permitted unattended, with a confirmer present, so
	// only the structural denial can block it. It must still be denied.
	g := unattendedAutoGate(t, "bash", &okConfirmer{})
	d := g.Authorize(context.Background(), Command{Binary: "bash", Args: []string{"-lc", "id"}})
	if d.Allowed {
		t.Errorf("unattended Auto allowed a shell, want structural deny")
	}
}

func TestUnattendedAutoStillDeniesMetacharAndExecFlag(t *testing.T) {
	// metachar in an arg of an allowed binary, unattended -> still denied.
	g := unattendedAutoGate(t, "nmap", &okConfirmer{})
	if d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "a;b"}}); d.Allowed {
		t.Errorf("unattended Auto allowed a metachar arg, want structural deny")
	}
	// nmap --script (NSE RCE) unattended -> still denied.
	if d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "--script=http-title", "10.0.0.5"}}); d.Allowed {
		t.Errorf("unattended Auto allowed nmap --script, want structural deny")
	}
}

// --- RELAX: human-confirmed paths SURFACE structural commands for approval ---

func TestLocalConfirmedSurfacesShell(t *testing.T) {
	// LOCAL always-confirm: a shell is surfaced for approval, not auto-denied. With
	// an approving confirmer it runs.
	cf := &okConfirmer{}
	g := localConfirmGate(t, cf)
	d := g.Authorize(context.Background(), Command{Binary: "bash", Args: []string{"-lc", "id; whoami"}})
	if !d.Allowed {
		t.Errorf("LOCAL confirmed shell denied: %s", d.Reason)
	}
	if cf.calls == 0 {
		t.Errorf("LOCAL confirmed shell was not surfaced to the confirmer")
	}
}

func TestLocalConfirmedShellDeclinedDenies(t *testing.T) {
	// The decline is a confirmation decision, not a structural auto-deny.
	cf := &declineConfirmer{}
	g := localConfirmGate(t, cf)
	d := g.Authorize(context.Background(), Command{Binary: "python3", Args: []string{"-c", "print(1)"}})
	if d.Allowed {
		t.Errorf("LOCAL declined interpreter allowed, want deny")
	}
	if cf.calls == 0 {
		t.Errorf("LOCAL interpreter was not surfaced to the confirmer (auto-denied structurally?)")
	}
}

func TestAutoHITLFallbackSurfacesExecFlag(t *testing.T) {
	// Auto with an empty unattended bound -> every command is HITL. A bounded
	// nmap --script (allowlisted, not permitted unattended) is surfaced + runs.
	s, err := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	cf := &okConfirmer{}
	g := &Gate{
		Mode: Auto, Scope: s,
		Allow:           NewAllowlist("nmap"),
		UnattendedAllow: NewAllowlist(), // empty -> HITL fallback for every binary
		Confirm:         cf,
		Approvals:       NewSessionApprovals(),
	}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "--script=http-title", "10.0.0.5"}})
	if !d.Allowed {
		t.Errorf("Auto HITL-fallback denied an exec flag that should surface: %s", d.Reason)
	}
	if cf.calls == 0 {
		t.Errorf("Auto HITL-fallback exec flag was not surfaced to the confirmer")
	}
}

func TestNoConfirmerStillDeniesStructuralOnLocal(t *testing.T) {
	// LOCAL with NO confirmer is not a human-governed path: structural denials stay
	// and the command fails closed.
	g := localConfirmGate(t, nil)
	d := g.Authorize(context.Background(), Command{Binary: "bash", Args: []string{"-lc", "id"}})
	if d.Allowed {
		t.Errorf("LOCAL with no confirmer allowed a shell, want deny (fail closed)")
	}
}

// --- KEEP: destructive, scope, empty-binary, enum stay even when confirmed ---

func TestConfirmedPathStillDeniesDestructive(t *testing.T) {
	g := localConfirmGate(t, &okConfirmer{})
	if d := g.Authorize(context.Background(), Command{Binary: "rm", Args: []string{"-rf", "/"}}); d.Allowed {
		t.Errorf("LOCAL confirmed allowed a destructive command, want deny (destructive denylist kept)")
	}
}

func TestConfirmedPathStillEnforcesScope(t *testing.T) {
	// Safe EXTERNAL (human-governed): an out-of-scope target is still denied by scope.
	s, _ := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	g := &Gate{Mode: Safe, Scope: s, Allow: NewAllowlist("nmap"), Confirm: &okConfirmer{}, Approvals: NewSessionApprovals()}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	if d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "9.9.9.9"}}); d.Allowed {
		t.Errorf("confirmed path allowed an out-of-scope target, want deny (scope kept)")
	}
}

func TestConfirmedPathStillDeniesEmptyBinaryAndEnum(t *testing.T) {
	// Empty binary denied even on a confirmed path.
	g := localConfirmGate(t, &okConfirmer{})
	if d := g.Authorize(context.Background(), Command{Binary: "  "}); d.Allowed {
		t.Errorf("confirmed path allowed an empty binary, want deny")
	}
	// A credential-file enum flag (ldapsearch -y) is non-structural and stays denied.
	s, _ := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	g2 := &Gate{Mode: Safe, Scope: s, Allow: NewAllowlist("ldapsearch"), Confirm: &okConfirmer{}, Approvals: NewSessionApprovals()}
	if err := g2.Start(); err != nil {
		t.Fatal(err)
	}
	if d := g2.Authorize(context.Background(), Command{Binary: "ldapsearch", Args: []string{"-y", "/etc/creds", "-H", "ldap://10.0.0.5"}}); d.Allowed {
		t.Errorf("confirmed path allowed a credential-file enum flag, want deny (enum denial kept)")
	}
}
