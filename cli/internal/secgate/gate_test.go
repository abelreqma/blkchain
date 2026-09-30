package secgate

import (
	"context"
	"strings"
	"testing"
)

func okScope(t *testing.T) *Scope {
	t.Helper()
	s, err := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAutoRefusesWithoutScope(t *testing.T) {
	g := &Gate{Mode: Auto, Allow: NewAllowlist("nmap")}
	if err := g.Start(); err == nil {
		t.Fatal("Auto must refuse to start without a valid scope")
	}
	empty, _ := ParseScope(strings.NewReader("# empty\n"))
	g2 := &Gate{Mode: Auto, Scope: empty, Allow: NewAllowlist("nmap")}
	if err := g2.Start(); err == nil {
		t.Fatal("Auto must refuse an empty scope")
	}
}

func TestAutoAllowsInScopeBoundedAllowlisted(t *testing.T) {
	g := &Gate{Mode: Auto, Scope: okScope(t), Allow: NewAllowlist("nmap")}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}})
	if !d.Allowed {
		t.Errorf("in-scope bounded allowlisted nmap should be allowed: %q", d.Reason)
	}
}

func TestAutoDeniesOutOfScope(t *testing.T) {
	g := &Gate{Mode: Auto, Scope: okScope(t), Allow: NewAllowlist("nmap")}
	g.Start()
	d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "8.8.8.8"}})
	if d.Allowed {
		t.Error("out-of-scope target must be denied")
	}
}

// recordingGate returns a gate whose audited actions are captured in *actions.
func recordingGate(g *Gate, actions *[]string) *Gate {
	g.Audit = func(action, detail string) { *actions = append(*actions, action) }
	return g
}

func lastAction(t *testing.T, actions []string) string {
	t.Helper()
	if len(actions) == 0 {
		t.Fatal("no audited action")
	}
	return actions[len(actions)-1]
}

func TestAutoDeniesUnlistedBinary(t *testing.T) {
	var actions []string
	g := recordingGate(&Gate{Mode: Auto, Scope: okScope(t), Allow: NewAllowlist("nmap")}, &actions)
	g.Start()
	d := g.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"10.0.0.5"}})
	if d.Allowed {
		t.Error("unlisted binary must be denied")
	}
	if got := lastAction(t, actions); got != "deny:allowlist" {
		t.Errorf("want deny:allowlist, got %q", got)
	}
}

func TestNilAllowlistDenies(t *testing.T) {
	var actions []string
	g := recordingGate(&Gate{Mode: Auto, Scope: okScope(t)}, &actions)
	g.Start()
	d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}})
	if d.Allowed {
		t.Error("a nil allowlist must deny")
	}
	if got := lastAction(t, actions); got != "deny:allowlist" {
		t.Errorf("want deny:allowlist, got %q", got)
	}
}

func TestAutoDeniesMetacharacter(t *testing.T) {
	g := &Gate{Mode: Auto, Scope: okScope(t), Allow: NewAllowlist("nmap")}
	g.Start()
	d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"10.0.0.5; rm -rf /"}})
	if d.Allowed {
		t.Error("metacharacter must be denied by the classifier before anything else")
	}
}

func TestAutoDeniesNoTargetUnderScope(t *testing.T) {
	var actions []string
	g := recordingGate(&Gate{Mode: Auto, Scope: okScope(t), Allow: NewAllowlist("nmap")}, &actions)
	g.Start()
	d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80"}})
	if d.Allowed {
		t.Error("a scoped command with no verifiable target must be denied")
	}
	if got := lastAction(t, actions); got != "deny:scope" {
		t.Errorf("want deny:scope, got %q", got)
	}
}

func TestAutoDeniesUnverifiableTargetUnderScope(t *testing.T) {
	// ExtractTargets returns ok=false for a CIDR arg (it cannot resolve a whole
	// CIDR against InScope), so the gate must fail closed even though the CIDR is
	// literally the scope. A bounded single-host command is required.
	g := &Gate{Mode: Auto, Scope: okScope(t), Allow: NewAllowlist("nmap")}
	g.Start()
	d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.0/24"}})
	if d.Allowed {
		t.Error("a command with an unverifiable (ok=false) target must be denied under scope")
	}
}

func TestAutoDeniesFlagEmbeddedOutOfScope(t *testing.T) {
	// The in-scope positional would pass, but the out-of-scope host hidden in a
	// flag value must still be extracted so the gate denies (no scope bypass).
	g := &Gate{Mode: Auto, Scope: okScope(t), Allow: NewAllowlist("curl")}
	g.Start()
	d := g.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"10.0.0.5", "--url=http://evil.com"}})
	if d.Allowed {
		t.Error("an out-of-scope host in a flag value must be denied (no bypass)")
	}
}

func TestSafeRequiresConfirmationAndRemembers(t *testing.T) {
	appr := NewSessionApprovals()
	g := &Gate{Mode: Safe, Allow: NewAllowlist("nmap"), Confirm: stubConfirmer{true}, Approvals: appr}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	cmd := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}
	if d := g.Authorize(context.Background(), cmd); !d.Allowed {
		t.Fatalf("confirmed command should be allowed: %q", d.Reason)
	}
	if !appr.Approved(cmd) {
		t.Error("an approved command should be remembered for the session")
	}
	// A denying confirmer denies a new command.
	g2 := &Gate{Mode: Safe, Allow: NewAllowlist("nmap"), Confirm: stubConfirmer{false}, Approvals: NewSessionApprovals()}
	g2.Start()
	if g2.Authorize(context.Background(), cmd).Allowed {
		t.Error("a denied confirmation must deny the command")
	}
}

func TestSafeNilConfirmerDenies(t *testing.T) {
	g := &Gate{Mode: Safe, Allow: NewAllowlist("nmap")} // no Confirm
	g.Start()
	if g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"10.0.0.5"}}).Allowed {
		t.Error("Safe mode with a nil confirmer must deny (fail closed)")
	}
}

func TestCapDenialShortCircuits(t *testing.T) {
	e := NewEpisode(Caps{MaxCommands: 1, MaxOutputBytes: 1000, Wall: 0}, nil)
	g := &Gate{Mode: Auto, Scope: okScope(t), Allow: NewAllowlist("nmap"), Episode: e}
	g.Start()
	cmd := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}
	if !g.Authorize(context.Background(), cmd).Allowed {
		t.Fatal("first command should pass")
	}
	if g.Authorize(context.Background(), cmd).Allowed {
		t.Error("second command must be denied by the command cap")
	}
}

func TestAuditRecordsEveryDecision(t *testing.T) {
	var actions []string
	g := &Gate{Mode: Auto, Scope: okScope(t), Allow: NewAllowlist("nmap"),
		Audit: func(action, detail string) { actions = append(actions, action) }}
	g.Start()
	g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}) // allow
	g.Authorize(context.Background(), Command{Binary: "bash", Args: []string{"10.0.0.5"}})             // deny
	if len(actions) != 2 {
		t.Fatalf("want 2 audited decisions, got %d: %v", len(actions), actions)
	}
}

func TestAutoAuthorizeWithoutStartDeniesNilScope(t *testing.T) {
	g := &Gate{Mode: Auto, Allow: NewAllowlist("nmap")} // Start skipped, no scope
	d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}})
	if d.Allowed {
		t.Error("Auto without a scope must deny even when Start was not called")
	}
}

func TestUnknownModeFailsClosed(t *testing.T) {
	g := &Gate{Mode: Mode(99), Allow: NewAllowlist("nmap")}
	if err := g.Start(); err == nil {
		t.Error("Start must reject an unknown mode")
	}
	d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}})
	if d.Allowed {
		t.Error("an unknown mode must not allow without confirmation")
	}
}

func TestAuthorizeRejectsUnknownModeEvenWithConfirmer(t *testing.T) {
	var actions []string
	g := recordingGate(&Gate{Mode: Mode(99), Allow: NewAllowlist("nmap"), Confirm: stubConfirmer{true}}, &actions)
	d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}})
	if d.Allowed {
		t.Fatal("an unknown mode must be denied in Authorize")
	}
	if got := lastAction(t, actions); got != "deny:mode" {
		t.Errorf("audited action = %q, want deny:mode", got)
	}
}

func TestApprovedCommandStillScopeChecked(t *testing.T) {
	var actions []string
	appr := NewSessionApprovals()
	g := recordingGate(&Gate{Mode: Safe, Scope: okScope(t), Allow: NewAllowlist("nmap"),
		Confirm: stubConfirmer{true}, Approvals: appr}, &actions)
	g.Start()
	in := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}
	if d := g.Authorize(context.Background(), in); !d.Allowed {
		t.Fatalf("approved in-scope command should be allowed: %q", d.Reason)
	}
	out := Command{Binary: "nmap", Args: []string{"-p", "80", "8.8.8.8"}}
	if appr.Approved(out) {
		t.Fatal("a different command must not be approved")
	}
	if d := g.Authorize(context.Background(), out); d.Allowed {
		t.Error("a non-approved out-of-scope command must be denied")
	}
	if got := lastAction(t, actions); got != "deny:scope" {
		t.Errorf("want deny:scope, got %q", got)
	}
}

func TestAutoLocalScopeAllowsNoTargetCommand(t *testing.T) {
	s, _ := ParseScope(strings.NewReader("local\n"))
	g := &Gate{Mode: Auto, Scope: s, Allow: NewAllowlist("id")}
	if err := g.Start(); err != nil {
		t.Fatalf("Auto with a local scope must start: %v", err)
	}
	d := g.Authorize(context.Background(), Command{Binary: "id"})
	if !d.Allowed {
		t.Errorf("a no-target local command should be allowed: %q", d.Reason)
	}
}

func TestAutoLocalStillDeniesOutOfScopeNetworkTarget(t *testing.T) {
	s, _ := ParseScope(strings.NewReader("local\n10.0.0.0/24\n"))
	g := &Gate{Mode: Auto, Scope: s, Allow: NewAllowlist("curl")}
	g.Start()
	d := g.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"http://8.8.8.8/"}})
	if d.Allowed {
		t.Error("local mode must NOT allow an out-of-scope network target")
	}
}

func TestAutoNonLocalStillDeniesNoTarget(t *testing.T) {
	s, _ := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	g := &Gate{Mode: Auto, Scope: s, Allow: NewAllowlist("id")}
	g.Start()
	if g.Authorize(context.Background(), Command{Binary: "id"}).Allowed {
		t.Error("a non-local scope must still deny a no-target command")
	}
}

func TestAutoLocalDeniesNetworkBinaryWithSingleLabelHost(t *testing.T) {
	s, _ := ParseScope(strings.NewReader("local\n"))
	g := &Gate{Mode: Auto, Scope: s, Allow: NewAllowlist("curl", "nc", "id", "uname", "socat")}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	denied := []Command{
		{Binary: "curl", Args: []string{"intranet"}},
		{Binary: "/usr/bin/curl", Args: []string{"intranet"}},
		{Binary: "nc", Args: []string{"internal-host", "22"}},
		// socat is not a known local tool; an operator allowlisting it must not
		// bypass the target check via a single-label (no-extracted-target) host.
		// This is the positive-check regression test: the old denylist let an
		// allowlisted-but-unlisted binary like socat through here.
		{Binary: "socat", Args: []string{"internal-host"}},
	}
	for _, c := range denied {
		if d := g.Authorize(ctx, c); d.Allowed {
			t.Errorf("%v must be denied in local mode (not a known local tool, no in-scope target)", c)
		}
	}
	allowed := []Command{
		{Binary: "id"},
		{Binary: "uname", Args: []string{"-a"}},
	}
	for _, c := range allowed {
		if d := g.Authorize(ctx, c); !d.Allowed {
			t.Errorf("%v must be allowed in local mode: %q", c, d.Reason)
		}
	}
}
