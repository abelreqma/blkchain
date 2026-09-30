package secgate

import (
	"context"
	"strings"
	"testing"
	"time"
)

// blockingConfirmer signals entered when Confirm is entered, then blocks until
// release is closed. It models a slow human at the confirmation prompt.
type blockingConfirmer struct {
	entered chan struct{}
	release chan struct{}
}

func (b blockingConfirmer) Confirm(ctx context.Context, c Command) bool {
	close(b.entered)
	<-b.release
	return true
}

// countingConfirmer records how many times Confirm was called and returns ok.
type countingConfirmer struct {
	ok    bool
	calls int
}

func (c *countingConfirmer) Confirm(ctx context.Context, cmd Command) bool {
	c.calls++
	return c.ok
}

// TestSafeConfirmsOncePerCommand: a /safe command prompts exactly once; an
// identical second Authorize is remembered (no second prompt); a refusing
// confirmer denies with deny:confirm and Allowed=false.
func TestSafeConfirmsOncePerCommand(t *testing.T) {
	cc := &countingConfirmer{ok: true}
	appr := NewSessionApprovals()
	g := &Gate{Mode: Safe, Allow: NewAllowlist("nmap"), Confirm: cc, Approvals: appr}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	cmd := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}
	if d := g.Authorize(context.Background(), cmd); !d.Allowed {
		t.Fatalf("first confirmed command should be allowed: %q", d.Reason)
	}
	if cc.calls != 1 {
		t.Fatalf("Confirm called %d times on first authorize, want 1", cc.calls)
	}
	if d := g.Authorize(context.Background(), cmd); !d.Allowed {
		t.Fatalf("remembered command should be allowed: %q", d.Reason)
	}
	if cc.calls != 1 {
		t.Errorf("Confirm called %d times total, want 1 (second call must be remembered)", cc.calls)
	}

	var actions []string
	deny := &countingConfirmer{ok: false}
	g2 := recordingGate(&Gate{Mode: Safe, Allow: NewAllowlist("nmap"), Confirm: deny, Approvals: NewSessionApprovals()}, &actions)
	g2.Start()
	if d := g2.Authorize(context.Background(), cmd); d.Allowed {
		t.Error("a refusing confirmer must deny")
	}
	if got := lastAction(t, actions); got != "deny:confirm" {
		t.Errorf("want deny:confirm, got %q", got)
	}
}

// TestConfirmRunsOutsideMutex proves Authorize does NOT hold g.mu across the
// human confirmation: while one Authorize is blocked inside a slow Confirm, a
// second Authorize that needs only the lock (an already-approved command, so no
// confirm) must return promptly. If Confirm ran under g.mu the second call would
// block on the mutex and the test would time out. It also checks the shared
// episode budget counts both commands exactly once.
func TestConfirmRunsOutsideMutex(t *testing.T) {
	s, err := ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}
	bc := blockingConfirmer{entered: make(chan struct{}), release: make(chan struct{})}
	appr := NewSessionApprovals()
	cmdB := Command{Binary: "id", Args: []string{"b"}}
	appr.Remember(cmdB) // cmdB is pre-approved: its Authorize needs only the lock, no confirm.
	g := &Gate{
		Mode:      Safe,
		Scope:     s,
		Confirm:   bc,
		Approvals: appr,
		Episode:   NewEpisode(Caps{MaxCommands: 10}, nil),
	}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}

	// cmdA needs confirmation and blocks inside Confirm.
	aDone := make(chan Decision, 1)
	go func() {
		aDone <- g.Authorize(context.Background(), Command{Binary: "id", Args: []string{"a"}})
	}()
	<-bc.entered // cmdA is now inside Confirm; if the lock is held, it is held now.

	// cmdB needs only the lock. It must not be serialized behind cmdA's prompt.
	bDone := make(chan Decision, 1)
	go func() {
		bDone <- g.Authorize(context.Background(), cmdB)
	}()
	select {
	case d := <-bDone:
		if !d.Allowed {
			t.Fatalf("pre-approved cmdB should be allowed: %q", d.Reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cmdB blocked while cmdA was in Confirm: Authorize held g.mu across the human prompt")
	}

	close(bc.release) // let cmdA finish.
	select {
	case d := <-aDone:
		if !d.Allowed {
			t.Fatalf("confirmed cmdA should be allowed: %q", d.Reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cmdA never completed after release")
	}

	// Both commands consumed exactly one budget slot: no double-count, no loss.
	if g.Episode.count != 2 {
		t.Errorf("episode count = %d, want 2", g.Episode.count)
	}
}

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
	// LOCAL scope requires per-command confirmation in every mode, so an /auto
	// local command is allowed only once a confirmer approves it.
	s, _ := ParseScope(strings.NewReader("local\n"))
	g := &Gate{Mode: Auto, Scope: s, Allow: NewAllowlist("id"), Confirm: stubConfirmer{true}, Approvals: NewSessionApprovals()}
	if err := g.Start(); err != nil {
		t.Fatalf("Auto with a local scope must start: %v", err)
	}
	d := g.Authorize(context.Background(), Command{Binary: "id"})
	if !d.Allowed {
		t.Errorf("a no-target local command should be allowed: %q", d.Reason)
	}
}

// TestLocalAutoRequiresConfirm: LOCAL scope forces per-command confirmation even
// in Auto. An allowed-by-denylists command is put to Confirm (once) and allowed
// on approval; an identical second call is remembered (not re-prompted). With a
// nil confirmer the command is denied (fail-closed). Contrast: an EXTERNAL /auto
// command with a target and allowlist is NOT confirmed.
func TestLocalAutoRequiresConfirm(t *testing.T) {
	local, err := ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := Command{Binary: "id"}

	cc := &countingConfirmer{ok: true}
	g := &Gate{Mode: Auto, Scope: local, Confirm: cc, Approvals: NewSessionApprovals()}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	if d := g.Authorize(context.Background(), cmd); !d.Allowed {
		t.Fatalf("local /auto command should be allowed on approval: %q", d.Reason)
	}
	if cc.calls != 1 {
		t.Fatalf("Confirm called %d times on first authorize, want 1 (local /auto must confirm)", cc.calls)
	}
	if d := g.Authorize(context.Background(), cmd); !d.Allowed {
		t.Fatalf("remembered local command should be allowed: %q", d.Reason)
	}
	if cc.calls != 1 {
		t.Errorf("Confirm called %d times total, want 1 (second call must be remembered)", cc.calls)
	}

	// Fail closed: local /auto with no confirmer denies.
	var actions []string
	g2 := recordingGate(&Gate{Mode: Auto, Scope: local, Approvals: NewSessionApprovals()}, &actions)
	if err := g2.Start(); err != nil {
		t.Fatal(err)
	}
	if d := g2.Authorize(context.Background(), cmd); d.Allowed {
		t.Error("local /auto with no confirmer must fail closed (deny)")
	}
	if got := lastAction(t, actions); got != "deny:confirm" {
		t.Errorf("want deny:confirm, got %q", got)
	}

	// Contrast: external /auto must NOT confirm.
	ec := &countingConfirmer{ok: true}
	g3 := &Gate{Mode: Auto, Scope: okScope(t), Allow: NewAllowlist("nmap"), Confirm: ec, Approvals: NewSessionApprovals()}
	if err := g3.Start(); err != nil {
		t.Fatal(err)
	}
	if d := g3.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}); !d.Allowed {
		t.Fatalf("external /auto in-scope command should be allowed: %q", d.Reason)
	}
	if ec.calls != 0 {
		t.Errorf("external /auto must NOT confirm, but Confirm was called %d times", ec.calls)
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
