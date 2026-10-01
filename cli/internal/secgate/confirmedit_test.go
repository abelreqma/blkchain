package secgate

import (
	"context"
	"strings"
	"testing"
)

// editConfirmer is an EditConfirmer that returns a fixed allow verdict and an
// optional edited substitute command.
type editConfirmer struct {
	allow  bool
	edited *Command
}

func (e editConfirmer) Confirm(ctx context.Context, cmd Command) bool { return e.allow }
func (e editConfirmer) ConfirmOrEdit(ctx context.Context, cmd Command) (bool, *Command) {
	return e.allow, e.edited
}

// editGate is a Safe external gate (nmap/curl allowed) on an in-scope network
// scope, so the deny-layers pass and the confirm/edit path is exercised.
func editGate(t *testing.T, c Confirmer) *Gate {
	t.Helper()
	s, err := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Safe, Scope: s, Allow: NewAllowlist("nmap", "curl"), Confirm: c, Approvals: NewSessionApprovals()}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestEditSubstitutesAndReValidates(t *testing.T) {
	edited := &Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}
	g := editGate(t, editConfirmer{allow: true, edited: edited})
	orig := Command{Binary: "curl", Args: []string{"http://10.0.0.5"}}
	d := g.Authorize(context.Background(), orig)
	if !d.Allowed {
		t.Fatalf("edited in-scope command denied: %s", d.Reason)
	}
	if d.Command.Binary != "nmap" || len(d.Command.Args) != 3 || d.Command.Args[2] != "10.0.0.5" {
		t.Errorf("Decision.Command = %+v, want the edited nmap command", d.Command)
	}
}

func TestEditPreservesTierContext(t *testing.T) {
	// The edit inherits the ORIGINAL's Phase/Surface/Armed; the operator edits only
	// Binary+Args and cannot change the tier via the edit.
	edited := &Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}} // no phase/armed set
	g := editGate(t, editConfirmer{allow: true, edited: edited})
	orig := Command{Binary: "nmap", Args: []string{"-p", "22", "10.0.0.5"}, Phase: PhaseExploit, Surface: SurfaceNetwork, Armed: true}
	d := g.Authorize(context.Background(), orig)
	if !d.Allowed {
		t.Fatalf("armed exploit edit denied: %s", d.Reason)
	}
	if d.Command.Phase != PhaseExploit || !d.Command.Armed || d.Command.Surface != SurfaceNetwork {
		t.Errorf("edit did not inherit tier context: phase=%q armed=%v surface=%q", d.Command.Phase, d.Command.Armed, d.Command.Surface)
	}
}

func TestEditCannotBypassScope(t *testing.T) {
	// Edit to an OUT-of-scope target: the re-validation scope check denies it even
	// though the confirmer said allow.
	edited := &Command{Binary: "nmap", Args: []string{"-p", "80", "9.9.9.9"}}
	g := editGate(t, editConfirmer{allow: true, edited: edited})
	orig := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}
	d := g.Authorize(context.Background(), orig)
	if d.Allowed {
		t.Errorf("edit to an out-of-scope target was allowed, want deny")
	}
}

func TestEditCannotBypassDenylist(t *testing.T) {
	// Local profile: edit a benign command into a destructive one; the re-validation
	// destructive denylist denies it.
	s, err := ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}
	edited := &Command{Binary: "rm", Args: []string{"-rf", "/"}}
	g := &Gate{Mode: Safe, Scope: s, Confirm: editConfirmer{allow: true, edited: edited}, Approvals: NewSessionApprovals()}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	d := g.Authorize(context.Background(), Command{Binary: "id"})
	if d.Allowed {
		t.Errorf("edit to a destructive command was allowed, want deny")
	}
}

func TestEditDeclinedDenies(t *testing.T) {
	g := editGate(t, editConfirmer{allow: false})
	d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}})
	if d.Allowed {
		t.Errorf("declined edit-confirmer allowed the command, want deny")
	}
}

func TestPlainConfirmerDecisionCarriesCommand(t *testing.T) {
	// A plain (non-edit) Confirmer: Decision.Command is the original command (the
	// caller executes Decision.Command uniformly).
	g := editGate(t, &okConfirmer{})
	orig := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}
	d := g.Authorize(context.Background(), orig)
	if !d.Allowed {
		t.Fatalf("plain confirm denied: %s", d.Reason)
	}
	if d.Command.Binary != "nmap" {
		t.Errorf("Decision.Command = %+v, want the original command", d.Command)
	}
}

func TestAutoNoConfirmDecisionCarriesCommand(t *testing.T) {
	// The Auto no-confirmation path still sets Decision.Command to the original.
	s, _ := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	g := &Gate{Mode: Auto, Scope: s, Allow: NewAllowlist("nmap"), Approvals: NewSessionApprovals()}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	orig := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}
	d := g.Authorize(context.Background(), orig)
	if !d.Allowed || d.Command.Binary != "nmap" {
		t.Errorf("auto no-confirm: Decision.Command = %+v allowed=%v, want nmap allowed", d.Command, d.Allowed)
	}
}
