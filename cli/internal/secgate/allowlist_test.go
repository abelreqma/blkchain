package secgate

import (
	"context"
	"testing"
)

func TestAllowlistPermitsBareNameOnly(t *testing.T) {
	a := NewAllowlist("nmap", "curl")
	if !a.Permits("nmap") || !a.Permits("NMAP") {
		t.Error("allowlist should permit a bare allowlisted name, case-insensitively")
	}
	if a.Permits("bash") {
		t.Error("bash is not allowlisted")
	}
	// A path-containing binary must be denied even if its base name is listed,
	// or an attacker-planted /tmp/attacker/nmap would run under the nmap entry.
	if a.Permits("/usr/bin/nmap") || a.Permits("./nmap") || a.Permits("/tmp/attacker/nmap") {
		t.Error("a path-containing binary must be denied (fail closed)")
	}
}

func TestEmptyAllowlistPermitsNothing(t *testing.T) {
	if NewAllowlist().Permits("nmap") {
		t.Error("empty allowlist must permit nothing (fail closed)")
	}
}

func TestSessionApprovalsExactMatch(t *testing.T) {
	s := NewSessionApprovals()
	c := Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}
	if s.Approved(c) {
		t.Error("nothing approved yet")
	}
	s.Remember(c)
	if !s.Approved(c) {
		t.Error("exact repeat should be approved")
	}
	// A different argument is a different command and is NOT pre-approved.
	if s.Approved(Command{Binary: "nmap", Args: []string{"-p", "443", "10.0.0.5"}}) {
		t.Error("a different command must not be considered approved")
	}
}

type stubConfirmer struct{ ok bool }

func (s stubConfirmer) Confirm(ctx context.Context, c Command) bool { return s.ok }

func TestConfirmerContract(t *testing.T) {
	if !(stubConfirmer{true}).Confirm(context.Background(), Command{Binary: "x"}) {
		t.Error("stub confirmer true should confirm")
	}
	if (stubConfirmer{false}).Confirm(context.Background(), Command{Binary: "x"}) {
		t.Error("stub confirmer false should deny")
	}
}
