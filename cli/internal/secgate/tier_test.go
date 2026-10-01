package secgate

import "testing"

func TestPhaseTierPredicates(t *testing.T) {
	cases := []struct {
		phase        Phase
		requiresArm  bool
		perActionCfm bool
	}{
		{PhaseRecon, false, false},
		{PhaseReport, false, false},
		{PhaseExploit, true, true},
		{PhasePostEx, true, true},
		{Phase(""), false, false},      // empty == recon (legacy-safe default)
		{Phase("bogus"), false, false}, // unknown is not a confirm/arm tier
	}
	for _, c := range cases {
		if got := c.phase.requiresArm(); got != c.requiresArm {
			t.Errorf("Phase(%q).requiresArm() = %v, want %v", c.phase, got, c.requiresArm)
		}
		if got := c.phase.perActionConfirm(); got != c.perActionCfm {
			t.Errorf("Phase(%q).perActionConfirm() = %v, want %v", c.phase, got, c.perActionCfm)
		}
	}
}

func TestCommandZeroValueIsReconUnarmed(t *testing.T) {
	var c Command
	if c.Phase.requiresArm() || c.Phase.perActionConfirm() {
		t.Errorf("zero Command must gate as recon/unarmed, got phase %q armed=%v", c.Phase, c.Armed)
	}
	if c.Armed {
		t.Errorf("zero Command must be unarmed")
	}
}
