package secgate

import "testing"

func TestClaimPolicyActionHonorsActionCap(t *testing.T) {
	p := DefaultPolicy()
	p.MaxActions = 1
	g := &Gate{Policy: p}
	if err := g.ClaimPolicyAction("command"); err != nil {
		t.Fatal(err)
	}
	if err := g.ClaimPolicyAction("command"); err == nil {
		t.Fatal("second code-owned action exceeded the policy cap")
	}
	if got := g.PolicyUsage(); got != 1 {
		t.Fatalf("policy usage = %d, want 1", got)
	}
	if err := (&Gate{}).ClaimPolicyAction("command"); err == nil {
		t.Fatal("code-owned action ran without a policy")
	}
	noCommands := DefaultPolicy()
	noCommands.Allowed = []string{"api-read"}
	if err := (&Gate{Policy: noCommands}).ClaimPolicyAction("command"); err == nil {
		t.Fatal("code-owned command bypassed the RoE action policy")
	}
}
