package main

import (
	"context"
	"net"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

// webloopbackscope_test.go pins the scope rule for an internal address on the web
// action path, in both directions. CLAUDE.md states it as: a private or internal
// address is allowed when the RoE explicitly includes it, and an empty or ambiguous
// scope fails closed. Nothing had asserted the permissive half end to end, so a
// future tightening of WebAddressAllowed or of the policy gate could refuse a
// loopback target an operator deliberately put in scope and no test would say so.

// loopbackRoE builds an RoE whose In Scope section is the given lines.
func loopbackRoE(t *testing.T, inScope string) *RoE {
	t.Helper()
	roe, err := ParseRoE(strings.NewReader(
		"# Rules of Engagement\n\n## Summary\nscope fixture\n\n## Targets\n127.0.0.1\n\n## In Scope\n" +
			inScope + "\n\n## Out of Scope\n\n## Rate\n10/s\n\n## Allowed Actions\n- api-read\n\n## Autonomous Actions\n"))
	if err != nil {
		t.Fatalf("In Scope %q: %v", inScope, err)
	}
	return roe
}

// loopbackGate builds the gate the way the engage entry point does, so the verdict
// comes from the production construction rather than a hand-assembled Gate. The
// unattended allowlist is empty, which is what an engagement with no
// .blkchain/config.yaml gets.
func loopbackGate(t *testing.T, roe *RoE) *secgate.Gate {
	t.Helper()
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	g := buildEngageGate(ws, roe.Scope, secgate.Auto, nil, secgate.NewSessionApprovals(), t.TempDir(),
		gatePolicy{RoE: roe, UnattendedAllow: secgate.NewAllowlist()}, func(string, string) {})
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	return g
}

// An explicitly listed loopback address is reachable: the gate authorizes the
// request, the per-address hook the broker uses allows it, and the gated web_api
// tool carries it through to the driver.
func TestWebAPIReachesExplicitlyInScopeLoopback(t *testing.T) {
	for _, inScope := range []string{
		"127.0.0.1",
		"127.0.0.1\n127.0.0.1/32",
		"127.0.0.0/8",
	} {
		t.Run(strings.ReplaceAll(inScope, "\n", "+"), func(t *testing.T) {
			roe := loopbackRoE(t, inScope)
			g := loopbackGate(t, roe)

			if !roe.Scope.InScope("127.0.0.1") {
				t.Error("an explicitly listed loopback address must be in scope")
			}
			if !roe.Scope.WebAddressAllowed("127.0.0.1", net.ParseIP("127.0.0.1")) {
				t.Error("the per-address web hook must allow an explicitly listed loopback address")
			}
			if d := g.AuthorizeAPIRequest(context.Background(),
				secgate.APIRequest{Method: "GET", URL: "http://127.0.0.1:8787/"}); !d.Allowed {
				t.Fatalf("api-read to an in-scope loopback target was denied: %s", d.Reason)
			}
			drv := &webFakeDriver{body: "<title>fixture</title>"}
			out, err := newWebAPITool(g, nil, drv).Call(context.Background(),
				`{"method":"GET","url":"http://127.0.0.1:8787/"}`)
			if err != nil {
				t.Fatal(err)
			}
			if !drv.apiCalled {
				t.Fatalf("the request never reached the driver: %s", out)
			}
		})
	}
}

// The permissive half above must not generalize. A loopback address the RoE does
// not list is refused, so the allowance comes from the operator's declaration and
// not from the address being local.
func TestWebAPIRefusesLoopbackOutsideTheDeclaredScope(t *testing.T) {
	roe := loopbackRoE(t, "10.0.0.0/24")
	g := loopbackGate(t, roe)
	if roe.Scope.WebAddressAllowed("127.0.0.1", net.ParseIP("127.0.0.1")) {
		t.Error("an undeclared loopback address must not be allowed")
	}
	drv := &webFakeDriver{body: "x"}
	if d := g.AuthorizeAPIRequest(context.Background(),
		secgate.APIRequest{Method: "GET", URL: "http://127.0.0.1:8787/"}); d.Allowed {
		t.Error("api-read to an undeclared loopback target must be denied")
	}
	if _, err := newWebAPITool(g, nil, drv).Call(context.Background(),
		`{"method":"GET","url":"http://127.0.0.1:8787/"}`); err != nil {
		t.Fatal(err)
	}
	if drv.apiCalled {
		t.Error("an undeclared loopback request must not reach the driver")
	}
}

// A hostname cannot smuggle an internal address in. WebAddressAllowed requires an
// explicit, unpinned IP or CIDR entry for a non-global-unicast address, so a name
// in the scope, even one that resolves to loopback, does not authorize the address
// it resolves to.
func TestWebAPIRefusesLoopbackReachedOnlyByName(t *testing.T) {
	roe := loopbackRoE(t, "localhost")
	if roe.Scope.WebAddressAllowed("localhost", net.ParseIP("127.0.0.1")) {
		t.Error("a hostname entry must not authorize the internal address it resolves to")
	}
	if roe.Scope.WebAddressAllowed("127.0.0.1", net.ParseIP("127.0.0.1")) {
		t.Error("a hostname entry must not put the bare loopback address in scope")
	}
}

// Cloud metadata stays refused whatever else is declared, since it is not listed.
func TestWebAPIRefusesCloudMetadataWithLoopbackInScope(t *testing.T) {
	roe := loopbackRoE(t, "127.0.0.1")
	g := loopbackGate(t, roe)
	if roe.Scope.WebAddressAllowed("169.254.169.254", net.ParseIP("169.254.169.254")) {
		t.Error("link-local metadata must not be allowed by a loopback declaration")
	}
	if d := g.AuthorizeAPIRequest(context.Background(),
		secgate.APIRequest{Method: "GET", URL: "http://169.254.169.254/latest/meta-data/"}); d.Allowed {
		t.Error("api-read to cloud metadata must be denied")
	}
}

// An empty scope fails closed earlier than the request: an unattended gate with no
// in-scope target and no local directive is refused at construction, so there is no
// gate to authorize anything with. That is the strongest form of the documented
// "an empty or ambiguous scope fails closed", and it is what the code does.
func TestEmptyScopeIsRefusedBeforeAnyWebActionIsAuthorized(t *testing.T) {
	scope, err := secgate.BuildScope(secgate.ScopeSpec{})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	g := buildEngageGate(ws, scope, secgate.Auto, nil, secgate.NewSessionApprovals(), t.TempDir(),
		gatePolicy{UnattendedAllow: secgate.NewAllowlist()}, func(string, string) {})
	err = g.Start()
	if err == nil {
		t.Fatal("an unattended gate with an empty scope must not start")
	}
	if !strings.Contains(err.Error(), "scope") {
		t.Errorf("the refusal should name the scope, got %q", err)
	}
	// And the loopback address is not in that scope either way.
	if scope.WebAddressAllowed("127.0.0.1", net.ParseIP("127.0.0.1")) {
		t.Error("an empty scope must allow no address")
	}
}
