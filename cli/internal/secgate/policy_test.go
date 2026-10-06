package secgate

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPolicyAutoNeverConfirms(t *testing.T) {
	scope, err := ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	p.Allowed = []string{"local"}
	calls := 0
	g := &Gate{Mode: Auto, Scope: scope, Policy: p, Confirm: policyConfirmer{calls: &calls}}
	decision := g.Authorize(context.Background(), Command{Binary: "id", Phase: PhaseExploit})
	if !decision.Allowed || calls != 0 {
		t.Fatalf("auto decision=%+v confirmation calls=%d", decision, calls)
	}
}

type policyConfirmer struct{ calls *int }

func (c policyConfirmer) Confirm(context.Context, Command) bool { *c.calls++; return true }

func TestPolicySafeCannotOverrideExclusions(t *testing.T) {
	scope, _ := ParseScope(strings.NewReader("10.20.0.0/24\n!10.20.0.5\n"))
	calls := 0
	g := &Gate{Mode: Safe, Scope: scope, Policy: DefaultPolicy(), Confirm: policyConfirmer{calls: &calls}}
	d := g.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"http://10.20.0.5"}})
	if d.Allowed || calls != 0 {
		t.Fatalf("out-of-scope reached confirmation: %+v calls=%d", d, calls)
	}
}

func TestPolicyCommandDenialMatchesExecutableIdentity(t *testing.T) {
	p := DefaultPolicy()
	p.Commands = []CommandDenial{{Binary: "rm"}, {Binary: "curl", Arg: "--upload-file"}}
	for _, c := range []Command{{Binary: "/usr/bin/RM"}, {Binary: "curl", Args: []string{"--upload-file=x"}}} {
		if !p.Denies(c) {
			t.Fatalf("denial missed %+v", c)
		}
	}
	if p.Denies(Command{Binary: "curl", Args: []string{"--header", "X-Note: --upload-file"}}) {
		t.Fatal("denial matched text inside an unrelated argument")
	}
}

func TestPolicyPrivateScopeExclusionsAndRate(t *testing.T) {
	scope, err := BuildScope(ScopeSpec{In: []string{"10.20.0.0/24"}, Out: []string{"10.20.0.5"}, Rate: "1/s"})
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	g := &Gate{Mode: Auto, Scope: scope, Policy: p}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	if d := g.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"http://10.20.0.6"}}); !d.Allowed {
		t.Fatalf("permitted private target denied: %+v", d)
	}
	if d := g.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"http://10.20.0.5"}}); d.Allowed || !strings.Contains(d.Reason, "out of scope") {
		t.Fatalf("excluded target reached: %+v", d)
	}
	if d := g.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"http://10.20.0.7"}}); d.Allowed || !strings.Contains(d.Reason, "rate") {
		t.Fatalf("rate cap did not apply: %+v", d)
	}
}

func TestPolicyDNSChangeAndProtectedDestination(t *testing.T) {
	scope, err := ParseScope(strings.NewReader("example.test\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.PinNetwork([]string{"10.20.0.6"}, []string{"10.20.0.1"}); err != nil {
		t.Fatal(err)
	}
	old := lookupIPFn
	lookupIPFn = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.20.0.6")}, nil }
	t.Cleanup(func() { lookupIPFn = old })
	g := &Gate{Mode: Auto, Scope: scope, Policy: DefaultPolicy()}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	c := Command{Binary: "curl", Args: []string{"https://example.test"}}
	if d := g.Authorize(context.Background(), c); !d.Allowed {
		t.Fatalf("pinned DNS target denied: %+v", d)
	}
	lookupIPFn = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.20.0.1")}, nil }
	if d := g.Authorize(context.Background(), c); d.Allowed || !strings.Contains(d.Reason, "out-of-scope") {
		t.Fatalf("changed DNS reached protected host: %+v", d)
	}
	if d := g.AuthorizeWebRedirect("https://10.20.0.1/next"); d.Allowed {
		t.Fatalf("redirect reached protected host: %+v", d)
	}
}

func TestPolicyWildcardCommandRequiresMatchingPinnedHostname(t *testing.T) {
	scope, err := BuildScope(ScopeSpec{In: []string{"*.example.test"}, Out: []string{"blocked.example.test", "10.20.0.7"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.PinNetwork(nil, []string{"10.20.0.1"}); err != nil {
		t.Fatal(err)
	}
	policy := DefaultPolicy()
	if err := policy.Seal("", nil, scope); err != nil {
		t.Fatal(err)
	}
	gate := &Gate{Mode: Auto, Scope: scope, Policy: policy}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	withStubLookup(t, map[string][]net.IP{
		"api.example.test":       {net.ParseIP("10.20.0.6")},
		"deep.api.example.test":  {net.ParseIP("8.8.8.8")},
		"bad.example.test":       {net.ParseIP("10.20.0.7")},
		"protected.example.test": {net.ParseIP("10.20.0.1")},
		"mixed.example.test":     {net.ParseIP("8.8.8.8"), net.ParseIP("169.254.169.254")},
	}, nil)
	for _, host := range []string{"api.example.test", "deep.api.example.test"} {
		if d := gate.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"http://" + host + "/"}}); !d.Allowed {
			t.Errorf("wildcard command to %s denied: %s", host, d.Reason)
		}
	}
	for _, host := range []string{"blocked.example.test", "bad.example.test", "protected.example.test", "mixed.example.test", "example.test", "evil-example.test", "10.20.0.6"} {
		if d := gate.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"http://" + host + "/"}}); d.Allowed {
			t.Errorf("command to %s bypassed wildcard scope", host)
		}
	}
}

func TestPolicyActiveWebActionAllowedByRoEWithoutPrompt(t *testing.T) {
	scope, err := ParseScope(strings.NewReader("10.20.0.6\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	p.Allowed = append(p.Allowed, "api-write", "browser-write")
	calls := 0
	g := &Gate{Mode: Auto, Scope: scope, Policy: p, Confirm: policyConfirmer{calls: &calls}}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	if d := g.AuthorizeAPIRequest(context.Background(), APIRequest{Method: "POST", URL: "https://10.20.0.6/write"}); !d.Allowed {
		t.Fatalf("RoE-permitted API write denied: %+v", d)
	}
	if d := g.AuthorizeBrowser(context.Background(), BrowserAction{URL: "https://10.20.0.6/form", Active: true}); !d.Allowed {
		t.Fatalf("RoE-permitted browser write denied: %+v", d)
	}
	if calls != 0 {
		t.Fatalf("auto requested %d confirmations", calls)
	}
}

func TestPolicyCommandRedirectsFailClosedWithoutBlockingPlainFetch(t *testing.T) {
	scope, err := ParseScope(strings.NewReader("10.20.0.6\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Auto, Scope: scope, Policy: DefaultPolicy()}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	for _, command := range []Command{
		{Binary: "curl", Args: []string{"-sSL", "http://10.20.0.6"}},
		{Binary: "curl", Args: []string{"--location-trusted", "http://10.20.0.6"}},
		{Binary: "curl", Args: []string{"-K", "settings", "http://10.20.0.6"}},
		{Binary: "curl", Args: []string{"--config=settings", "http://10.20.0.6"}},
		{Binary: "wget", Args: []string{"http://10.20.0.6"}},
	} {
		if decision := g.Authorize(context.Background(), command); decision.Allowed || !strings.Contains(decision.Reason, "redirect") {
			t.Fatalf("redirecting command allowed: %+v %+v", command, decision)
		}
	}
	for _, command := range []Command{
		{Binary: "curl", Args: []string{"-fsS", "http://10.20.0.6"}},
		{Binary: "curl", Args: []string{"-oL", "http://10.20.0.6"}},
		{Binary: "curl", Args: []string{"-HLocation: test", "http://10.20.0.6"}},
	} {
		if decision := g.Authorize(context.Background(), command); !decision.Allowed {
			t.Fatalf("plain in-scope fetch denied: %+v %+v", command, decision)
		}
	}
}

func TestPolicyActionCapSurvivesRestore(t *testing.T) {
	scope, err := ParseScope(strings.NewReader("10.20.0.6\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	p.MaxActions = 1
	g := &Gate{Mode: Auto, Scope: scope, Policy: p}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	c := Command{Binary: "curl", Args: []string{"http://10.20.0.6"}}
	if d := g.Authorize(context.Background(), c); !d.Allowed {
		t.Fatalf("first action denied: %+v", d)
	}
	if d := g.Authorize(context.Background(), c); d.Allowed || !strings.Contains(d.Reason, "cap") {
		t.Fatalf("action cap did not stop reuse: %+v", d)
	}
	resume := &Gate{Mode: Auto, Scope: scope, Policy: p}
	if err := resume.Start(); err != nil {
		t.Fatal(err)
	}
	if err := resume.RestorePolicyUsage(1, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if d := resume.Authorize(context.Background(), c); d.Allowed {
		t.Fatalf("restored action cap was reset: %+v", d)
	}
	if err := resume.RestorePolicyUsage(2, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("over-budget checkpoint was accepted")
	}
}

func TestPolicyByteCapSurvivesRestore(t *testing.T) {
	scope, err := ParseScope(strings.NewReader("10.20.0.6\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	p.OutputBytes, p.TotalBytes = 8, 8
	g := &Gate{Mode: Auto, Scope: scope, Policy: p}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	if err := g.ClaimPolicyBytes(8); err != nil || g.PolicyByteUsage() != 8 {
		t.Fatalf("first byte claim=%d err=%v", g.PolicyByteUsage(), err)
	}
	if err := g.ClaimPolicyBytes(1); err == nil {
		t.Fatal("byte cap accepted an extra byte")
	}
	resume := &Gate{Mode: Auto, Scope: scope, Policy: p}
	if err := resume.Start(); err != nil {
		t.Fatal(err)
	}
	if err := resume.RestorePolicyUsage(0, time.Now().Add(time.Minute), 8); err != nil {
		t.Fatal(err)
	}
	if resume.PolicyBytesRemaining() != 0 || resume.ClaimPolicyBytes(1) == nil {
		t.Fatal("restored byte cap was reset")
	}
	if err := resume.RestorePolicyUsage(0, time.Now().Add(time.Minute), 9); err == nil {
		t.Fatal("over-budget byte checkpoint was accepted")
	}
}

func TestPolicyHostnameOnlyScopeUsesBrokerForWebAndRequiresIPForCommands(t *testing.T) {
	old := lookupIPFn
	lookupIPFn = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.20.0.6")}, nil }
	t.Cleanup(func() { lookupIPFn = old })
	makeGate := func(entries string) *Gate {
		t.Helper()
		scope, err := ParseScope(strings.NewReader(entries))
		if err != nil {
			t.Fatal(err)
		}
		policy := DefaultPolicy()
		if err := policy.Seal("", nil, scope); err != nil {
			t.Fatal(err)
		}
		if err := scope.PinNetwork([]string{"10.20.0.6"}, nil); err != nil {
			t.Fatal(err)
		}
		gate := &Gate{Mode: Auto, Scope: scope, Policy: policy}
		if err := gate.Start(); err != nil {
			t.Fatal(err)
		}
		return gate
	}
	hostOnly := makeGate("example.test\n")
	command := Command{Binary: "curl", Args: []string{"https://example.test/"}}
	if d := hostOnly.Authorize(context.Background(), command); d.Allowed || !strings.Contains(d.Reason, "explicit in-scope IP") {
		t.Fatalf("hostname-only command escaped IP scope: %+v", d)
	}
	if d := hostOnly.AuthorizeAPIRequest(context.Background(), APIRequest{Method: "GET", URL: "https://example.test/"}); !d.Allowed {
		t.Fatalf("hostname-scoped broker request denied: %+v", d)
	}
	withIP := makeGate("example.test\n10.20.0.0/24\n")
	if d := withIP.Authorize(context.Background(), command); !d.Allowed {
		t.Fatalf("hostname and explicit IP command denied: %+v", d)
	}
}
