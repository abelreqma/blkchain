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
	decision := g.Authorize(context.Background(), Command{Binary: "id", Phase: PhaseExploit, Armed: true})
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
	g := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist("curl", "wget", "id"), Policy: p}
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
	scope, err := ParseScope(strings.NewReader("example.test\n10.20.0.6\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.PinNetwork([]string{"10.20.0.6"}, []string{"10.20.0.1"}); err != nil {
		t.Fatal(err)
	}
	old := lookupIPFn
	lookupIPFn = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.20.0.6")}, nil }
	t.Cleanup(func() { lookupIPFn = old })
	g := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist("curl", "wget", "id"), Policy: DefaultPolicy()}
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
	scope, err := BuildScope(ScopeSpec{In: []string{"*.example.test", "10.20.0.6"}, Out: []string{"blocked.example.test", "10.20.0.7"}})
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
	gate := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist("curl", "wget", "id"), Policy: policy}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	withStubLookup(t, map[string][]net.IP{
		"api.example.test":       {net.ParseIP("10.20.0.6")},
		"deep.api.example.test":  {net.ParseIP("8.8.8.8")},
		"bad.example.test":       {net.ParseIP("10.20.0.7")},
		"protected.example.test": {net.ParseIP("10.20.0.1")},
		"mixed.example.test":     {net.ParseIP("8.8.8.8"), net.ParseIP("169.254.169.254")},
		"lan.example.test":       {net.ParseIP("192.168.1.10")},
	}, nil)
	for _, host := range []string{"api.example.test", "deep.api.example.test"} {
		if d := gate.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"http://" + host + "/"}}); !d.Allowed {
			t.Errorf("wildcard command to %s denied: %s", host, d.Reason)
		}
	}
	for _, host := range []string{"blocked.example.test", "bad.example.test", "protected.example.test", "mixed.example.test", "lan.example.test", "example.test", "evil-example.test", "10.20.0.9"} {
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
	if d := g.AuthorizeAPIRequest(context.Background(), APIRequest{Method: "POST", URL: "https://10.20.0.6/write", Armed: true}); !d.Allowed {
		t.Fatalf("RoE-permitted API write denied: %+v", d)
	}
	if d := g.AuthorizeBrowser(context.Background(), BrowserAction{URL: "https://10.20.0.6/form", Active: true, Armed: true}); !d.Allowed {
		t.Fatalf("RoE-permitted browser write denied: %+v", d)
	}
	if calls != 0 {
		t.Fatalf("auto requested %d confirmations", calls)
	}
}

// TestPolicyActiveWebActionRequiresArmedTask pins the tier arm requirement on
// the policy branch. An engagement gate always carries a sealed policy, so a
// state-changing web action reaching a target from an unarmed task is the
// difference between the arm requirement being a rule and being a rule only for
// a gate no engagement uses. The RoE here permits the action class and the mode
// is Auto, so nothing but the arm requirement can deny it.
func TestPolicyActiveWebActionRequiresArmedTask(t *testing.T) {
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
	for _, tc := range []struct {
		name string
		call func() Decision
	}{
		{"api write", func() Decision {
			return g.AuthorizeAPIRequest(context.Background(), APIRequest{Method: "POST", URL: "https://10.20.0.6/write"})
		}},
		{"browser write", func() Decision {
			return g.AuthorizeBrowser(context.Background(), BrowserAction{URL: "https://10.20.0.6/form", Active: true})
		}},
	} {
		d := tc.call()
		if d.Allowed {
			t.Errorf("%s from an unarmed task was allowed under a sealed policy", tc.name)
			continue
		}
		if !strings.Contains(d.Reason, "requires an armed task") {
			t.Errorf("%s denied for %q, want the arm requirement", tc.name, d.Reason)
		}
	}
	// A read-only action carries no arm requirement, so the rule above moves no
	// recon verdict.
	if d := g.AuthorizeAPIRequest(context.Background(), APIRequest{Method: "GET", URL: "https://10.20.0.6/read"}); !d.Allowed {
		t.Errorf("unarmed GET denied under a sealed policy: %+v", d)
	}
}

func TestPolicyCommandRedirectsFailClosedWithoutBlockingPlainFetch(t *testing.T) {
	scope, err := ParseScope(strings.NewReader("10.20.0.6\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist("curl", "wget", "id"), Policy: DefaultPolicy()}
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
	g := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist("curl", "wget", "id"), Policy: p}
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
	resume := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist("curl", "wget", "id"), Policy: p}
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

func TestPolicyBudgetKeepsReadOnlySudoAvailable(t *testing.T) {
	scope, err := ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	p.Allowed = []string{"local"}
	p.MaxCommands, p.MaxActions = 1, 1
	g := &Gate{Mode: Auto, Scope: scope, Policy: p}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	if d := g.Authorize(context.Background(), Command{Binary: "id"}); !d.Allowed {
		t.Fatalf("first command denied: %+v", d)
	}
	for _, args := range [][]string{{"-l"}, {"-n", "-l"}, {"-ln"}, {"-nl"}} {
		if d := g.Authorize(context.Background(), Command{Binary: "sudo", Args: args}); !d.Allowed {
			t.Fatalf("sudo listing %v denied at command cap: %+v", args, d)
		}
	}
	if got := g.PolicyUsage(); got != 1 || g.PolicyActionUsage() != 1 {
		t.Fatalf("usage commands=%d actions=%d", got, g.PolicyActionUsage())
	}
	if d := g.Authorize(context.Background(), Command{Binary: "id"}); d.Allowed || !strings.Contains(d.Reason, "cap") {
		t.Fatalf("substantive command bypassed cap: %+v", d)
	}
	if g.PolicyCapReason() == "" {
		t.Fatal("cap denial was not retained for the planner")
	}
}

func TestPolicyBudgetSeparatesCommandsAndActions(t *testing.T) {
	p := DefaultPolicy()
	p.MaxCommands, p.MaxActions = 1, 3
	g := &Gate{Policy: p}
	if err := g.ClaimPolicyAction("api-read"); err != nil {
		t.Fatal(err)
	}
	if got := g.PolicyUsage(); got != 0 || g.PolicyActionUsage() != 1 {
		t.Fatalf("usage commands=%d actions=%d", got, g.PolicyActionUsage())
	}
	if err := g.ClaimPolicyAction("command"); err != nil {
		t.Fatal(err)
	}
	if err := g.ClaimPolicyAction("api-read"); err != nil {
		t.Fatal(err)
	}
	if err := g.ClaimPolicyAction("api-read"); err == nil {
		t.Fatal("action cap did not apply")
	}
	if err := g.RestorePolicyUsageCounts(1, 3, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestDeniedInternalHelpProbeDoesNotSpendCommandBudget(t *testing.T) {
	scope, err := ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	p.Allowed = []string{"local"}
	p.MaxCommands, p.MaxActions = 1, 1
	g := &Gate{Mode: Auto, Scope: scope, Policy: p}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"--help"}, InternalProbe: true})
	}
	if g.PolicyUsage() != 0 || g.PolicyActionUsage() != 0 {
		t.Fatalf("help probes spent budget: commands=%d actions=%d", g.PolicyUsage(), g.PolicyActionUsage())
	}
	if g.PolicyStopReason() != "" {
		t.Fatalf("internal help checks stalled the planner: %s", g.PolicyStopReason())
	}
	if d := g.Authorize(context.Background(), Command{Binary: "id"}); !d.Allowed {
		t.Fatalf("substantive check was blocked: %+v", d)
	}
}

func TestPolicyStopsRepeatedIdenticalCommandDenial(t *testing.T) {
	scope, err := ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	p.Allowed = []string{"local"}
	g := &Gate{Mode: Auto, Scope: scope, Policy: p}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	cmd := Command{Binary: "nmap", Args: []string{"-p-", "10.0.0.5"}}
	if d := g.Authorize(context.Background(), cmd); d.Allowed || g.PolicyStopReason() != "" {
		t.Fatalf("first denial should permit adaptation: %+v stop=%q", d, g.PolicyStopReason())
	}
	if d := g.Authorize(context.Background(), cmd); d.Allowed || g.PolicyStopReason() != "repeated identical command denial" {
		t.Fatalf("repeat denial did not stop planning: %+v stop=%q", d, g.PolicyStopReason())
	}
	if d := g.Authorize(context.Background(), Command{Binary: "id"}); !d.Allowed || g.PolicyStopReason() != "" {
		t.Fatalf("allowed adaptation did not clear the stall: %+v stop=%q", d, g.PolicyStopReason())
	}
}

func TestPolicyByteCapSurvivesRestore(t *testing.T) {
	scope, err := ParseScope(strings.NewReader("10.20.0.6\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	p.OutputBytes, p.TotalBytes = 8, 8
	g := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist("curl", "wget", "id"), Policy: p}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	if err := g.ClaimPolicyBytes(8); err != nil || g.PolicyByteUsage() != 8 {
		t.Fatalf("first byte claim=%d err=%v", g.PolicyByteUsage(), err)
	}
	if err := g.ClaimPolicyBytes(1); err == nil {
		t.Fatal("byte cap accepted an extra byte")
	}
	resume := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist("curl", "wget", "id"), Policy: p}
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
	resolved := "8.8.8.8"
	lookupIPFn = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP(resolved)}, nil }
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
		if err := scope.PinNetwork([]string{resolved}, nil); err != nil {
			t.Fatal(err)
		}
		gate := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist("curl", "wget", "id"), Policy: policy}
		if err := gate.Start(); err != nil {
			t.Fatal(err)
		}
		return gate
	}
	hostOnly := makeGate("example.test\n")
	command := Command{Binary: "curl", Args: []string{"https://example.test/"}}
	request := APIRequest{Method: "GET", URL: "https://example.test/"}
	if d := hostOnly.Authorize(context.Background(), command); d.Allowed || !strings.Contains(d.Reason, "explicit in-scope IP") {
		t.Fatalf("hostname-only command escaped IP scope: %+v", d)
	}
	if d := hostOnly.AuthorizeAPIRequest(context.Background(), request); !d.Allowed {
		t.Fatalf("hostname-scoped broker request denied: %+v", d)
	}
	withIP := makeGate("example.test\n8.8.8.0/24\n")
	if d := withIP.Authorize(context.Background(), command); !d.Allowed {
		t.Fatalf("hostname and explicit IP command denied: %+v", d)
	}
	resolved = "10.20.0.6"
	if d := makeGate("example.test\n").AuthorizeAPIRequest(context.Background(), request); d.Allowed {
		t.Fatalf("hostname-only broker request reached the private address it resolves to: %+v", d)
	}
	if d := makeGate("example.test\n10.20.0.0/24\n").AuthorizeAPIRequest(context.Background(), request); !d.Allowed {
		t.Fatalf("hostname with explicit private CIDR broker request denied: %+v", d)
	}
}

// The structural file-access guard runs on the RoE policy path too. A sealed
// policy authorizes targets and action classes; it does not decide whether an
// argument reaches a file outside the scratch directory, so an in-scope,
// policy-authorized command whose file argument escapes the scratch directory
// is still denied, on both exec-time entry points.
func TestPolicyPathEnforcesFileAccessGuard(t *testing.T) {
	scope, err := ParseScope(strings.NewReader("10.20.0.6\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist("curl"), Policy: DefaultPolicy()}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	key := "/home/operator/.ssh/foothold_key"
	d := g.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"-T", key, "http://10.20.0.6/"}})
	if d.Allowed {
		t.Fatalf("policy path allowed a scratch-escaping upload: %+v", d)
	}
	if !strings.Contains(d.Reason, key) {
		t.Errorf("denial must name the offending argument, got %q", d.Reason)
	}
	if d := g.Check(context.Background(), Command{Binary: "curl", Args: []string{"--output", "/etc/cron.d/x", "http://10.20.0.6/"}}); d.Allowed {
		t.Fatalf("Check allowed a scratch-escaping write on the policy path: %+v", d)
	}
	// A relative path stays inside the scratch directory and is permitted.
	if d := g.Check(context.Background(), Command{Binary: "curl", Args: []string{"-o", "evidence/out.txt", "http://10.20.0.6/"}}); !d.Allowed {
		t.Fatalf("in-scratch write denied: %+v", d)
	}
}
