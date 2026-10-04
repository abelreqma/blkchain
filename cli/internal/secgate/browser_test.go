package secgate

import (
	"context"
	"strings"
	"testing"
)

// recordingConfirmer records whether it was asked to confirm and returns a fixed
// verdict, so a test can assert when the gate requests confirmation.
type recordingConfirmer struct {
	ok     bool
	called *bool
}

func (c recordingConfirmer) Confirm(ctx context.Context, cmd Command) bool {
	if c.called != nil {
		*c.called = true
	}
	return c.ok
}

func browserGate(t *testing.T, mode Mode, confirm Confirmer) *Gate {
	t.Helper()
	s, err := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	// No Allow: a web action is not a subprocess, so AuthorizeBrowser/
	// AuthorizeAPIRequest must not consult the binary allowlist.
	return &Gate{Mode: mode, Scope: s, Confirm: confirm, Approvals: NewSessionApprovals()}
}

// TestAuthorizeBrowserPassiveInScopeAllowed: a passive navigation to an in-scope
// host is recon-tiered and allowed without arming or (in Auto) confirmation.
func TestAuthorizeBrowserPassiveInScopeAllowed(t *testing.T) {
	g := browserGate(t, Auto, nil)
	d := g.AuthorizeBrowser(context.Background(), BrowserAction{URL: "http://10.0.0.5/app", Active: false, Armed: false})
	if !d.Allowed {
		t.Fatalf("passive in-scope navigation denied: %q", d.Reason)
	}
}

// TestAuthorizeBrowserOutOfScopeDenied: a navigation to an out-of-scope host is
// denied; the subprocess/driver is never reached.
func TestAuthorizeBrowserOutOfScopeDenied(t *testing.T) {
	g := browserGate(t, Auto, nil)
	d := g.AuthorizeBrowser(context.Background(), BrowserAction{URL: "http://8.8.8.8/", Active: false, Armed: false})
	if d.Allowed {
		t.Fatal("out-of-scope browser navigation was allowed, want denied")
	}
	if !strings.Contains(strings.ToLower(d.Reason), "scope") {
		t.Errorf("want a scope denial reason, got %q", d.Reason)
	}
}

// TestAuthorizeBrowserActiveRequiresArm: an active (injecting/state-changing)
// browser action is exploit-tiered and denied unless the task is armed.
func TestAuthorizeBrowserActiveRequiresArm(t *testing.T) {
	called := false
	g := browserGate(t, Auto, recordingConfirmer{ok: true, called: &called})
	d := g.AuthorizeBrowser(context.Background(), BrowserAction{URL: "http://10.0.0.5/x", Active: true, Armed: false})
	if d.Allowed {
		t.Fatal("active browser action without an armed task was allowed, want denied")
	}
	if !strings.Contains(strings.ToLower(d.Reason), "arm") {
		t.Errorf("want an arm-required denial, got %q", d.Reason)
	}
	if called {
		t.Error("confirmer must not be consulted when the tier denies before confirmation")
	}
}

// TestAuthorizeBrowserActiveArmedAutoDoesNotPrompt: an armed Auto web action
// follows its engagement authorization without a per-action prompt.
func TestAuthorizeBrowserActiveArmedAutoDoesNotPrompt(t *testing.T) {
	called := false
	g := browserGate(t, Auto, recordingConfirmer{ok: true, called: &called})
	d := g.AuthorizeBrowser(context.Background(), BrowserAction{URL: "http://10.0.0.5/x", Active: true, Armed: true})
	if !d.Allowed {
		t.Fatalf("armed active action with an approving confirmer denied: %q", d.Reason)
	}
	if called {
		t.Error("an armed Auto web action must not require a per-action confirmation")
	}
}

// TestAuthorizeBrowserActiveSafeNoConfirmerFailsClosed: Safe mode still requires
// confirmation for an active action.
func TestAuthorizeBrowserActiveNoConfirmerFailsClosed(t *testing.T) {
	g := browserGate(t, Safe, nil)
	d := g.AuthorizeBrowser(context.Background(), BrowserAction{URL: "http://10.0.0.5/x", Active: true, Armed: true})
	if d.Allowed {
		t.Fatal("active action with no confirmer was allowed, want fail-closed deny")
	}
}

// TestAuthorizeAPIRequestReadIsRecon: a read-only API request (GET) is recon and
// allowed to an in-scope host without arming.
func TestAuthorizeAPIRequestReadIsRecon(t *testing.T) {
	g := browserGate(t, Auto, nil)
	d := g.AuthorizeAPIRequest(context.Background(), APIRequest{Method: "GET", URL: "http://10.0.0.5/api/v1/users", Armed: false})
	if !d.Allowed {
		t.Fatalf("in-scope GET denied: %q", d.Reason)
	}
}

// TestAuthorizeAPIRequestWriteRequiresArm: a state-changing API request (POST) is
// exploit-tiered and denied unless armed.
func TestAuthorizeAPIRequestWriteRequiresArm(t *testing.T) {
	g := browserGate(t, Auto, recordingConfirmer{ok: true})
	d := g.AuthorizeAPIRequest(context.Background(), APIRequest{Method: "POST", URL: "http://10.0.0.5/api/v1/users", Armed: false})
	if d.Allowed {
		t.Fatal("unarmed POST was allowed, want denied")
	}
	if !strings.Contains(strings.ToLower(d.Reason), "arm") {
		t.Errorf("want an arm-required denial, got %q", d.Reason)
	}
}

// TestAuthorizeAPIRequestWriteArmedAutoDoesNotPrompt: an armed Auto API action
// follows its engagement authorization without a per-action prompt.
func TestAuthorizeAPIRequestWriteArmedAutoDoesNotPrompt(t *testing.T) {
	called := false
	g := browserGate(t, Auto, recordingConfirmer{ok: true, called: &called})
	d := g.AuthorizeAPIRequest(context.Background(), APIRequest{Method: "POST", URL: "http://10.0.0.5/api/v1/users", Armed: true})
	if !d.Allowed {
		t.Fatalf("armed POST with an approving confirmer denied: %q", d.Reason)
	}
	if called {
		t.Error("an armed Auto API action must not require a per-action confirmation")
	}
}

// TestAuthorizeAPIRequestOutOfScopeDenied: an API request to an out-of-scope host
// is denied.
func TestAuthorizeAPIRequestOutOfScopeDenied(t *testing.T) {
	g := browserGate(t, Auto, nil)
	d := g.AuthorizeAPIRequest(context.Background(), APIRequest{Method: "GET", URL: "https://8.8.8.8/api", Armed: false})
	if d.Allowed {
		t.Fatal("out-of-scope API request allowed, want denied")
	}
}

// TestAuthorizeWebRedirectOutOfScopeDenied: a redirect hop to an out-of-scope
// host is denied, so a 30x cannot carry the browser/API client off scope.
func TestAuthorizeWebRedirectOutOfScopeDenied(t *testing.T) {
	g := browserGate(t, Auto, nil)
	d := g.AuthorizeWebRedirect("http://169.254.169.254/latest/meta-data/")
	if d.Allowed {
		t.Fatal("redirect to an out-of-scope host was allowed, want denied")
	}
}

// TestAuthorizeWebRedirectInScopeAllowed: a redirect hop that stays in scope is
// allowed.
func TestAuthorizeWebRedirectInScopeAllowed(t *testing.T) {
	g := browserGate(t, Auto, nil)
	d := g.AuthorizeWebRedirect("http://10.0.0.9/next")
	if !d.Allowed {
		t.Fatalf("in-scope redirect hop denied: %q", d.Reason)
	}
}
