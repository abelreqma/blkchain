package main

import (
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
)

// TestWebBrowserOpClassification pins the passive/active split that drives the
// tier: navigate is passive (recon); inject and submit are active and state-
// changing (exploit, which the gate denies unless the task is armed).
func TestWebBrowserOpClassification(t *testing.T) {
	cases := []struct {
		op     webBrowserOp
		valid  bool
		active bool
		phase  engagement.Phase
	}{
		{webBrowserNavigate, true, false, engagement.PhaseRecon},
		{webBrowserInject, true, true, engagement.PhaseExploit},
		{webBrowserSubmit, true, true, engagement.PhaseExploit},
		{webBrowserOp("evaljs"), false, false, engagement.PhaseExploit},
	}
	for _, c := range cases {
		if got := c.op.valid(); got != c.valid {
			t.Errorf("op %q valid()=%v, want %v", c.op, got, c.valid)
		}
		if got := c.op.active(); got != c.active {
			t.Errorf("op %q active()=%v, want %v", c.op, got, c.active)
		}
		if got := c.op.webPhase(); got != c.phase {
			t.Errorf("op %q webPhase()=%v, want %v", c.op, got, c.phase)
		}
	}
}

// TestWebParseBrowserActionValidates: the tool args must name a valid op and a
// parseable http/https URL with a host; everything else fails closed with an
// error (no action is produced).
func TestWebParseBrowserActionValidates(t *testing.T) {
	good := []string{
		`{"op":"navigate","url":"http://10.0.0.5/"}`,
		`{"op":"inject","url":"https://10.0.0.5/search?q=1","payload":"<script>1</script>"}`,
		`{"op":"submit","url":"http://10.0.0.5/login","form_selector":"form#login","fields":{"#user":"a","#pass":"b"}}`,
	}
	for _, in := range good {
		if _, err := webParseBrowserAction(in); err != nil {
			t.Errorf("webParseBrowserAction(%s) err=%v, want nil", in, err)
		}
	}
	bad := []string{
		`{"op":"navigate"}`,                         // no URL
		`{"op":"navigate","url":"ftp://10.0.0.5/"}`, // non-http scheme
		`{"op":"navigate","url":"/relative/path"}`,  // no scheme/host
		`{"op":"navigate","url":"http:///nohost"}`,  // no host
		`{"op":"evaljs","url":"http://10.0.0.5/"}`,  // invalid op
		`{"url":"http://10.0.0.5/"}`,                // missing op
		`not json`,                                  // malformed
	}
	for _, in := range bad {
		if _, err := webParseBrowserAction(in); err == nil {
			t.Errorf("webParseBrowserAction(%s) err=nil, want a validation error", in)
		}
	}
}

// TestWebParseBrowserActionHost: the parsed action exposes the target host for
// the gate's scope check (the port is not part of the host).
func TestWebParseBrowserActionHost(t *testing.T) {
	act, err := webParseBrowserAction(`{"op":"navigate","url":"https://10.0.0.5:8443/app"}`)
	if err != nil {
		t.Fatal(err)
	}
	if act.host() != "10.0.0.5" {
		t.Fatalf("host()=%q, want 10.0.0.5 (no userinfo, no port)", act.host())
	}
}

// TestWebUntrustedTag: driver output is wrapped as untrusted web content before
// it reaches the model (page content is attacker-controlled, same posture as a
// web corpus result).
func TestWebUntrustedTag(t *testing.T) {
	out := webUntrustedTag("<html>evil</html>")
	if !strings.Contains(strings.ToLower(out), "untrusted") {
		t.Errorf("webUntrustedTag output missing the untrusted marker: %q", out)
	}
	if !strings.Contains(out, "<html>evil</html>") {
		t.Errorf("webUntrustedTag dropped the body: %q", out)
	}
}

// TestWebParseAPIRequestValidates: the API tool args must name a known HTTP
// method and a parseable http/https URL with a host; everything else fails closed.
func TestWebParseAPIRequestValidates(t *testing.T) {
	good := []string{
		`{"method":"GET","url":"http://10.0.0.5/api/users"}`,
		`{"method":"post","url":"https://10.0.0.5/api/users","body":"{}"}`,
		`{"method":"DELETE","url":"http://10.0.0.5/api/users/1"}`,
	}
	for _, in := range good {
		if _, err := webParseAPIRequest(in); err != nil {
			t.Errorf("webParseAPIRequest(%s) err=%v, want nil", in, err)
		}
	}
	bad := []string{
		`{"method":"GET"}`, // no URL
		`{"method":"FETCHALL","url":"http://10.0.0.5/"}`, // unknown method
		`{"method":"GET","url":"ftp://10.0.0.5/"}`,       // non-http scheme
		`{"url":"http://10.0.0.5/"}`,                     // missing method
		`{"method":"GET","url":"http:///nohost"}`,        // no host
		`not json`, // malformed
	}
	for _, in := range bad {
		if _, err := webParseAPIRequest(in); err == nil {
			t.Errorf("webParseAPIRequest(%s) err=nil, want a validation error", in)
		}
	}
}

// TestWebAPIRequestHost: the parsed request exposes the host for the gate's scope
// check without its port.
func TestWebAPIRequestHost(t *testing.T) {
	r, err := webParseAPIRequest(`{"method":"GET","url":"https://10.0.0.5:8443/api"}`)
	if err != nil {
		t.Fatal(err)
	}
	if r.host() != "10.0.0.5" {
		t.Fatalf("host()=%q, want 10.0.0.5", r.host())
	}
}
