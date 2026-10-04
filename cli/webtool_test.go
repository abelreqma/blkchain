package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/secgate"
)

// webFakeDriver records which path was driven and returns a canned body, so a
// tool test can assert the driver is reached only on an allow and that its output
// is untrusted-tagged. It also captures the redirect authorizer the tool wired.
type webFakeDriver struct {
	browserCalled bool
	apiCalled     bool
	body          string
	redirectOK    webRedirectAuthorizer
}

func (f *webFakeDriver) DoBrowser(ctx context.Context, act webBrowserAction, r webRedirectAuthorizer) (string, error) {
	f.browserCalled = true
	f.redirectOK = r
	return f.body, nil
}

func (f *webFakeDriver) DoAPIRequest(ctx context.Context, req webAPIRequest, r webRedirectAuthorizer) (string, error) {
	f.apiCalled = true
	f.redirectOK = r
	return f.body, nil
}

// webErrDriver is a test driver that always fails closed with
// errWebDriverUnavailable, standing in for the real adapter when the pinned
// Playwright driver is not provisioned, so the tool's error-surfacing can be
// tested without a live browser.
type webErrDriver struct{}

func (webErrDriver) DoBrowser(ctx context.Context, act webBrowserAction, r webRedirectAuthorizer) (string, error) {
	return "", errWebDriverUnavailable
}

func (webErrDriver) DoAPIRequest(ctx context.Context, req webAPIRequest, r webRedirectAuthorizer) (string, error) {
	return "", errWebDriverUnavailable
}

// webOKConfirmer approves every confirmation (for the armed-active allow path).
type webOKConfirmer struct{}

func (webOKConfirmer) Confirm(ctx context.Context, c secgate.Command) bool { return true }

func webConfirmGate(t *testing.T) *secgate.Gate {
	t.Helper()
	s, err := secgate.ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	return &secgate.Gate{Mode: secgate.Auto, Scope: s, Confirm: webOKConfirmer{}, Approvals: secgate.NewSessionApprovals()}
}

func TestWebBrowserToolDeniesOutOfScope(t *testing.T) {
	drv := &webFakeDriver{body: "page"}
	tool := newWebBrowserTool(autoGate(t), nil, drv)
	out, err := tool.Call(context.Background(), `{"op":"navigate","url":"http://8.8.8.8/"}`)
	if err != nil {
		t.Fatal(err)
	}
	if drv.browserCalled {
		t.Fatal("driver must not be reached when the gate denies an out-of-scope target")
	}
	if !strings.Contains(strings.ToLower(out), "denied") {
		t.Errorf("want a gate denial surfaced to the model, got %q", out)
	}
}

func TestWebBrowserToolActiveNeedsArm(t *testing.T) {
	drv := &webFakeDriver{body: "page"}
	tool := newWebBrowserTool(webConfirmGate(t), func() bool { return false }, drv)
	out, err := tool.Call(context.Background(), `{"op":"inject","url":"http://10.0.0.5/x","payload":"<script>1</script>"}`)
	if err != nil {
		t.Fatal(err)
	}
	if drv.browserCalled {
		t.Fatal("an active browser op on an unarmed task must be denied before the driver runs")
	}
	if !strings.Contains(strings.ToLower(out), "arm") {
		t.Errorf("want an arm-required denial, got %q", out)
	}
}

func TestWebBrowserToolPassiveAllowedUntrusted(t *testing.T) {
	drv := &webFakeDriver{body: "<html>hello</html>"}
	tool := newWebBrowserTool(autoGate(t), nil, drv)
	out, err := tool.Call(context.Background(), `{"op":"navigate","url":"http://10.0.0.5/app"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !drv.browserCalled {
		t.Fatal("passive in-scope navigation should reach the driver")
	}
	if !strings.Contains(strings.ToLower(out), "untrusted") || !strings.Contains(out, "<html>hello</html>") {
		t.Errorf("output must be untrusted-tagged and carry the body, got %q", out)
	}
}

func TestWebBrowserToolRedirectAuthorizerWiredToGate(t *testing.T) {
	drv := &webFakeDriver{body: "page"}
	tool := newWebBrowserTool(autoGate(t), nil, drv)
	if _, err := tool.Call(context.Background(), `{"op":"navigate","url":"http://10.0.0.5/app"}`); err != nil {
		t.Fatal(err)
	}
	if drv.redirectOK == nil {
		t.Fatal("the tool must hand the driver a redirect authorizer")
	}
	if drv.redirectOK("http://169.254.169.254/latest/") {
		t.Error("redirect authorizer must deny an out-of-scope host")
	}
	if !drv.redirectOK("http://10.0.0.9/next") {
		t.Error("redirect authorizer must allow an in-scope host")
	}
}

func TestWebAPIToolReadAllowedUntrusted(t *testing.T) {
	drv := &webFakeDriver{body: `{"ok":true}`}
	tool := newWebAPITool(autoGate(t), nil, drv)
	out, err := tool.Call(context.Background(), `{"method":"GET","url":"http://10.0.0.5/api/users"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !drv.apiCalled {
		t.Fatal("an in-scope GET should reach the driver")
	}
	if !strings.Contains(strings.ToLower(out), "untrusted") || !strings.Contains(out, `{"ok":true}`) {
		t.Errorf("API output must be untrusted-tagged and carry the body, got %q", out)
	}
}

func TestWebAPIToolWriteNeedsArm(t *testing.T) {
	drv := &webFakeDriver{body: "x"}
	tool := newWebAPITool(webConfirmGate(t), func() bool { return false }, drv)
	out, err := tool.Call(context.Background(), `{"method":"POST","url":"http://10.0.0.5/api/users","body":"{}"}`)
	if err != nil {
		t.Fatal(err)
	}
	if drv.apiCalled {
		t.Fatal("an unarmed POST must be denied before the driver runs")
	}
	if !strings.Contains(strings.ToLower(out), "arm") {
		t.Errorf("want an arm-required denial, got %q", out)
	}
}

func TestWebAPIToolWriteArmedConfirmed(t *testing.T) {
	drv := &webFakeDriver{body: "created"}
	tool := newWebAPITool(webConfirmGate(t), func() bool { return true }, drv)
	out, err := tool.Call(context.Background(), `{"method":"POST","url":"http://10.0.0.5/api/users","body":"{}"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !drv.apiCalled {
		t.Fatal("an armed, confirmed POST should reach the driver")
	}
	if !strings.Contains(out, "created") {
		t.Errorf("want the driver body in the output, got %q", out)
	}
}

// TestWebToolDriverUnavailableSurfacesFailClosed: when the gate allows but no
// verified driver is provisioned, the tool surfaces the fail-closed message to
// the model rather than crashing the loop or driving a target.
func TestWebToolDriverUnavailableSurfacesFailClosed(t *testing.T) {
	tool := newWebBrowserTool(autoGate(t), nil, webErrDriver{})
	out, err := tool.Call(context.Background(), `{"op":"navigate","url":"http://10.0.0.5/app"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(out), "not available") {
		t.Errorf("want the fail-closed driver-unavailable message, got %q", out)
	}
}
