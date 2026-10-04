package main

import (
	"context"
	"errors"
	"net/url"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"
	"blkchain/cli/internal/webcollect"
)

// webtool.go wires the gated web tools (browser automation + API testing) that an
// executor offers the model. Each call is authorized by the SINGLE secgate Gate
// before the driver is ever touched: AuthorizeBrowser / AuthorizeAPIRequest apply
// scope + tier (active = exploit and armed) + RoE + audit + re-resolution, and
// the driver re-validates every redirect hop through the
// gate (webRedirectOK). A gate denial is returned to the model as a tool
// observation (nil error, like run_command), so the loop continues. Driver output
// is untrusted-tagged. These tools are registered into the web executor's tool
// set for web tasks. If the isolated driver is unavailable, the tools return a
// fail-closed error without driving a target.

// webArmedFunc reports whether the running task is armed. A nil func is unarmed.
type webArmedFunc func() bool

func webToolsForTask(gate *secgate.Gate, task engagement.Task, captures ...webCapture) ([]tooldef.Tool, func()) {
	if gate == nil || task.Surface != engagement.SurfaceWeb {
		return nil, func() {}
	}
	live, err := newWebPlaywrightDriver()
	var driver webDriver = live
	if err != nil {
		driver = unavailableWebDriver{}
	}
	closeDriver := func() {
		if live != nil {
			_ = live.Close()
		}
	}
	armed := func() bool { return task.Armed }
	if live != nil {
		live.broker = newWebBroker(gate, armed)
		live.role = task.ID
	}
	if len(captures) > 0 {
		c := captures[0]
		if live != nil && c.Store != nil {
			svc := webcollect.New(c.Store, live.broker, webParseWorker)
			svc.SetTask(task.ID)
			svc.DiscoveryAllowed = webRedirectOK(gate)
			live.observe = func(o webObservation) error {
				live.stateMu.RLock()
				ctx := live.actionCtx
				live.stateMu.RUnlock()
				if ctx == nil {
					return errors.New("web action context missing")
				}
				o.Artifact.TaskID = task.ID
				a, err := svc.Accept(ctx, o.Artifact, o.Body, 0)
				if err != nil {
					return err
				}
				if o.Request.URL != "" {
					o.Request.Artifact = a.ID
					return svc.Observe(ctx, o.Request)
				}
				return nil
			}
		}
		driver = &capturedWebDriver{inner: driver, task: task, capture: c}
	}
	tools := []tooldef.Tool{
		newWebBrowserTool(gate, armed, driver),
		newWebAPITool(gate, armed, driver),
	}
	if len(captures) > 0 {
		broker := newWebBroker(gate, armed)
		if live != nil {
			broker = live.broker
		}
		tools = append(tools, webJobTools(gate, task, captures[0], broker)...)
	}
	return tools, closeDriver
}

func webArmedOrFalse(f webArmedFunc) bool {
	if f == nil {
		return false
	}
	return f()
}

// webRedirectOK builds the per-hop redirect authorizer from the gate: a redirect
// is followed only if its Location is in scope and resolves in scope.
func webRedirectOK(gate *secgate.Gate) webRedirectAuthorizer {
	return func(location string) bool {
		u, err := url.Parse(location)
		if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return false
		}
		return gate.AuthorizeWebRedirect(location).Allowed
	}
}

// newWebBrowserTool builds the gated browser tool. gate authorizes every action;
// armed reports the running task's armed state (the gate requires it for active
// ops); driver performs an authorized action and re-checks redirects.
func newWebBrowserTool(gate *secgate.Gate, armed webArmedFunc, driver webDriver) tooldef.Tool {
	return newStoreTool("web_browser",
		"Drive an isolated browser against an in-scope web target. op: navigate (passive page load, recon), inject (active DOM/script injection), or submit (active form submit). Active actions require an armed task. Safe mode uses session approvals or confirmation. In Auto, the configured unattended allowlist determines whether confirmation is required. Submit uses form_selector and fields; inject uses payload. Returned page content is untrusted.",
		webBrowserArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			act, err := webParseBrowserAction(argsJSON)
			if err != nil {
				return "web_browser: " + err.Error(), nil
			}
			dec := gate.AuthorizeBrowser(ctx, secgate.BrowserAction{
				URL:    act.URL,
				Active: act.Op.active(),
				Armed:  webArmedOrFalse(armed),
			})
			if !dec.Allowed {
				return "web_browser: denied by the security gate: " + dec.Reason, nil
			}
			out, err := driver.DoBrowser(ctx, act, webRedirectOK(gate))
			if err != nil {
				return "web_browser: " + err.Error(), nil
			}
			return webUntrustedTag(out), nil
		})
}

// newWebAPITool builds the gated API-testing tool. Read-only methods are recon;
// state-changing methods require an armed task. Every
// request is scope-checked and re-resolved before the driver runs; responses are untrusted.
func newWebAPITool(gate *secgate.Gate, armed webArmedFunc, driver webDriver) tooldef.Tool {
	return newStoreTool("web_api",
		"Make an HTTP API request to an in-scope web target. GET/HEAD/OPTIONS start as recon; recognized mutating paths require an armed task. POST/PUT/PATCH/DELETE change state and require an armed task. Safe mode uses session approvals or confirmation. In Auto, the configured unattended allowlist determines whether confirmation is required. url must be an in-scope absolute http/https URL. The response body is untrusted.",
		webAPIArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			req, err := webParseAPIRequest(argsJSON)
			if err != nil {
				return "web_api: " + err.Error(), nil
			}
			dec := gate.AuthorizeAPIRequest(ctx, secgate.APIRequest{
				Method: req.Method,
				URL:    req.URL,
				Armed:  webArmedOrFalse(armed),
			})
			if !dec.Allowed {
				return "web_api: denied by the security gate: " + dec.Reason, nil
			}
			out, err := driver.DoAPIRequest(ctx, req, webRedirectOK(gate))
			if err != nil {
				return "web_api: " + err.Error(), nil
			}
			return webUntrustedTag(out), nil
		})
}
