package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/mxschmitt/playwright-go"
)

// webplaywright.go is the live web driver for the gated web tools: a webDriver
// backed by playwright-go (binding v0.6201.1, the Playwright 1.62.1 client). It
// drives real browser automation and real API testing (APIRequestContext), and
// NEVER downloads anything.
//
// CONNECTION MODEL: the browser, which
// renders attacker-controlled web content - runs INSIDE a pinned Docker Hardened
// Image (dhi/playwright, referenced BY SHA256 DIGEST, carrying Playwright 1.63.0
// browsers), which the operator provisions and runs out-of-band, exposing a
// LOOPBACK-only CDP endpoint. blkChain connects to that endpoint with
// pw.Chromium.ConnectOverCDP: CDP is tied to the Chromium build, not Playwright's
// own wire protocol, so the 1.62.1 client drives the 1.63.0 browser (validated:
// ConnectOverCDP + a navigation + Title, and an APIRequestContext GET=200). The
// local side starts the pinned playwright-core package inside the same container
// through a hash-checked launcher; Node never runs on the operator host. The API
// leg uses the isolated driver's APIRequestContext.
//
// blkChain never calls playwright.Install / DownloadDriver on any path (a
// source-guard test enforces this), never pulls the image's floating :1 tag
// (digest only), and FAILS CLOSED when the local driver or the loopback CDP
// endpoint is not provisioned. The CDP endpoint MUST be loopback (the DHI
// container binds CDP loopback-only; a non-loopback endpoint is rejected).
//
// Every action is authorized by secgate before the driver runs. The driver
// re-checks browser requests and API redirect hops against scope. These checks
// do not pin the browser's eventual socket destination; the provisioning guide
// records that remaining egress boundary.

// webPinnedPlaywrightVersion is the exact LOCAL Playwright driver/CLI version the
// client is built against (playwright-go binding v0.6201.1). Provisioning must
// supply exactly this local driver; playwright.Run refuses a mismatch.
const webPinnedPlaywrightVersion = "1.62.1"

// webPinnedDHIImageDigest is the pinned Docker Hardened Image the operator runs to
// serve the browsers over CDP. blkChain references it BY DIGEST only (never the
// floating :1 tag). It carries Playwright 1.63.0 browsers; CDP bridges the 1.62.1
// client to them. Recorded here and in the provisioning manifest/docs.
const webPinnedDHIImageDigest = "sha256:362a6b32631204936ec45c03f5c0f0b75bab6489a05031d59f51665fef3d7851"

// webPinnedDHIBrowserVersion is the Playwright version of the browsers in the
// pinned DHI image (for the provisioning manifest/docs).
const webPinnedDHIBrowserVersion = "1.63.0"

const webDriverLauncherSHA256 = "5021d5f31f68d772f4e5c0e2f418ef63e181ba314500f5b1fabdaa6174de1aa3"

// webMaxDriverBytes bounds text returned from a driver action after the browser
// has already materialized the page or response body.
const webMaxDriverBytes = 200_000

const webMaxPageRequests = 100

const webActionTimeout = 15_000

// webPlaywrightDriverDir returns the operator-provisioned driver directory, or ""
// when no provisioning is configured.
func webPlaywrightDriverDir() string {
	if p := strings.TrimSpace(os.Getenv("PLAYWRIGHT_DRIVER_PATH")); p != "" {
		return p
	}
	return ""
}

// webPlaywrightProvisioned reports whether the pinned driver is provisioned via
// the environment. Without PLAYWRIGHT_DRIVER_PATH, the adapter fails closed
// rather than letting playwright-go fall back to its default cache or download.
func webPlaywrightProvisioned() bool {
	return webPlaywrightDriverDir() != "" && strings.TrimSpace(os.Getenv("BLKCHAIN_PLAYWRIGHT_CONTAINER")) != ""
}

// webPlaywrightCDPEndpoint returns the loopback CDP endpoint of the pinned,
// operator-run DHI container, from BLKCHAIN_PLAYWRIGHT_CDP; "" when unset.
func webPlaywrightCDPEndpoint() string {
	return strings.TrimSpace(os.Getenv("BLKCHAIN_PLAYWRIGHT_CDP"))
}

// webIsLoopbackHost reports whether host is loopback. The CDP endpoint must be
// loopback: the DHI container binds CDP loopback-only, and a non-loopback endpoint
// would be a misconfiguration or an attempt to reach an unintended host.
func webIsLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// webValidateCDPEndpoint validates the CDP endpoint is an http(s) URL on a
// loopback host. It fails closed on anything else.
func webValidateCDPEndpoint(ep string) error {
	u, err := url.Parse(ep)
	if err != nil {
		return fmt.Errorf("invalid CDP endpoint: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("CDP endpoint scheme %q not allowed (want http or https)", u.Scheme)
	}
	if !webIsLoopbackHost(u.Hostname()) {
		return fmt.Errorf("CDP endpoint host %q is not loopback (the DHI container binds CDP loopback-only)", u.Hostname())
	}
	return nil
}

// webPlaywrightDriver is the live webDriver. It holds the local Playwright
// connection and the remote browser connected over CDP to the pinned DHI
// container.
type webPlaywrightDriver struct {
	pw         *playwright.Playwright
	browser    playwright.Browser
	mu         sync.Mutex
	context    playwright.BrowserContext
	page       playwright.Page
	redirectOK webRedirectAuthorizer
	requests   atomic.Int64
}

// newWebPlaywrightDriver starts the pinned driver through the isolated container
// launcher and connects over CDP to Chromium at the container-loopback endpoint.
// It fails closed (error wrapping errWebDriverUnavailable) when the
// local driver is not provisioned (PLAYWRIGHT_DRIVER_PATH), when the CDP endpoint
// is unset or not loopback, or when the connection fails. It NEVER downloads: a
// missing/mismatched local driver makes playwright.Run error, not fetch. The
// caller owns Close.
func newWebPlaywrightDriver() (*webPlaywrightDriver, error) {
	if !webPlaywrightProvisioned() {
		return nil, fmt.Errorf("%w: set PLAYWRIGHT_DRIVER_PATH and BLKCHAIN_PLAYWRIGHT_CONTAINER for the isolated Playwright driver", errWebDriverUnavailable)
	}
	driverDir := webPlaywrightDriverDir()
	launcher := filepath.Join(driverDir, "node")
	launcherBytes, err := os.ReadFile(launcher)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(launcherBytes)) != webDriverLauncherSHA256 {
		return nil, fmt.Errorf("%w: the Playwright node launcher is missing or does not match the pinned container launcher", errWebDriverUnavailable)
	}
	if override := strings.TrimSpace(os.Getenv("PLAYWRIGHT_NODEJS_PATH")); override != "" && override != launcher {
		return nil, fmt.Errorf("%w: PLAYWRIGHT_NODEJS_PATH must not override the isolated container launcher", errWebDriverUnavailable)
	}
	ep := webPlaywrightCDPEndpoint()
	if ep == "" {
		return nil, fmt.Errorf("%w: set BLKCHAIN_PLAYWRIGHT_CDP to the loopback CDP endpoint of the pinned DHI container (image %s)", errWebDriverUnavailable, webPinnedDHIImageDigest)
	}
	if err := webValidateCDPEndpoint(ep); err != nil {
		return nil, fmt.Errorf("%w: %v", errWebDriverUnavailable, err)
	}
	// SkipInstallBrowsers plus a provisioned DriverDirectory means Run validates
	// the existing LOCAL driver and never installs; the browsers live in the DHI
	// container, not locally.
	opts := &playwright.RunOptions{SkipInstallBrowsers: true}
	opts.DriverDirectory = driverDir
	pw, err := playwright.Run(opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errWebDriverUnavailable, err)
	}
	browser, err := pw.Chromium.ConnectOverCDP(ep)
	if err != nil {
		_ = pw.Stop()
		return nil, fmt.Errorf("%w: connect over CDP to the pinned DHI container failed: %v", errWebDriverUnavailable, err)
	}
	return &webPlaywrightDriver{pw: pw, browser: browser}, nil
}

type unavailableWebDriver struct{}

func (unavailableWebDriver) DoBrowser(context.Context, webBrowserAction, webRedirectAuthorizer) (string, error) {
	return "", errWebDriverUnavailable
}

func (unavailableWebDriver) DoAPIRequest(context.Context, webAPIRequest, webRedirectAuthorizer) (string, error) {
	return "", errWebDriverUnavailable
}

// Close disconnects from the remote browser (it does NOT stop the operator-run
// container) and stops the local Playwright driver.
func (d *webPlaywrightDriver) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var firstErr error
	if d.context != nil {
		if err := d.context.Close(); err != nil {
			firstErr = err
		}
	}
	if d.browser != nil {
		if err := d.browser.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if d.pw != nil {
		if err := d.pw.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (d *webPlaywrightDriver) ensureContext() error {
	if d.context != nil {
		return nil
	}
	bctx, err := d.browser.NewContext(&playwright.BrowserNewContextOptions{
		AcceptDownloads: playwright.Bool(false),
		ServiceWorkers:  playwright.ServiceWorkerPolicyBlock,
	})
	if err != nil {
		return fmt.Errorf("new browser context: %w", err)
	}
	bctx.SetDefaultTimeout(webActionTimeout)
	bctx.SetDefaultNavigationTimeout(webActionTimeout)
	if err := bctx.Route("**/*", func(route playwright.Route) {
		if d.requests.Add(1) > webMaxPageRequests {
			_ = route.Abort("blockedbyclient")
			return
		}
		raw := route.Request().URL()
		u, parseErr := url.Parse(raw)
		if parseErr == nil && u.User == nil && d.redirectOK != nil && d.redirectOK(raw) {
			_ = route.Continue()
			return
		}
		_ = route.Abort("blockedbyclient")
	}); err != nil {
		_ = bctx.Close()
		return fmt.Errorf("install route guard: %w", err)
	}
	page, err := bctx.NewPage()
	if err != nil {
		_ = bctx.Close()
		return fmt.Errorf("new page: %w", err)
	}
	d.context = bctx
	d.page = page
	return nil
}

// webBoundOutput caps a driver result to webMaxDriverBytes (runes), appending a
// truncation marker when it trims.
func webBoundOutput(s string) string {
	r := []rune(s)
	if len(r) <= webMaxDriverBytes {
		return s
	}
	return string(r[:webMaxDriverBytes]) + "\n...[truncated]"
}

// DoBrowser drives a headless Chromium action in the task-scoped browser context.
// It re-checks each browser request against scope. navigate returns page content;
// inject evaluates its payload; submit fills the selected form controls and
// calls requestSubmit.
func (d *webPlaywrightDriver) DoBrowser(ctx context.Context, act webBrowserAction, redirectOK webRedirectAuthorizer) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.redirectOK = redirectOK
	d.requests.Store(0)
	if err := d.ensureContext(); err != nil {
		return "", err
	}
	page := d.page
	var err error
	if _, err := page.Goto(act.URL); err != nil {
		return "", fmt.Errorf("navigate: %w", err)
	}
	switch act.Op {
	case webBrowserInject:
		if _, err := page.Evaluate(act.Payload); err != nil {
			return "", fmt.Errorf("evaluate payload: %w", err)
		}
	case webBrowserSubmit:
		form := page.Locator(act.FormSelector)
		count, err := form.Count()
		if err != nil {
			return "", fmt.Errorf("find form: %w", err)
		}
		if count != 1 {
			return "", fmt.Errorf("form selector matched %d elements, want exactly one", count)
		}
		selectors := make([]string, 0, len(act.Fields))
		for selector := range act.Fields {
			selectors = append(selectors, selector)
		}
		sort.Strings(selectors)
		for _, selector := range selectors {
			_, err := form.Evaluate(`(form, field) => {
				const control = form.querySelector(field.selector);
				if (!control || !("value" in control)) throw new Error("field is not a form control");
				const proto = Object.getPrototypeOf(control);
				const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
				if (!setter) throw new Error("form control has no value setter");
				setter.call(control, field.value);
				control.dispatchEvent(new Event("input", { bubbles: true }));
				control.dispatchEvent(new Event("change", { bubbles: true }));
			}`, map[string]string{"selector": selector, "value": act.Fields[selector]})
			if err != nil {
				return "", fmt.Errorf("fill form field: %w", err)
			}
		}
		if _, err := form.Evaluate("form => { if (!(form instanceof HTMLFormElement)) throw new Error('selector is not a form'); form.requestSubmit(); }", nil); err != nil {
			return "", fmt.Errorf("submit form: %w", err)
		}
	}
	content, err := page.Content()
	if err != nil {
		return "", fmt.Errorf("read content: %w", err)
	}
	return webBoundOutput(content), nil
}

// DoAPIRequest makes an API request via Playwright's APIRequestContext. It
// disables automatic redirect-following (MaxRedirects 0) and follows redirects
// manually, re-validating each hop's Location host against the gate (redirectOK),
// so an API redirect cannot carry the request to an out-of-scope or internal
// host. The response status, headers, and body are returned (bounded).
func (d *webPlaywrightDriver) DoAPIRequest(ctx context.Context, req webAPIRequest, redirectOK webRedirectAuthorizer) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.redirectOK = redirectOK
	if err := d.ensureContext(); err != nil {
		return "", err
	}
	apiCtx := d.context.Request()

	headers := webParseHeaderLines(req.Headers)
	target := req.URL
	const maxHops = 10
	for hop := 0; ; hop++ {
		if hop > maxHops {
			return "", fmt.Errorf("too many redirects (> %d)", maxHops)
		}
		opts := playwright.APIRequestContextFetchOptions{
			Method:       playwright.String(req.Method),
			MaxRedirects: playwright.Int(0),
			MaxRetries:   playwright.Int(0),
			Timeout:      playwright.Float(webActionTimeout),
		}
		if req.Body != "" {
			opts.Data = req.Body
		}
		if len(headers) > 0 {
			opts.Headers = headers
		}
		resp, err := apiCtx.Fetch(target, opts)
		if err != nil {
			return "", fmt.Errorf("api request: %w", err)
		}
		status := resp.Status()
		if status >= 300 && status < 400 {
			loc := resp.Headers()["location"]
			if loc == "" {
				return webAPIResponseText(resp)
			}
			if apiMethodActive(req.Method) {
				return webAPIResponseText(resp)
			}
			next := webResolveRedirect(target, loc)
			if redirectOK == nil || !redirectOK(next) {
				return "", fmt.Errorf("redirect to an out-of-scope host denied: %s", next)
			}
			if !webSameOrigin(target, next) {
				webClearHeaders(headers)
			}
			target = next
			continue
		}
		return webAPIResponseText(resp)
	}
}

// webAPIResponseText renders an API response as status + body (bounded).
func webAPIResponseText(resp playwright.APIResponse) (string, error) {
	body, err := resp.Text()
	if err != nil {
		body = ""
	}
	return webBoundOutput(fmt.Sprintf("%d %s\n\n%s", resp.Status(), resp.StatusText(), body)), nil
}

// webParseHeaderLines turns "Name: value" lines into a header map. A line without
// a colon is skipped.
func webParseHeaderLines(lines []string) map[string]string {
	if len(lines) == 0 {
		return nil
	}
	h := make(map[string]string, len(lines))
	for _, l := range lines {
		i := strings.IndexByte(l, ':')
		if i <= 0 {
			continue
		}
		name := strings.TrimSpace(l[:i])
		val := strings.TrimSpace(l[i+1:])
		if name != "" {
			h[name] = val
		}
	}
	return h
}

// webResolveRedirect resolves a redirect Location against the current request URL
// (absolute Location is used as-is; a relative one is resolved against base). A
// parse failure returns the raw location, which the scope recheck then fails
// closed on.
func webResolveRedirect(base, location string) string {
	bu, err := url.Parse(base)
	if err != nil {
		return location
	}
	ref, err := url.Parse(location)
	if err != nil {
		return location
	}
	return bu.ResolveReference(ref).String()
}
