package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// TestWebPinnedDHIImageDigest pins the DHI image digest + browser version the
// adapter connects to. blkChain references the image by this SHA256 digest only,
// never the floating :1 tag.
func TestWebPinnedDHIImageDigest(t *testing.T) {
	if webPinnedDHIImageDigest != "sha256:362a6b32631204936ec45c03f5c0f0b75bab6489a05031d59f51665fef3d7851" {
		t.Errorf("webPinnedDHIImageDigest = %q, want the pinned DHI digest", webPinnedDHIImageDigest)
	}
	if !strings.HasPrefix(webPinnedDHIImageDigest, "sha256:") {
		t.Error("the image must be pinned by sha256 digest, not a tag")
	}
	if webPinnedDHIBrowserVersion != "1.63.0" {
		t.Errorf("webPinnedDHIBrowserVersion = %q, want 1.63.0", webPinnedDHIBrowserVersion)
	}
}

// TestWebValidateCDPEndpoint: the CDP endpoint must be an http(s) URL on a
// loopback host. Divergence cases: loopback forms accepted; a routable host,
// 0.0.0.0, a hostname, and a bad scheme rejected.
func TestWebValidateCDPEndpoint(t *testing.T) {
	ok := []string{"http://127.0.0.1:9222", "http://localhost:9222/", "http://[::1]:9222", "https://127.0.0.1:9000"}
	for _, ep := range ok {
		if err := webValidateCDPEndpoint(ep); err != nil {
			t.Errorf("webValidateCDPEndpoint(%q) = %v, want nil (loopback)", ep, err)
		}
	}
	bad := []string{
		"http://10.0.0.5:9222",    // routable host
		"http://0.0.0.0:9222",     // wildcard, not loopback
		"http://evil.example/",    // hostname
		"http://169.254.169.254/", // link-local metadata
		"ftp://127.0.0.1/",        // bad scheme
		"127.0.0.1:9222",          // no scheme
		"::not a url",             // unparseable
	}
	for _, ep := range bad {
		if err := webValidateCDPEndpoint(ep); err == nil {
			t.Errorf("webValidateCDPEndpoint(%q) = nil, want a rejection", ep)
		}
	}
}

// TestWebPlaywrightDriverFailsClosedNoCDP: provisioned local driver but no CDP
// endpoint set -> fail closed before any playwright.Run/connect (no download).
func TestWebPlaywrightDriverFailsClosedNoCDP(t *testing.T) {
	t.Setenv("PLAYWRIGHT_DRIVER_PATH", "/nonexistent/pinned/driver")
	t.Setenv("PLAYWRIGHT_CLI_PATH", "")
	t.Setenv("BLKCHAIN_PLAYWRIGHT_CDP", "")
	d, err := newWebPlaywrightDriver()
	if err == nil {
		if d != nil {
			_ = d.Close()
		}
		t.Fatal("no CDP endpoint must fail closed, got nil error")
	}
	if !errors.Is(err, errWebDriverUnavailable) {
		t.Fatalf("error must wrap errWebDriverUnavailable, got %v", err)
	}
}

// TestWebPlaywrightDriverRejectsNonLoopbackCDP: a non-loopback CDP endpoint is
// rejected (fail closed) even with the local driver provisioned.
func TestWebPlaywrightDriverRejectsNonLoopbackCDP(t *testing.T) {
	t.Setenv("PLAYWRIGHT_DRIVER_PATH", "/nonexistent/pinned/driver")
	t.Setenv("PLAYWRIGHT_CLI_PATH", "")
	t.Setenv("BLKCHAIN_PLAYWRIGHT_CDP", "http://10.0.0.5:9222")
	_, err := newWebPlaywrightDriver()
	if err == nil {
		t.Fatal("a non-loopback CDP endpoint must be rejected")
	}
	if !errors.Is(err, errWebDriverUnavailable) {
		t.Fatalf("error must wrap errWebDriverUnavailable, got %v", err)
	}
}

// TestWebPinnedPlaywrightVersion pins the exact Playwright driver/CLI version the
// adapter is built against (playwright-go binding v0.6201.1 embeds 1.62.1). A
// change here must be matched by the provisioned driver + the pins manifest.
func TestWebPinnedPlaywrightVersion(t *testing.T) {
	if webPinnedPlaywrightVersion != "1.62.1" {
		t.Fatalf("webPinnedPlaywrightVersion = %q, want 1.62.1 (matching playwright-go v0.6201.1)", webPinnedPlaywrightVersion)
	}
}

// TestWebPlaywrightProvisionedEnv: provisioning is detected only from the
// PLAYWRIGHT_* env; with none set the adapter is considered unprovisioned.
func TestWebPlaywrightProvisionedEnv(t *testing.T) {
	t.Setenv("PLAYWRIGHT_DRIVER_PATH", "")
	t.Setenv("PLAYWRIGHT_CLI_PATH", "")
	if webPlaywrightProvisioned() {
		t.Fatal("with no PLAYWRIGHT_* set, provisioned must be false")
	}
	t.Setenv("PLAYWRIGHT_DRIVER_PATH", "/opt/pinned/playwright")
	t.Setenv("BLKCHAIN_PLAYWRIGHT_CONTAINER", "fixture")
	if !webPlaywrightProvisioned() {
		t.Fatal("with PLAYWRIGHT_DRIVER_PATH set, provisioned must be true")
	}
}

// TestWebPlaywrightDriverFailsClosedUnprovisioned: with no provisioning, the live
// driver constructor fails closed (errWebDriverUnavailable) and never attempts a
// download. provisioned() is false, so playwright.Run (which would validate/err,
// never fetch) is not even reached.
func TestWebPlaywrightDriverFailsClosedUnprovisioned(t *testing.T) {
	t.Setenv("PLAYWRIGHT_DRIVER_PATH", "")
	t.Setenv("PLAYWRIGHT_CLI_PATH", "")
	d, err := newWebPlaywrightDriver()
	if err == nil {
		if d != nil {
			_ = d.Close()
		}
		t.Fatal("unprovisioned newWebPlaywrightDriver must fail closed, got nil error")
	}
	if !errors.Is(err, errWebDriverUnavailable) {
		t.Fatalf("error must wrap errWebDriverUnavailable, got %v", err)
	}
}

// TestWebParseHeaderLines parses "Name: value" header lines and skips malformed ones.
func TestWebParseHeaderLines(t *testing.T) {
	h := webParseHeaderLines([]string{"Authorization: Bearer x", "Content-Type:application/json", "nocolon", ": noname"})
	if h["Authorization"] != "Bearer x" {
		t.Errorf("Authorization = %q, want 'Bearer x'", h["Authorization"])
	}
	if h["Content-Type"] != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", h["Content-Type"])
	}
	if len(h) != 2 {
		t.Errorf("want 2 valid headers, got %d: %v", len(h), h)
	}
}

// TestWebResolveRedirect resolves absolute and relative Location values against
// the request URL.
func TestWebResolveRedirect(t *testing.T) {
	if got := webResolveRedirect("http://10.0.0.5/a/b", "https://evil.example/x"); got != "https://evil.example/x" {
		t.Errorf("absolute redirect = %q, want the absolute URL", got)
	}
	if got := webResolveRedirect("http://10.0.0.5/a/b", "/c"); got != "http://10.0.0.5/c" {
		t.Errorf("relative redirect = %q, want http://10.0.0.5/c", got)
	}
}

// TestWebBoundOutput caps oversized output.
func TestWebBoundOutput(t *testing.T) {
	big := strings.Repeat("x", webMaxDriverBytes+50)
	out := webBoundOutput(big)
	if len(out) <= webMaxDriverBytes {
		t.Fatalf("bounded output len=%d, want > cap with marker", len(out))
	}
	if !strings.Contains(out, "truncated") {
		t.Error("bounded output must carry a truncation marker")
	}
	small := "ok"
	if webBoundOutput(small) != small {
		t.Error("small output must pass through unchanged")
	}
}

// TestWebDriverNeverCallsInstall is a source guard: no PRODUCTION file in this
// package may call playwright.Install or (*PlaywrightDriver).DownloadDriver. The
// offline posture forbids an uncontrolled driver/browser fetch; the only
// acquisition is operator pre-provisioning. This scans non-test .go files for the
// call forms (with "("), so prose mentions in comments do not trip it.
func TestWebDriverNeverCallsInstall(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"playwright.Install(", ".DownloadDriver(", ".Install("}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, f := range forbidden {
			if strings.Contains(src, f) {
				t.Errorf("%s contains forbidden driver-fetch call %q: blkChain must never auto-download the Playwright driver/browsers", name, f)
			}
		}
	}
}
