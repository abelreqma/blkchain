package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestWebPlaywrightE2E drives the REAL production adapter end-to-end
// (newWebPlaywrightDriver -> ConnectOverCDP -> DoBrowser / DoAPIRequest) against a
// provisioned, pinned DHI container. It is an integration test, gated by
// BLKCHAIN_PW_E2E=1 and skipped in the normal suite; it requires a provisioned
// environment:
//   - PLAYWRIGHT_DRIVER_PATH: the pinned local playwright-core 1.62.1 driver dir.
//   - BLKCHAIN_PLAYWRIGHT_CDP: the loopback CDP endpoint of the running pinned DHI
//     container (image digest webPinnedDHIImageDigest).
//
// This is the live-verification harness for the CDP connection model; it proves
// the production code path (not a probe) works against the pinned 1.63.0 browser.
func TestWebPlaywrightE2E(t *testing.T) {
	if os.Getenv("BLKCHAIN_PW_E2E") != "1" {
		t.Skip("E2E disabled; set BLKCHAIN_PW_E2E=1 with PLAYWRIGHT_DRIVER_PATH + a running pinned DHI container at BLKCHAIN_PLAYWRIGHT_CDP")
	}
	drv, err := newWebPlaywrightDriver()
	if err != nil {
		t.Fatalf("newWebPlaywrightDriver (production path): %v", err)
	}
	defer drv.Close()

	allow := func(string) bool { return true } // the gate is validated separately; this probes the driver.

	out, err := drv.DoBrowser(context.Background(), webBrowserAction{Op: webBrowserNavigate, URL: "data:text/html,<title>e2e-ok</title><h1>hi</h1>"}, allow)
	if err != nil {
		t.Fatalf("DoBrowser: %v", err)
	}
	t.Logf("BROWSER-LEG out(len=%d): %.90s", len(out), strings.ReplaceAll(out, "\n", " "))
	if !strings.Contains(out, "e2e-ok") {
		t.Errorf("browser content missing the expected marker: %q", out)
	}

	cdp := os.Getenv("BLKCHAIN_PLAYWRIGHT_CDP")
	apiOut, err := drv.DoAPIRequest(context.Background(), webAPIRequest{Method: "GET", URL: cdp + "/json/version"}, allow)
	if err != nil {
		t.Fatalf("DoAPIRequest: %v", err)
	}
	t.Logf("API-LEG out(len=%d): %.90s", len(apiOut), strings.ReplaceAll(apiOut, "\n", " "))
	if !strings.Contains(apiOut, "200") || !strings.Contains(apiOut, "Browser") {
		t.Errorf("api response unexpected: %q", apiOut)
	}
}
