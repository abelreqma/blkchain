package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/webacquire"
)

func TestWebPlaywrightUsesApprovedPivotBroker(t *testing.T) {
	if os.Getenv("BLKCHAIN_PW_E2E") != "1" || os.Getenv("BLKCHAIN_ENGAGE_DOCKER_E2E") != "1" {
		t.Skip("requires the pinned browser and local Docker fixture")
	}
	ip, _ := startDockerHTTPFixture(t, "browser-pivot", "internal-browser-fixture")
	roe, err := ParseRoE(strings.NewReader("## In Scope\n" + ip + "\n\n## Foothold\n" + ip + " transport=command surfaces=web exec=env\n"))
	if err != nil {
		t.Fatal(err)
	}
	pivotScope, err := roe.Scope.WithApprovedPrivateNetworks([]string{ip + "/32"})
	if err != nil {
		t.Fatal(err)
	}
	gate := &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, PivotScope: pivotScope, Policy: roe.Policy,
		Allow: secgate.NewAllowlist("env")}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner, err := newEngageRunner(ctx, roe)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	ctx = context.WithValue(ctx, engageRuntimeKey{}, &engageRuntime{runner: runner, policy: roe.Policy})
	driver, err := newWebPlaywrightDriver()
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	broker := newWebBroker(gate, nil)
	target := "http://" + ip + ":8080/"
	direct, err := broker.Fetch(ctx, webacquire.Request{URL: target})
	if err != nil || string(direct.Body) != "internal-browser-fixture" {
		t.Fatalf("pivot broker control=%+v err=%v", direct, err)
	}
	driver.broker = broker
	page, err := driver.DoBrowser(ctx, webBrowserAction{Op: webBrowserNavigate, URL: target}, nil)
	if err != nil || !strings.Contains(page, "internal-browser-fixture") {
		t.Fatalf("pivoted browser page=%q err=%v", page, err)
	}
}
