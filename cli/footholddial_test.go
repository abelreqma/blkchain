package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/webacquire"
)

func TestFootholdStreamThroughGuardedWorker(t *testing.T) {
	if os.Getenv("BLKCHAIN_ENGAGE_DOCKER_E2E") != "1" {
		t.Skip("requires the pinned local Docker runner")
	}
	ip, _ := startDockerHTTPFixture(t, "pivot-stream", "pivot-stream-fixture")
	roe, err := ParseRoE(strings.NewReader("## In Scope\n" + ip + "\n\n## Foothold\n" + ip + " transport=command surfaces=web exec=env\n"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner, err := newEngageRunner(ctx, roe)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	conn, err := runner.DialFoothold(ctx, net.JoinHostPort(ip, "8080"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "pivot-stream-fixture" {
		t.Fatalf("stream response status=%d body=%q err=%v", response.StatusCode, body, err)
	}
}

func TestFootholdHostnameLookupUsesCarrierAndBoundsAnswers(t *testing.T) {
	var sent []pipelineStage
	runner := &engageRunner{foothold: &footholdTransport{name: "command", prefix: []string{"kubectl", "exec", "-i", "fixture", "--"}, quote: "argv"},
		runFn: func(_ context.Context, stages []pipelineStage, _ string, _ int, _ time.Duration) (runResult, []isolatedStageResult) {
			sent = stages
			return runResult{}, []isolatedStageResult{{Stdout: "10.7.0.7 STREAM app.internal.test\n10.7.0.7 DGRAM app.internal.test\n", ExitCode: 0}}
		}}
	ips, bytes, err := runner.LookupFootholdHost(context.Background(), "app.internal.test")
	if err != nil || len(ips) != 1 || ips[0].String() != "10.7.0.7" || bytes == 0 {
		t.Fatalf("carrier DNS result ips=%v bytes=%d err=%v", ips, bytes, err)
	}
	if len(sent) != 1 || sent[0].Binary != "kubectl" || sent[0].Args[len(sent[0].Args)-3] != "getent" {
		t.Fatalf("lookup did not use carrier: %+v", sent)
	}
	runner.runFn = func(_ context.Context, _ []pipelineStage, _ string, _ int, _ time.Duration) (runResult, []isolatedStageResult) {
		return runResult{}, []isolatedStageResult{{Stdout: "not-an-ip STREAM app.internal.test\n", ExitCode: 0}}
	}
	if _, _, err := runner.LookupFootholdHost(context.Background(), "app.internal.test"); err == nil {
		t.Fatal("malformed foothold DNS output was accepted")
	}
}

func TestWebBrokerThroughGuardedCarrier(t *testing.T) {
	if os.Getenv("BLKCHAIN_ENGAGE_DOCKER_E2E") != "1" {
		t.Skip("requires the pinned local Docker runner")
	}
	ip, _ := startDockerHTTPFixture(t, "web-pivot", "web-pivot-fixture")
	roe, err := ParseRoE(strings.NewReader("## In Scope\n" + ip + "\n\n## Foothold\n" + ip + " transport=command surfaces=web exec=env\n"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner, err := newEngageRunner(ctx, roe)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	gate := &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, Policy: roe.Policy, Allow: secgate.NewAllowlist("env")}
	if err := authorizeFootholdCarrier(gate, runner.foothold); err != nil {
		t.Fatal(err)
	}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	ctx = context.WithValue(ctx, engageRuntimeKey{}, &engageRuntime{runner: runner, policy: roe.Policy})
	response, err := newWebBroker(gate, nil).Fetch(ctx, webacquire.Request{URL: "http://" + net.JoinHostPort(ip, "8080") + "/"})
	if err != nil || !response.Complete || string(response.Body) != "web-pivot-fixture" {
		t.Fatalf("guarded web broker response=%+v err=%v", response, err)
	}
}
