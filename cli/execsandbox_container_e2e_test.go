package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/secgate"
)

const dockerHTTPFixture = `from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = sys.argv[1].encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
`

func startDockerHTTPFixture(t *testing.T, suffix, body string) (string, string) {
	t.Helper()
	name := fmt.Sprintf("blkchain-egress-%d-%s", os.Getpid(), suffix)
	cmd := exec.Command("docker", "run", "-d", "--rm", "--pull", "never", "--network", "bridge", "--name", name,
		"--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--user", "1000:1000", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--memory", "128m", "--pids-limit", "64",
		defaultRunnerTag(), "/usr/bin/python3", "-u", "-c", dockerHTTPFixture, body)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture %s: %v %s", suffix, err, output)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	inspect := exec.Command("docker", "inspect", name, "--format", `{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}`)
	output, err := inspect.Output()
	ip := strings.TrimSpace(string(output))
	if err != nil || net.ParseIP(ip) == nil {
		t.Fatalf("fixture IP %s: %v %q", suffix, err, output)
	}
	time.Sleep(200 * time.Millisecond)
	return ip, name
}

func TestDockerExecutorScopesEgress(t *testing.T) {
	if os.Getenv("BLKCHAIN_ENGAGE_DOCKER_E2E") != "1" {
		t.Skip("requires the pinned local Docker runner")
	}
	allowed, _ := startDockerHTTPFixture(t, "allowed", "allowed-fixture")
	blocked, _ := startDockerHTTPFixture(t, "blocked", "blocked-fixture")
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := dockerReservedIPs(context.Background(), dockerPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range reserved {
		if ip.To4() == nil {
			continue
		}
		if _, _, err := newContainerCommand(context.Background(), "curl", []string{"http://" + ip.String() + "/"}, privateScratchDir(t), executorEgress{IPs: []string{ip.String()}}); err == nil {
			t.Fatalf("Docker host gateway %s accepted", ip)
		}
	}
	scope, err := secgate.ParseScope(strings.NewReader(allowed + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := withExecutorScope(context.Background(), scope)
	scratch := privateScratchDir(t)
	input := scratch + "/input.txt"
	if err := os.WriteFile(input, []byte("input-marker"), 0600); err != nil {
		t.Fatal(err)
	}
	inputCmd, inputCleanup, err := newContainerCommand(ctx, "/bin/cat", []string{input}, scratch, executorEgress{IPs: []string{allowed}})
	if err != nil {
		t.Fatal(err)
	}
	inputCmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	inputOutput, inputErr := inputCmd.CombinedOutput()
	if err := inputCleanup(); err != nil {
		t.Fatal(err)
	}
	if inputErr != nil || string(inputOutput) != "input-marker" {
		t.Fatalf("read-only scratch input: output=%q err=%v", inputOutput, inputErr)
	}
	result := realExec(ctx, "curl", []string{"-fsS", "--max-time", "3", "http://" + allowed + ":8080/"}, scratch, 4096, 10*time.Second)
	if result.Err != nil || !strings.Contains(result.Output, "allowed-fixture") {
		t.Fatalf("allowed target: output=%q err=%v", result.Output, result.Err)
	}
	cmd, cleanup, err := newContainerCommand(context.Background(), "curl", []string{"-fsS", "--connect-timeout", "1", "--max-time", "2", "http://" + blocked + ":8080/"}, privateScratchDir(t), executorEgress{IPs: []string{allowed}})
	if err != nil {
		t.Fatal(err)
	}
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	output, err := cmd.CombinedOutput()
	if cleanupErr := cleanup(); cleanupErr != nil {
		t.Fatal(cleanupErr)
	}
	if err == nil || !strings.Contains(string(output), "timed out") {
		t.Fatalf("blocked target: output=%q err=%v", output, err)
	}
	quotaScratch := privateScratchDir(t)
	large := quotaScratch + "/large"
	quotaCmd, quotaCleanup, err := newContainerCommand(context.Background(), "/bin/dd", []string{"if=/dev/zero", "of=" + large, "bs=1M", "count=65"}, quotaScratch, executorEgress{IPs: []string{allowed}})
	if err != nil {
		t.Fatal(err)
	}
	quotaCmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	quotaOutput, quotaErr := quotaCmd.CombinedOutput()
	if err := quotaCleanup(); err != nil {
		t.Fatal(err)
	}
	if quotaErr == nil || !strings.Contains(string(quotaOutput), "No space left on device") {
		t.Fatalf("scratch quota: output=%q err=%v", quotaOutput, quotaErr)
	}
	if _, err := os.Stat(large); !os.IsNotExist(err) {
		t.Fatalf("container output reached host scratch: %v", err)
	}
	inputScratch := privateScratchDir(t)
	oversized, err := os.Create(inputScratch + "/oversized")
	if err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 1<<20)
	for i := range block {
		block[i] = 1
	}
	for i := 0; i < 65; i++ {
		if _, err := oversized.Write(block); err != nil {
			oversized.Close()
			t.Fatal(err)
		}
	}
	if err := oversized.Close(); err != nil {
		t.Fatal(err)
	}
	inputCmd, inputCleanup, err = newContainerCommand(context.Background(), "/bin/echo", []string{"should-not-run"}, inputScratch, executorEgress{IPs: []string{allowed}})
	if err != nil {
		t.Fatal(err)
	}
	inputCmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	inputOutput, inputErr = inputCmd.CombinedOutput()
	if err := inputCleanup(); err != nil {
		t.Fatal(err)
	}
	if inputErr == nil || strings.Contains(string(inputOutput), "should-not-run") {
		t.Fatalf("oversized staged input ran the tool: output=%q err=%v", inputOutput, inputErr)
	}
	cancelCtx, cancel := context.WithCancel(context.Background())
	longCmd, cleanupLong, err := newContainerCommand(cancelCtx, "sleep", []string{"30"}, privateScratchDir(t), executorEgress{IPs: []string{allowed}})
	if err != nil {
		t.Fatal(err)
	}
	longCmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	if err := longCmd.Start(); err != nil {
		t.Fatal(err)
	}
	name := ""
	for i, arg := range longCmd.Args {
		if arg == "--name" && i+1 < len(longCmd.Args) {
			name = longCmd.Args[i+1]
			break
		}
	}
	if name == "" {
		t.Fatal("executor container has no name for cancellation cleanup")
	}
	deadline := time.Now().Add(5 * time.Second)
	running := false
	for time.Now().Before(deadline) {
		check := exec.Command("docker", "inspect", name, "--format", `{{.State.Running}}`)
		state, err := check.Output()
		if err == nil && strings.TrimSpace(string(state)) == "true" {
			running = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !running {
		cancel()
		_ = longCmd.Wait()
		_ = cleanupLong()
		t.Fatal("executor container did not start before cancellation")
	}
	cancel()
	_ = longCmd.Wait()
	if err := cleanupLong(); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.Command("docker", "inspect", name).Output(); err == nil {
		t.Fatal("canceled executor container is still present")
	}
}
