package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/ragconfig"
)

func startSourcePortProtectedFixture(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("blkchain-source-port-%d", os.Getpid())
	cmd := exec.Command("docker", "run", "-d", "--rm", "--pull", "never", "--network", "bridge", "--name", name,
		"--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--user", "0:0", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
		"--security-opt", "no-new-privileges", "--memory", "128m", "--pids-limit", "64", defaultRunnerTag(),
		"/bin/sh", "-c", `iptables -A INPUT -p tcp --dport 8080 ! --sport 53 -j DROP; exec /usr/bin/python3 -u -c "$1" "$2"`,
		"source-port-fixture", dockerHTTPFixture, "source-port-protected")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("source-port fixture: %v %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	inspect := exec.Command("docker", "inspect", name, "--format", `{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}`)
	output, err := inspect.Output()
	ip := strings.TrimSpace(string(output))
	if err != nil || net.ParseIP(ip) == nil {
		t.Fatalf("source-port fixture IP: %v %q", err, output)
	}
	time.Sleep(200 * time.Millisecond)
	return ip
}

func startUDPEchoFixture(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("blkchain-udp-probe-%d", os.Getpid())
	server := `import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 4500))
while True:
    data, address = s.recvfrom(2048)
    if data == bytes.fromhex("00000000aabb"):
        s.sendto(data, address)
`
	cmd := exec.Command("docker", "run", "-d", "--rm", "--pull", "never", "--network", "bridge", "--name", name,
		"--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--user", "1000:1000", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--memory", "128m", "--pids-limit", "64",
		defaultRunnerTag(), "/usr/bin/python3", "-u", "-c", server)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("UDP fixture: %v %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	inspect := exec.Command("docker", "inspect", name, "--format", `{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}`)
	output, err := inspect.Output()
	ip := strings.TrimSpace(string(output))
	if err != nil || net.ParseIP(ip) == nil {
		t.Fatalf("UDP fixture IP: %v %q", err, output)
	}
	time.Sleep(200 * time.Millisecond)
	return ip
}

func TestServiceDispatchRealRunner(t *testing.T) {
	requireRunnerImage(t)
	ip, _ := startDockerHTTPFixture(t, "service-dispatch", "dispatch-fixture")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	reg, closeTools, err := newChatToolRegistry(ctx, nil, ragconfig.Config{}, nil, "Inspect http://"+ip+":8080/ and http://dispatch.example.test:8080/ through "+ip, nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, ok := reg.Get("run_command")
	if !ok {
		t.Fatal("target command tool unavailable")
	}
	args, err := json.Marshal(runCommandArgs{Binary: "curl", Args: []string{"-fsS", "--max-time", "5", "http://" + ip + ":8080/"}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := tool.Call(ctx, string(args))
	if err != nil || !strings.Contains(out, "dispatch-fixture") {
		t.Fatalf("observed port did not unlock the real worker request: %q %v", out, err)
	}
	connect, err := json.Marshal(runCommandArgs{Binary: "nping", Args: []string{"--tcp-connect", "--source-port", "53", "-c", "1", "--rate", "1", "-p", "8080", ip}})
	if err != nil {
		t.Fatal(err)
	}
	out, err = tool.Call(ctx, string(connect))
	if err != nil || !strings.Contains(out, "Successful connections: 1") {
		t.Fatalf("source-port connect did not run in the worker: %q %v", out, err)
	}
	raw, err := json.Marshal(runCommandArgs{Binary: "nping", Args: []string{"--tcp", "--flags", "syn", "-c", "1", "--rate", "1", "-p", "8080", ip}})
	if err != nil {
		t.Fatal(err)
	}
	out, err = tool.Call(ctx, string(raw))
	if err != nil || !strings.Contains(out, "Raw packets sent: 1") {
		t.Fatalf("raw packet probe did not run in the worker: %q %v", out, err)
	}
	resolved, err := json.Marshal(runCommandArgs{Binary: "curl", Args: []string{"--resolve", "dispatch.example.test:8080:" + ip, "-fsS", "--max-time", "5", "http://dispatch.example.test:8080/"}})
	if err != nil {
		t.Fatal(err)
	}
	out, err = tool.Call(ctx, string(resolved))
	if err != nil || !strings.Contains(out, "dispatch-fixture") {
		t.Fatalf("named virtual host did not reach the observed address: %q %v", out, err)
	}
	closed, err := json.Marshal(runCommandArgs{Binary: "curl", Args: []string{"-fsS", "--max-time", "5", "http://" + ip + ":8081/"}})
	if err != nil {
		t.Fatal(err)
	}
	out, err = tool.Call(ctx, string(closed))
	if err != nil || !strings.Contains(out, "service dispatch") {
		t.Fatalf("closed port was not stopped at dispatch: %q %v", out, err)
	}
}

func TestFirewallProbeModesRealRunner(t *testing.T) {
	requireRunnerImage(t)
	ip, _ := startDockerHTTPFixture(t, "firewall-probes", "probe-fixture")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	reg, closeTools, err := newChatToolRegistry(ctx, nil, ragconfig.Config{}, nil, "Check firewall behavior on "+ip, nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, ok := reg.Get("run_command")
	if !ok {
		t.Fatal("target command tool unavailable")
	}
	for _, args := range [][]string{
		{"-sn", "-n", "-PE", "-PS8080", "-PA8080", "-PU53", ip},
		{"-sA", "-Pn", "-n", "-p", "8080", ip},
		{"-sF", "-Pn", "-n", "-p", "8080", ip},
		{"-sN", "-Pn", "-n", "-p", "8080", ip},
		{"-sX", "-Pn", "-n", "-p", "8080", ip},
		{"-sS", "-Pn", "-n", "--source-port", "53", "-p", "8080", ip},
		{"-sS", "-Pn", "-n", "-f", "-p", "8080", ip},
		{"-sY", "-Pn", "-n", "-p", "8080", ip},
		{"-sZ", "-Pn", "-n", "-p", "8080", ip},
		{"-sO", "-Pn", "-n", "-p", "50,51", ip},
	} {
		input, err := json.Marshal(runCommandArgs{Binary: "nmap", Args: args})
		if err != nil {
			t.Fatal(err)
		}
		out, err := tool.Call(ctx, string(input))
		if err != nil || !strings.Contains(out, "Nmap done:") {
			t.Fatalf("firewall probe %v failed: %q %v", args, out, err)
		}
	}
}

func TestSourcePortHTTPValidationRealRunner(t *testing.T) {
	requireRunnerImage(t)
	ip, _ := startDockerHTTPFixture(t, "source-port", "source-port-fixture")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	reg, closeTools, err := newChatToolRegistry(ctx, nil, ragconfig.Config{}, nil, "Check http://"+ip+":8080/ with source port 53", nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, ok := reg.Get("run_command")
	if !ok {
		t.Fatal("target command tool unavailable")
	}
	args, err := json.Marshal(runCommandArgs{Binary: "curl", Args: []string{
		"-q", "--silent", "--show-error", "--include", "--noproxy", "*",
		"--connect-timeout", "3", "--max-time", "8", "--local-port", "53",
		"http://" + ip + ":8080/",
	}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := tool.Call(ctx, string(args))
	if err != nil || !strings.Contains(out, "HTTP/") || !strings.Contains(out, "source-port-fixture") {
		t.Fatalf("source-port validation did not reach the application: %q %v", out, err)
	}
}

func TestSourcePortRuleDifferentialRealRunner(t *testing.T) {
	requireRunnerImage(t)
	ip := startSourcePortProtectedFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	reg, closeTools, err := newChatToolRegistry(ctx, nil, ragconfig.Config{}, nil, "Compare ordinary and source-port access to http://"+ip+":8080/", nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, ok := reg.Get("run_command")
	if !ok {
		t.Fatal("target command tool unavailable")
	}
	baseline, err := json.Marshal(runCommandArgs{Binary: "nmap", Args: []string{"-sT", "-Pn", "-n", "-p", "8080", ip}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := tool.Call(ctx, string(baseline))
	if err != nil || !strings.Contains(out, "8080/tcp filtered") {
		t.Fatalf("ordinary scan did not observe the filter: %q %v", out, err)
	}
	variant, err := json.Marshal(runCommandArgs{Binary: "nmap", Args: []string{"-sS", "-Pn", "-n", "--source-port", "53", "-p", "8080", ip}})
	if err != nil {
		t.Fatal(err)
	}
	out, err = tool.Call(ctx, string(variant))
	if err != nil || !strings.Contains(out, "8080/tcp open") {
		t.Fatalf("source-port scan did not reach the listener: %q %v", out, err)
	}
	ordinary, err := json.Marshal(runCommandArgs{Binary: "curl", Args: []string{"-q", "--silent", "--max-time", "3", "http://" + ip + ":8080/"}})
	if err != nil {
		t.Fatal(err)
	}
	out, err = tool.Call(ctx, string(ordinary))
	if err != nil || !strings.Contains(out, "service dispatch") {
		t.Fatalf("ordinary path was not denied: %q %v", out, err)
	}
	bound, err := json.Marshal(runCommandArgs{Binary: "curl", Args: []string{
		"-q", "--silent", "--show-error", "--include", "--noproxy", "*",
		"--connect-timeout", "3", "--max-time", "8", "--local-port", "53",
		"http://" + ip + ":8080/",
	}})
	if err != nil {
		t.Fatal(err)
	}
	out, err = tool.Call(ctx, string(bound))
	if err != nil || !strings.Contains(out, "source-port-protected") {
		t.Fatalf("source-port path did not reach the application: %q %v", out, err)
	}
}

func TestUDPPayloadRunsAfterDiscoveryRealRunner(t *testing.T) {
	requireRunnerImage(t)
	ip := startUDPEchoFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	reg, closeTools, err := newChatToolRegistry(ctx, nil, ragconfig.Config{}, nil, "Check UDP/4500 on "+ip, nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, ok := reg.Get("run_command")
	if !ok {
		t.Fatal("target command tool unavailable")
	}
	wrong, err := json.Marshal(runCommandArgs{Binary: "nping", Args: []string{"--udp", "--data", "0x00000000aabc", "-c", "1", "--rate", "1", "-p", "4500", ip}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := tool.Call(ctx, string(wrong))
	if err != nil || !strings.Contains(out, "Rcvd: 0") {
		t.Fatalf("UDP control did not stay silent: %q %v", out, err)
	}
	args, err := json.Marshal(runCommandArgs{Binary: "nping", Args: []string{"--udp", "--data", "0x00000000aabb", "-c", "1", "--rate", "1", "-p", "4500", ip}})
	if err != nil {
		t.Fatal(err)
	}
	out, err = tool.Call(ctx, string(args))
	if err != nil || !strings.Contains(out, "Raw packets sent: 1") || strings.Contains(out, "Rcvd: 0") || strings.Contains(out, "service dispatch") {
		t.Fatalf("UDP payload did not follow observed port discovery: %q %v", out, err)
	}
}
