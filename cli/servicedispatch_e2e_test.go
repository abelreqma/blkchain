package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
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

func startIKEFixture(t *testing.T) (string, string) {
	t.Helper()
	name := fmt.Sprintf("blkchain-ike-%d", os.Getpid())
	server := `import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 4500))
while True:
    data, address = s.recvfrom(2048)
    if len(data) < 32 or data[:4] != b"\x00\x00\x00\x00" or data[21] != 0x20:
        continue
    print("ikev2-natt-marker", flush=True)
    header = data[4:32]
    reply = header[:8] + b"\x01\x02\x03\x04\x05\x06\x07\x08" + bytes([41, 0x20, 34, 0x20]) + header[20:24] + struct.pack("!I", 36)
    notify = struct.pack("!BBHBBH", 0, 0, 8, 0, 0, 14)
    s.sendto(b"\x00\x00\x00\x00" + reply + notify, address)
`
	cmd := exec.Command("docker", "run", "-d", "--rm", "--pull", "never", "--network", "bridge", "--name", name,
		"--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--user", "1000:1000", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--memory", "128m", "--pids-limit", "64",
		defaultRunnerTag(), "/usr/bin/python3", "-u", "-c", server)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("IKE fixture: %v %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	output, err := exec.Command("docker", "inspect", name, "--format", `{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}`).Output()
	ip := strings.TrimSpace(string(output))
	if err != nil || net.ParseIP(ip) == nil {
		t.Fatalf("IKE fixture IP: %v %q", err, output)
	}
	time.Sleep(200 * time.Millisecond)
	return ip, name
}

const caddyHTTP3Image = "caddy:2.10.2@sha256:c3d7ee5d2b11f9dc54f947f68a734c84e9c9666c92c88a7f30b9cba5da182adb"

func capturedCommandOutput(t *testing.T, wrapped string) string {
	t.Helper()
	const begin = "----UNTRUSTED command BEGIN----\n"
	const end = "----UNTRUSTED command END----"
	start := strings.Index(wrapped, begin)
	if start < 0 {
		t.Fatalf("command output marker missing: %q", wrapped)
	}
	content := wrapped[start+len(begin):]
	stop := strings.Index(content, end)
	if stop < 0 {
		t.Fatalf("command output end marker missing: %q", wrapped)
	}
	return strings.TrimSpace(content[:stop])
}

func startHTTP3Fixture(t *testing.T) string {
	t.Helper()
	if output, err := exec.Command("docker", "image", "inspect", caddyHTTP3Image).CombinedOutput(); err != nil {
		t.Skipf("HTTP/3 fixture image unavailable (docker pull %s): %s", caddyHTTP3Image, output)
	}
	config := "{\n  skip_install_trust\n}\nhttp3.example.test:8443 {\n  tls internal\n  respond \"http3-fixture {http.request.proto}\"\n}\n"
	file := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(file, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("blkchain-http3-%d", os.Getpid())
	cmd := exec.Command("docker", "run", "-d", "--rm", "--pull", "never", "--network", "bridge", "--name", name,
		"--read-only", "--tmpfs", "/data:rw,noexec,nosuid,size=16m,uid=1000,gid=1000", "--tmpfs", "/config:rw,noexec,nosuid,size=16m,uid=1000,gid=1000",
		"--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--user", "1000:1000", "--memory", "128m", "--pids-limit", "64",
		"-v", file+":/etc/caddy/Caddyfile:ro", caddyHTTP3Image, "caddy", "run", "--config", "/etc/caddy/Caddyfile")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("HTTP/3 fixture: %v %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	output, err := exec.Command("docker", "inspect", name, "--format", `{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}`).Output()
	ip := strings.TrimSpace(string(output))
	if err != nil || net.ParseIP(ip) == nil {
		t.Fatalf("HTTP/3 fixture IP: %v %q", err, output)
	}
	time.Sleep(300 * time.Millisecond)
	return ip
}

func TestIKENATTPinRealRunner(t *testing.T) {
	requireRunnerImage(t)
	ip, fixture := startIKEFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	reg, closeTools, err := newChatToolRegistry(ctx, nil, ragconfig.Config{}, nil, "Probe IKEv2 NAT-T on "+ip+" UDP/4500", nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, ok := reg.Get("run_command")
	if !ok {
		t.Fatal("target command tool unavailable")
	}
	input, err := json.Marshal(runCommandArgs{Binary: "ike-scan", Args: []string{"--ikev2", "--nat-t", "--nodns", "--sport=0", "--retry=1", "--timeout=1000", ip}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := tool.Call(ctx, string(input))
	if err != nil || !strings.Contains(out, "1 returned notify") {
		t.Fatalf("IKEv2 NAT-T response missing: %q %v", out, err)
	}
	if observations := scanIKEObservations(secgate.Command{Binary: "ike-scan", Args: []string{"--ikev2", "--nat-t", "--nodns", "--sport=0", "--retry=1", "--timeout=1000", ip}}, capturedCommandOutput(t, out)); len(observations) != 1 || observations[0].state != "open" {
		t.Fatalf("real IKE response was not verified as UDP/4500 evidence: %+v", observations)
	}
	log, err := exec.Command("docker", "logs", fixture).CombinedOutput()
	if err != nil || !strings.Contains(string(log), "ikev2-natt-marker") {
		t.Fatalf("fixture did not observe non-ESP marker: %s %v", log, err)
	}
	out, err = tool.Call(ctx, string(input))
	if err != nil || !strings.Contains(out, "already completed") {
		t.Fatalf("duplicate IKE scan not suppressed: %q %v", out, err)
	}
}

func TestHTTP3PinRealRunner(t *testing.T) {
	requireRunnerImage(t)
	ip := startHTTP3Fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	reg, closeTools, err := newChatToolRegistry(ctx, nil, ragconfig.Config{}, nil, "Check https://http3.example.test:8443/ through "+ip, nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, ok := reg.Get("run_command")
	if !ok {
		t.Fatal("target command tool unavailable")
	}
	input, err := json.Marshal(runCommandArgs{Binary: "curl", Args: []string{
		"-q", "--silent", "--show-error", "--include", "--http3-only", "--insecure", "--noproxy", "*", "--connect-timeout", "3", "--max-time", "10",
		"--resolve", "http3.example.test:8443:" + ip, "https://http3.example.test:8443/",
	}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := tool.Call(ctx, string(input))
	if err != nil || !strings.Contains(out, "http3-fixture HTTP/3.0") {
		t.Fatalf("HTTP/3 response missing through worker: %q %v", out, err)
	}
	if raw := capturedCommandOutput(t, out); !strings.HasPrefix(raw, "HTTP/3 ") || !sourcePortHTTPResponse(raw) {
		t.Fatalf("real HTTP/3 response was not verifiable: %q", raw)
	}
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
	baseline, err := json.Marshal(runCommandArgs{Binary: "nmap", Args: []string{"-sT", "-Pn", "-n", "-p", "8080", ip}})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := tool.Call(ctx, string(baseline)); err != nil || !strings.Contains(out, "Nmap done:") {
		t.Fatalf("firewall baseline failed: %q %v", out, err)
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
