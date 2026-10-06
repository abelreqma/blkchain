package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// toolcatalog_e2e_test.go runs every catalog tool inside the pinned runner
// image, in the same shape the workers use. It is the check that catches a
// packaging defect no unit test can see: an installed binary whose
// dependencies are incomplete still fails at startup, which is how Alpine's
// dnsrecon was found to be unusable.
//
// These tests shell out through /bin/sh deliberately. The harness is not a
// gated command path, so the shell-free argv rule does not apply to it, and a
// bounded `timeout` inside the container is the only way to probe a tool that
// blocks once it opens a capture socket.

const (
	generalWorkerUser = "1000:1000"
	rawWorkerUser     = "0:0"
)

func requireRunnerImage(t *testing.T) string {
	t.Helper()
	if os.Getenv("BLKCHAIN_ENGAGE_DOCKER_E2E") != "1" {
		t.Skip("requires the pinned local Docker runner")
	}
	image := defaultRunnerTag()
	if out, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", image).CombinedOutput(); err != nil {
		t.Skipf("runner image %s unavailable (run blk engage setup): %s", image, out)
	}
	return image
}

// workerShell runs script with /bin/sh inside a container shaped like a worker
// and returns its combined output. network is "none" for a tool that needs no
// interface and "bridge" for one that initializes a device. extra carries any
// additional docker flags, such as the raw worker's capability.
func workerShell(t *testing.T, image, user, network string, extra []string, script string) string {
	t.Helper()
	args := []string{
		"run", "--rm", "--pull", "never", "--network", network,
		"--read-only", "--tmpfs", "/work:rw,nosuid,nodev,size=16m,uid=1000,gid=1000",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=16m",
		"--user", user, "--cap-drop", "ALL",
		"--memory", "256m", "--pids-limit", "64",
		"--entrypoint", "/bin/sh",
	}
	args = append(args, extra...)
	args = append(args, image, "-c", script)
	// Exit status is never the signal: masscan --version, nbtscan -v and getcap
	// all exit non-zero while working, and a bounded probe is killed on purpose.
	out, _ := exec.Command("docker", args...).CombinedOutput()
	return string(out)
}

// TestCatalogToolsRunInTheImage asserts every catalog tool the image ships is
// present and executes. A nil Probe marks a tool that is deliberately not
// shipped; an empty ProbeWant marks one with no stable output, so only its
// presence on PATH is asserted.
func TestCatalogToolsRunInTheImage(t *testing.T) {
	image := requireRunnerImage(t)
	for _, tl := range toolCatalog {
		if tl.Probe == nil {
			continue
		}
		t.Run(tl.Binary, func(t *testing.T) {
			if tl.ProbeWant == "" {
				out := workerShell(t, image, generalWorkerUser, "none", nil, "command -v "+tl.Binary)
				if strings.TrimSpace(out) == "" {
					t.Fatalf("%s is not on PATH in the runner image", tl.Binary)
				}
				return
			}
			script := "timeout 20 " + shellQuoteArgv(append([]string{tl.Binary}, tl.Probe...)) + " 2>&1"
			out := workerShell(t, image, generalWorkerUser, "none", nil, script)
			if !strings.Contains(out, tl.ProbeWant) {
				t.Fatalf("%s %v output does not contain %q: %s",
					tl.Binary, tl.Probe, tl.ProbeWant, terminalSafe(out))
			}
		})
	}
}

// TestUnavailableToolsAreAbsentFromTheImage asserts a tool recorded as
// unavailable really is absent, so the recorded reason cannot go stale while a
// binary quietly reappears in the lock.
func TestUnavailableToolsAreAbsentFromTheImage(t *testing.T) {
	image := requireRunnerImage(t)
	for binary := range unavailableTools {
		t.Run(binary, func(t *testing.T) {
			out := workerShell(t, image, generalWorkerUser, "none", nil, "command -v "+binary+" || true")
			if strings.TrimSpace(out) != "" {
				t.Fatalf("%s is recorded as unavailable but resolves to %s", binary, strings.TrimSpace(out))
			}
		})
	}
	// A discouraged tool is the opposite case: present, but no persona may name
	// it. If one ever disappears from the image it belongs in unavailableTools
	// instead, so the recorded reason stays true.
	for binary := range discouragedTools {
		t.Run("discouraged/"+binary, func(t *testing.T) {
			out := workerShell(t, image, generalWorkerUser, "none", nil, "command -v "+binary+" || true")
			if strings.TrimSpace(out) == "" {
				t.Fatalf("%s is recorded as discouraged but is absent; move it to unavailableTools", binary)
			}
		})
	}
}

// TestImageCarriesNoPrivilegeEscalationPath asserts the build's setuid and
// capability strip held. The expanded package set ships ksu, mount.nfs and
// unix_chkpwd, none of which the sandbox needs, and the raw worker runs as
// root, so a lingering setuid binary would matter.
func TestImageCarriesNoPrivilegeEscalationPath(t *testing.T) {
	image := requireRunnerImage(t)
	out := workerShell(t, image, rawWorkerUser, "none", nil,
		"find / -xdev -type f -perm /6000 2>/dev/null; getcap -r / 2>/dev/null")
	if strings.TrimSpace(out) != "" {
		t.Fatalf("image carries setuid, setgid, or capability files: %s", terminalSafe(out))
	}
}

// TestRawSocketToolsNeedTheRawWorker asserts the measurement the raw-socket
// worker exists for: a raw tool fails in the general unprivileged worker and
// works in the raw worker. Without it a persona could name masscan or tcpdump
// and always get a permission error.
func TestRawSocketToolsNeedTheRawWorker(t *testing.T) {
	image := requireRunnerImage(t)
	cases := []struct {
		binary  string
		script  string
		working string
		denied  string
	}{
		{
			binary:  "masscan",
			script:  "timeout 20 masscan -p80 --rate 100 --wait 0 127.0.0.1 2>&1",
			working: "Initiating SYN Stealth Scan",
			denied:  "permission denied",
		},
		{
			binary:  "tcpdump",
			script:  "timeout 5 tcpdump -c 1 -i lo -w /dev/null 2>&1",
			working: "listening on lo",
			denied:  "CAP_NET_RAW may be required",
		},
	}
	for _, c := range cases {
		t.Run(c.binary, func(t *testing.T) {
			if !rawSocketCommand(c.binary, nil) {
				t.Fatalf("%s should always route to the raw-socket worker", c.binary)
			}
			general := workerShell(t, image, generalWorkerUser, "bridge", nil, c.script)
			if !strings.Contains(general, c.denied) {
				t.Fatalf("%s in the general worker should have been denied the capability: %s",
					c.binary, terminalSafe(general))
			}
			raw := workerShell(t, image, rawWorkerUser, "bridge", []string{"--cap-add", "NET_RAW"}, c.script)
			if !strings.Contains(raw, c.working) {
				t.Fatalf("%s did not work in the raw-socket worker: %s", c.binary, terminalSafe(raw))
			}
		})
	}
}

// TestRunnerRoutesRawScanToTheRawWorker is the whole-chain proof: a real
// engageRunner, a real guard firewall, and an nmap SYN scan of an in-scope
// fixture. The scan can only succeed in the privileged worker, and the general
// worker must still be the one serving a connect scan.
func TestRunnerRoutesRawScanToTheRawWorker(t *testing.T) {
	image := requireRunnerImage(t)
	_ = image
	ip, _ := startDockerHTTPFixture(t, "rawscan", "raw-fixture")
	roe, err := ParseRoE(strings.NewReader("# Rules of Engagement\n\n## Summary\nraw-socket routing test\n\n## Targets\n" +
		ip + "\n\n## In Scope\n" + ip + "\n\n## Rate\n100/s\n"))
	if err != nil {
		t.Fatalf("parse RoE: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	runner, err := newEngageRunner(ctx, roe)
	if err != nil {
		t.Skipf("isolated runner unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := runner.Close(); err != nil {
			t.Errorf("runner cleanup: %v", err)
		}
	})

	syn := []pipelineStage{{Binary: "nmap", Args: []string{"-sS", "-Pn", "-n", "-p", "8080", ip}}}
	if !pipelineNeedsRawSocket(syn) {
		t.Fatal("a SYN scan must route to the raw-socket worker")
	}
	res, _ := runner.Run(ctx, syn, "rawtask", 1<<20, 2*time.Minute)
	if !strings.Contains(res.Output, "8080/tcp open") {
		t.Fatalf("SYN scan did not reach the fixture: %v %s", res.Err, terminalSafe(res.Output))
	}
	if len(runner.rawWorkers) != 1 {
		t.Fatalf("SYN scan did not create a raw worker: %+v", runner.rawWorkers)
	}
	if len(runner.workers) != 0 {
		t.Fatalf("SYN scan should not have created a general worker: %+v", runner.workers)
	}

	connect := []pipelineStage{{Binary: "nmap", Args: []string{"-sT", "-Pn", "-n", "-p", "8080", ip}}}
	if pipelineNeedsRawSocket(connect) {
		t.Fatal("a connect scan must stay in the general worker")
	}
	res, _ = runner.Run(ctx, connect, "generaltask", 1<<20, 2*time.Minute)
	if !strings.Contains(res.Output, "8080/tcp open") {
		t.Fatalf("connect scan did not reach the fixture: %v %s", res.Err, terminalSafe(res.Output))
	}
	if len(runner.workers) != 1 {
		t.Fatalf("connect scan did not create a general worker: %+v", runner.workers)
	}
}

// TestFootholdCarrierIsPresentButUnreachable asserts both halves of the ssh
// carrier's position in the image: the binary exists and runs, so an
// operator-declared ssh foothold works, and it is absent from the catalog and
// from the external allowlist, so the model cannot invoke ssh as a command and
// reach its proxy, port-forwarding, and local-command options.
func TestFootholdCarrierIsPresentButUnreachable(t *testing.T) {
	image := requireRunnerImage(t)
	out := workerShell(t, image, generalWorkerUser, "none", nil, "command -v ssh && ssh -V 2>&1")
	if !strings.Contains(out, "/usr/bin/ssh") {
		t.Errorf("ssh is not installed in the image: %s", out)
	}
	if !strings.Contains(out, "OpenSSH") {
		t.Errorf("ssh does not report a version: %s", out)
	}
	if _, ok := toolFor("ssh"); ok {
		t.Error("ssh is in the tool catalog, which would make it a reachable command")
	}
	for _, bin := range externalEngageAllowlist() {
		if strings.EqualFold(bin, "ssh") {
			t.Error("ssh is in the external allowlist, which would make it a reachable command")
		}
	}
}

// TestFootholdCarrierProvisionsAndConnects is the whole-chain proof for the
// pivot's execution half: a real engageRunner, a real guard firewall, a real
// worker, and a real ssh carrier.
//
// It asserts the four things this repository owns. The declared key reaches the
// worker as a 0600 file owned by the worker rather than by the operator; the
// carrier starts as uid 1000, which needs the image's passwd entry; the guard
// permits the foothold address, which needs the declared host pinned into the
// accept list; and ssh reaches TCP connect, so the argv, the options, and the
// identity file are all usable. The fixture listens on 8080 and not on 22, so
// the connection is refused immediately and the test stays deterministic.
//
// What this does not cover is the remote half: a successful session against a
// live sshd, which depends on an operator's own foothold. Everything up to the
// moment the foothold would answer is exercised here.
func TestFootholdCarrierProvisionsAndConnects(t *testing.T) {
	requireRunnerImage(t)
	ip, _ := startDockerHTTPFixture(t, "foothold", "foothold-fixture")

	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "id_ed25519")
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", "blk-foothold-test", "-f", keyPath).CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen unavailable: %v %s", err, out)
	}
	roe, err := ParseRoE(strings.NewReader("# Rules of Engagement\n\n## Summary\nfoothold carrier test\n\n## Targets\n" +
		ip + "\n\n## In Scope\n" + ip + "\nlocal\n\n## Foothold\n" + ip + " user=root key=" + keyPath + "\n\n## Rate\n100/s\n"))
	if err != nil {
		t.Fatalf("parse RoE: %v", err)
	}
	if roe.Policy.Foothold == nil || roe.Policy.Foothold.Host != ip {
		t.Fatalf("foothold declaration = %+v", roe.Policy.Foothold)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	runner, err := newEngageRunner(ctx, roe)
	if err != nil {
		t.Skipf("isolated runner unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := runner.Close(); err != nil {
			t.Errorf("runner cleanup: %v", err)
		}
	})
	if runner.foothold == nil {
		t.Fatal("the runner built no carrier from a declared foothold")
	}

	// Creating the worker provisions the carrier secrets.
	worker, err := runner.worker(ctx, "footholdtask", false)
	if err != nil {
		t.Fatalf("worker: %v", err)
	}
	stat, err := exec.Command("docker", "exec", worker, "/usr/bin/python3", "-c",
		"import os,sys; p=sys.argv[1]; s=os.stat(p); print(oct(s.st_mode & 0o777), s.st_uid, open(p).read().splitlines()[0])",
		footholdSecretDir+"/key").CombinedOutput()
	if err != nil {
		t.Fatalf("cannot inspect the provisioned key: %v %s", err, stat)
	}
	fields := strings.Fields(string(stat))
	if len(fields) < 3 || fields[0] != "0o600" || fields[1] != "1000" {
		t.Errorf("provisioned key mode/owner = %q, want 0o600 owned by uid 1000", stat)
	}
	if !strings.Contains(string(stat), "BEGIN OPENSSH PRIVATE KEY") {
		t.Errorf("provisioned key content = %q, want the declared key", stat)
	}

	// A local-surface command is carried to the foothold. The fixture refuses
	// port 22, which proves ssh ran and reached connect rather than failing on
	// its own startup, its options, or the guard's firewall.
	carried := footholdStages(runner.foothold, []pipelineStage{{Binary: "id", Args: nil}})
	if carried[0].Binary != "ssh" {
		t.Fatalf("carried stage binary = %q, want ssh", carried[0].Binary)
	}
	res, _ := runner.Run(ctx, carried, "footholdtask", 1<<20, time.Minute)
	out := terminalSafe(res.Output)
	// Only ssh's own startup failures are rejections here. An authentication
	// failure would mean the carrier reached a server, which this fixture is not.
	for _, reject := range []string{"No user exists", "usage:", "Bad configuration option", "no such identity"} {
		if strings.Contains(out, reject) {
			t.Fatalf("carrier failed before connecting: %s", out)
		}
	}
	if !strings.Contains(out, "Connection refused") && !strings.Contains(out, "Connection closed") {
		t.Fatalf("carrier did not reach TCP connect against the fixture: %q", out)
	}
}
