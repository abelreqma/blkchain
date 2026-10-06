package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
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

// shellQuote renders argv as a single-quoted sh word list, so no catalog probe
// argument can be reinterpreted by the harness shell.
func shellQuote(argv []string) string {
	quoted := make([]string, 0, len(argv))
	for _, a := range argv {
		quoted = append(quoted, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
	}
	return strings.Join(quoted, " ")
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
			script := "timeout 20 " + shellQuote(append([]string{tl.Binary}, tl.Probe...)) + " 2>&1"
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
	for binary, reason := range unavailableTools {
		if strings.Contains(reason, "busybox") {
			continue // present, but the catalog records why no persona uses it
		}
		t.Run(binary, func(t *testing.T) {
			out := workerShell(t, image, generalWorkerUser, "none", nil, "command -v "+binary+" || true")
			if strings.TrimSpace(out) != "" {
				t.Fatalf("%s is recorded as unavailable but resolves to %s", binary, strings.TrimSpace(out))
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
