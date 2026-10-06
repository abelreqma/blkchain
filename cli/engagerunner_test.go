package main

import (
	"blkchain/cli/internal/secgate"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestEngageRunnerCleanupFailureIsReportedAndRetried(t *testing.T) {
	r := &engageRunner{guard: "guard", workers: map[string]string{"task": "worker"}}
	r.remove = func(_ context.Context, id string) error {
		if id == "worker" {
			return errors.New("daemon refused removal")
		}
		return nil
	}
	if err := r.Release("task"); err == nil || !strings.Contains(err.Error(), "daemon refused removal") {
		t.Fatalf("worker cleanup failure hidden: %v", err)
	}
	if r.workers["task"] != "worker" {
		t.Fatal("failed worker was forgotten before retry")
	}
	if err := r.Close(); err == nil || !strings.Contains(err.Error(), "remove worker worker") {
		t.Fatalf("runner cleanup failure hidden: %v", err)
	}
	r.remove = func(context.Context, string) error { return nil }
	if err := r.Close(); err != nil || len(r.workers) != 0 || r.guard != "" {
		t.Fatalf("runner retry did not clean up: %v %+v", err, r)
	}
}

func TestEngageWorkerHasNoHostAccess(t *testing.T) {
	args := engageWorkerArgs("worker", "guard", "sha256:"+strings.Repeat("a", 64), nil)
	s := strings.Join(args, " ")
	for _, want := range []string{"--read-only", "--cap-drop ALL", "--security-opt no-new-privileges", "--user 1000:1000", "--network container:guard", "--pids-limit", "--memory", "--tmpfs"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in %s", want, s)
		}
	}
	for _, bad := range []string{"--privileged", "--volume", "--mount", "--cap-add", "--network host"} {
		if strings.Contains(s, bad) {
			t.Fatalf("host access %q in %s", bad, s)
		}
	}
}

func TestEngageFirewallDenialsPrecedePermissions(t *testing.T) {
	rules, err := engageFirewall([]string{"10.20.0.0/24"}, []string{"10.20.0.5"}, []string{"10.20.0.1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"10.20.0.5", "10.20.0.1", "127.0.0.0/8", "169.254.0.0/16"} {
		if strings.Index(rules, "-d "+bad+" -j DROP") < 0 || strings.Index(rules, "-d "+bad+" -j DROP") > strings.Index(rules, "-d 10.20.0.0/24 -j ACCEPT") {
			t.Fatalf("denial %s does not precede allowance: %s", bad, rules)
		}
	}
	if !strings.Contains(rules, ":OUTPUT DROP") {
		t.Fatal("firewall defaults open")
	}
}

func TestRunnerCommandFirewallUsesOnlyExplicitIPScope(t *testing.T) {
	scope, err := secgate.ParseScope(strings.NewReader("example.test\n10.20.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	allowed := runnerCommandIPs(scope)
	if len(allowed) != 1 || allowed[0] != "10.20.0.0/24" {
		t.Fatalf("hostname pin broadened command firewall: %v", allowed)
	}
}

func TestEngageFirewallRejectsUnparsedInput(t *testing.T) {
	if _, err := engageFirewall([]string{"10.0.0.5\nCOMMIT"}, nil, nil, false); err == nil {
		t.Fatal("firewall accepted injected line")
	}
}

func TestEngageRunnerLiveBoundary(t *testing.T) {
	if os.Getenv("BLKCHAIN_ENGAGE_RUNNER_E2E") != "1" {
		t.Skip("requires local Docker runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := setupEngageRunner(ctx); err != nil {
		t.Fatal(err)
	}
	roe, err := ParseRoE(strings.NewReader("## In Scope\nlocal\n## Allowed Actions\nlocal\n"))
	if err != nil {
		t.Fatal(err)
	}
	runner, err := newEngageRunner(ctx, roe)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	os.Setenv("BLKCHAIN_OPERATOR_SENTINEL", "must-not-reach-worker")
	t.Cleanup(func() { os.Unsetenv("BLKCHAIN_OPERATOR_SENTINEL") })
	result, stages := runner.Run(ctx, []pipelineStage{{Binary: "python3", Args: []string{"-c", "import os; print(os.getenv('BLKCHAIN_OPERATOR_SENTINEL', 'absent')); print(os.path.exists('/Users/blkbrd')); print(os.getuid())"}}}, "boundary", 65536, 5*time.Second)
	if result.Err != nil || len(stages) != 1 || !strings.Contains(result.Output, "absent\nFalse\n1000") {
		t.Fatalf("isolation result=%+v stages=%+v", result, stages)
	}
	result, _ = runner.Run(ctx, []pipelineStage{{Binary: "python3", Args: []string{"-c", "import os; open(os.path.join(os.environ['HOME'], '.curlrc'), 'w').write('--location')"}}}, "boundary", 65536, 5*time.Second)
	if result.Err != nil {
		t.Fatalf("setup of per-action home failed: %+v", result)
	}
	result, _ = runner.Run(ctx, []pipelineStage{{Binary: "python3", Args: []string{"-c", "import os; print(os.path.exists(os.path.join(os.environ['HOME'], '.curlrc')))"}}}, "boundary", 65536, 5*time.Second)
	if result.Err != nil || !strings.Contains(result.Output, "False") {
		t.Fatalf("runner reused an action home: %+v", result)
	}
	result, _ = runner.Run(ctx, []pipelineStage{{Binary: "curl", Args: []string{"--connect-timeout", "1", "http://1.1.1.1"}}}, "boundary", 65536, 3*time.Second)
	if result.Err == nil && !result.TimedOut {
		t.Fatal("local worker reached an unauthorized destination")
	}
	result, stages = runner.Run(ctx, []pipelineStage{{Binary: "python3", Args: []string{"-u", "-c", "import time; print('partial'); time.sleep(10)"}}}, "boundary", 65536, time.Second)
	if !result.TimedOut || !strings.Contains(result.Output, "partial") || len(stages) != 1 {
		t.Fatalf("timeout lost partial output: %+v", result)
	}
}

func TestEngageRawWorkerAddsOnlyRawSocketCapability(t *testing.T) {
	image := "sha256:" + strings.Repeat("a", 64)
	raw := strings.Join(engageRawWorkerArgs("rawworker", "guard", image, nil), " ")
	// Raw sockets need a root process: Docker exposes no ambient capability and
	// no-new-privileges blocks the file-capability route, so an unprivileged
	// process keeps an empty effective set however the capability is added.
	for _, want := range []string{"--cap-add NET_RAW", "--user 0:0"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("missing %q in %s", want, raw)
		}
	}
	// Every other control is the general worker's.
	for _, want := range []string{"--read-only", "--cap-drop ALL", "--security-opt no-new-privileges", "--network container:guard", "--pids-limit", "--memory", "--tmpfs"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("missing %q in %s", want, raw)
		}
	}
	for _, bad := range []string{"--privileged", "--volume", "--mount", "--network host", "NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "CAP_SYS"} {
		if strings.Contains(raw, bad) {
			t.Fatalf("raw worker grants %q in %s", bad, raw)
		}
	}
	// The general worker keeps its unprivileged identity and gains nothing.
	general := strings.Join(engageWorkerArgs("worker", "guard", image, nil), " ")
	if strings.Contains(general, "NET_RAW") {
		t.Fatalf("general worker gained NET_RAW: %s", general)
	}
	if !strings.Contains(general, "--user 1000:1000") {
		t.Fatalf("general worker is not unprivileged: %s", general)
	}
}

func TestEngageRunnerReleasesAndClosesBothWorkerPools(t *testing.T) {
	r := &engageRunner{
		guard:      "guard",
		workers:    map[string]string{"task": "worker", "other": "worker2"},
		rawWorkers: map[string]string{"task": "rawworker", "other": "rawworker2"},
	}
	var removed []string
	r.remove = func(_ context.Context, id string) error {
		removed = append(removed, id)
		return nil
	}
	if err := r.Release("task"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if r.workers["task"] != "" || r.rawWorkers["task"] != "" {
		t.Fatalf("release left a worker behind: %+v", r)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(r.workers) != 0 || len(r.rawWorkers) != 0 || r.guard != "" {
		t.Fatalf("close left containers behind: %+v", r)
	}
	for _, want := range []string{"worker", "rawworker", "worker2", "rawworker2", "guard"} {
		if !slices.Contains(removed, want) {
			t.Fatalf("%s was never removed, removed=%v", want, removed)
		}
	}
}

func TestEngageRunnerWorkerCapSpansBothPools(t *testing.T) {
	r := &engageRunner{
		guard:      "guard",
		workers:    map[string]string{"a": "1", "b": "2", "c": "3", "d": "4"},
		rawWorkers: map[string]string{"a": "5", "b": "6", "c": "7", "d": "8"},
	}
	// The cap check precedes any docker call, so a refused worker touches no daemon.
	if _, err := r.worker(context.Background(), "new", false); err == nil || !strings.Contains(err.Error(), "cap reached") {
		t.Fatalf("general worker ignored the shared cap: %v", err)
	}
	if _, err := r.worker(context.Background(), "new", true); err == nil || !strings.Contains(err.Error(), "cap reached") {
		t.Fatalf("raw worker ignored the shared cap: %v", err)
	}
	// An existing directory still resolves without creating anything.
	if id, err := r.worker(context.Background(), "a", true); err != nil || id != "5" {
		t.Fatalf("existing raw worker not reused: %q %v", id, err)
	}
}

func TestPipelineNeedsRawSocket(t *testing.T) {
	raw := [][]pipelineStage{
		{{Binary: "masscan", Args: []string{"-p80", "192.0.2.1"}}},
		{{Binary: "nmap", Args: []string{"-sS", "-p", "80", "192.0.2.1"}}},
		// One raw stage takes the whole pipeline to the raw worker.
		{{Binary: "nmap", Args: []string{"-sU", "-p", "161", "192.0.2.1"}}, {Binary: "jq", Args: []string{"."}}},
		{{Binary: "curl", Args: []string{"http://192.0.2.1/"}}, {Binary: "tcpdump", Args: []string{"-c", "1"}}},
	}
	for _, stages := range raw {
		if !pipelineNeedsRawSocket(stages) {
			t.Errorf("%+v should need the raw-socket worker", stages)
		}
	}
	general := [][]pipelineStage{
		nil,
		{{Binary: "nmap", Args: []string{"-sT", "-p", "80", "192.0.2.1"}}},
		{{Binary: "curl", Args: []string{"http://192.0.2.1/"}}, {Binary: "jq", Args: []string{"."}}},
		{{Binary: "smbclient", Args: []string{"-L", "192.0.2.1"}}},
		{{Binary: "sh", Args: []string{"-c", "masscan -p80 192.0.2.1"}}},
	}
	for _, stages := range general {
		if pipelineNeedsRawSocket(stages) {
			t.Errorf("%+v should stay in the general unprivileged worker", stages)
		}
	}
}

// TestBothExecutionPathsUseTheBuiltImage pins the two substrates to one image.
// They drifted before: the per-command sandbox pinned a hardcoded digest that no
// build produced, so it failed with "No such image" under --pull never.
func TestBothExecutionPathsUseTheBuiltImage(t *testing.T) {
	tag := defaultRunnerTag()
	if executorRunnerImage() != tag {
		t.Fatalf("sandbox image %q is not the built image %q", executorRunnerImage(), tag)
	}
	if !strings.HasPrefix(tag, "blkchain-engage-runner:") || len(tag) != len("blkchain-engage-runner:")+64 {
		t.Fatalf("runner tag is not the content-addressed form: %q", tag)
	}
}
