package main

import (
	"blkchain/cli/internal/secgate"
	"context"
	"errors"
	"os"
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
