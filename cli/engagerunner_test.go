package main

import (
	"blkchain/cli/internal/secgate"
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"slices"
	"strconv"
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
	args := engageWorkerArgs("worker", "guard", "sha256:"+strings.Repeat("a", 64), "", nil)
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

func TestEngageWorkerPinsHostsFromPrivateReadOnlyFile(t *testing.T) {
	dir, path, err := writeRunnerHosts([]string{"10.20.0.6 api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "10.20.0.6 api.example.test\n") {
		t.Fatalf("host pin file=%q err=%v", data, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("host pin directory mode=%v", info.Mode())
	}
	args := strings.Join(engageWorkerArgs("worker", "guard", "sha256:"+strings.Repeat("a", 64), path, nil), " ")
	if !strings.Contains(args, "--mount type=bind,src="+path+",dst=/etc/hosts,readonly") {
		t.Fatalf("worker did not mount only its generated host pins: %s", args)
	}
	if _, _, err := writeRunnerHosts([]string{""}); err == nil {
		t.Fatal("empty host pin was accepted")
	}
	runner := &engageRunner{hostsDir: dir, hostsFile: path, workers: map[string]string{}}
	if err := runner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("runner host pins remained after cleanup: %v", err)
	}
}

func TestEngageFirewallDenialsPrecedePermissions(t *testing.T) {
	rules, err := engageFirewall([]string{"10.20.0.0/24"}, []string{"10.20.0.5"}, []string{"10.20.0.1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"10.20.0.5", "10.20.0.1", "127.0.0.0/8", "169.254.0.0/16"} {
		deny := strings.Index(rules, "-d "+bad+" -j DROP")
		if deny < 0 || deny > strings.Index(rules, "-d 10.20.0.0/24 -j ACCEPT") {
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

func TestRunnerScopeDoesNotResolveWildcardPattern(t *testing.T) {
	scope, err := secgate.BuildScope(secgate.ScopeSpec{
		In:  []string{"*.example.test", "10.20.0.5", "192.0.2.0/28"},
		Out: []string{"*.blocked.example.test", "10.20.0.7"},
	})
	if err != nil {
		t.Fatal(err)
	}
	in, out, hosts, err := runnerScope(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(in, ",") != "10.20.0.5,192.0.2.0/28" || strings.Join(out, ",") != "10.20.0.7" || len(hosts) != 0 {
		t.Fatalf("runner scope in=%v out=%v hosts=%v", in, out, hosts)
	}
	if got := runnerCommandIPs(scope); strings.Join(got, ",") != "10.20.0.5,192.0.2.0/28" {
		t.Fatalf("wildcard broadened command egress: %v", got)
	}
}

func TestPlanWildcardEgressPinsOnlyActionTargets(t *testing.T) {
	scope, err := secgate.BuildScope(secgate.ScopeSpec{
		In:  []string{"*.example.test", "10.20.0.9"},
		Out: []string{"10.20.0.7", "blocked.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.PinNetwork(nil, []string{"10.20.0.1"}); err != nil {
		t.Fatal(err)
	}
	resolve := func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host == "mixed.example.test" {
			return []net.IPAddr{{IP: net.ParseIP("10.20.0.6")}, {IP: net.ParseIP("10.20.0.7")}}, nil
		}
		addresses := map[string]string{"api.example.test": "10.20.0.6", "bad.example.test": "10.20.0.7", "protected.example.test": "10.20.0.1"}
		if value := addresses[host]; value != "" {
			return []net.IPAddr{{IP: net.ParseIP(value)}}, nil
		}
		return nil, errors.New("unresolved")
	}
	stages := []pipelineStage{
		{Binary: "curl", Args: []string{"http://api.example.test:8080/"}},
		{Binary: "nmap", Args: []string{"10.20.0.9"}},
	}
	plan, err := planWildcardEgress(context.Background(), scope, stages, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Dynamic || strings.Join(plan.IPs, ",") != "10.20.0.6,10.20.0.9" || strings.Join(plan.Hosts, ",") != "10.20.0.6 api.example.test" {
		t.Fatalf("wildcard egress plan = %+v", plan)
	}
	plain, err := planWildcardEgress(context.Background(), scope, stages[1:], resolve)
	if err != nil || plain.Dynamic {
		t.Fatalf("numeric-only action became dynamic: %+v %v", plain, err)
	}
	for _, host := range []string{"bad.example.test", "protected.example.test", "mixed.example.test", "blocked.example.test", "evil-example.test"} {
		if _, err := planWildcardEgress(context.Background(), scope, []pipelineStage{{Binary: "curl", Args: []string{"http://" + host + "/"}}}, resolve); err == nil {
			t.Errorf("wildcard plan accepted %s", host)
		}
	}
}

func TestPlanWildcardEgressStopsOnCanceledContext(t *testing.T) {
	scope, err := secgate.BuildScope(secgate.ScopeSpec{In: []string{"*.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err = planWildcardEgress(ctx, scope, []pipelineStage{{Binary: "curl", Args: []string{"http://api.example.test/"}}},
		func(context.Context, string) ([]net.IPAddr, error) {
			called = true
			return []net.IPAddr{{IP: net.ParseIP("10.20.0.6")}}, nil
		})
	if !errors.Is(err, context.Canceled) || called {
		t.Fatalf("canceled action resolved a target: err=%v called=%v", err, called)
	}
}

// The egress plan authorizes a network target on the same rule the gate uses:
// one in-scope CIDR covers the whole range and nothing excluded overlaps it. A
// range has no hostname to resolve, so it never makes the plan dynamic; when
// another target does, the range is pinned into the action-scoped guard so the
// sweep can still reach it.
func TestPlanWildcardEgressAuthorizesScopedNetwork(t *testing.T) {
	scope, err := secgate.BuildScope(secgate.ScopeSpec{
		In:  []string{"10.20.0.0/16", "*.example.test"},
		Out: []string{"10.20.9.9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host == "api.example.test" {
			return []net.IPAddr{{IP: net.ParseIP("10.20.0.6")}}, nil
		}
		return nil, errors.New("unresolved")
	}
	sweep := pipelineStage{Binary: "nmap", Args: []string{"-n", "-sn", "10.20.1.0/24"}}

	plan, err := planWildcardEgress(context.Background(), scope, []pipelineStage{sweep}, resolve)
	if err != nil {
		t.Fatalf("in-scope sweep denied at the egress plan: %v", err)
	}
	if plan.Dynamic {
		t.Errorf("a range target made the plan dynamic: %+v", plan)
	}

	mixed := []pipelineStage{sweep, {Binary: "curl", Args: []string{"http://api.example.test/"}}}
	plan, err = planWildcardEgress(context.Background(), scope, mixed, resolve)
	if err != nil {
		t.Fatalf("mixed sweep and wildcard host denied: %v", err)
	}
	if !plan.Dynamic || !slices.Contains(plan.IPs, "10.20.1.0/24") || !slices.Contains(plan.IPs, "10.20.0.6") {
		t.Errorf("action-scoped plan = %+v, want the range and the resolved host pinned", plan)
	}

	for _, args := range [][]string{
		{"-n", "-sn", "10.30.0.0/24"}, // wholly outside the scope
		{"-n", "-sn", "10.20.0.0/8"},  // wider than any single in-scope entry
		{"-n", "-sn", "10.20.9.0/24"}, // overlaps an excluded host
	} {
		if _, err := planWildcardEgress(context.Background(), scope, []pipelineStage{{Binary: "nmap", Args: args}}, resolve); err == nil {
			t.Errorf("egress plan accepted the network in %v", args)
		}
	}
}

func TestWildcardRunUsesActionScopedGuardAndCleansUp(t *testing.T) {
	previous := newEngageRunnerForRun
	t.Cleanup(func() { newEngageRunnerForRun = previous })
	policy := secgate.DefaultPolicy()
	removed := map[string]bool{}
	var child *engageRunner
	newEngageRunnerForRun = func(_ context.Context, roe *RoE) (*engageRunner, error) {
		in, _ := roe.Scope.Entries()
		// The sub-runner inherits every operator cap unchanged. It receives a copy
		// rather than the same pointer for one reason: the foothold is stripped,
		// because no pivoted action reaches the dynamic path and the foothold's
		// address does not belong in this runner's deliberately narrow accept list.
		inherited := *policy
		inherited.Foothold = nil
		if strings.Join(in, ",") != "10.20.0.6" || roe.Policy == nil || !reflect.DeepEqual(*roe.Policy, inherited) {
			t.Errorf("action runner received scope=%v policy=%+v", in, roe.Policy)
		}
		child = &engageRunner{guard: "guard", workers: map[string]string{"task": "worker"}, remove: func(_ context.Context, id string) error {
			removed[id] = true
			return nil
		}}
		child.runFn = func(_ context.Context, _ []pipelineStage, _ string, _ int, _ time.Duration) (runResult, []isolatedStageResult) {
			if strings.Join(child.hosts, ",") != "10.20.0.6 api.example.test" {
				t.Errorf("worker host pin = %v", child.hosts)
			}
			return runResult{Output: "observed"}, []isolatedStageResult{{Stdout: "observed"}}
		}
		return child, nil
	}
	parent := &engageRunner{slots: make(chan struct{}, 1)}
	plan := engageEgressPlan{Dynamic: true, IPs: []string{"10.20.0.6"}, Hosts: []string{"10.20.0.6 api.example.test"}}
	result, outputs := parent.RunScoped(context.Background(), []pipelineStage{{Binary: "curl", Args: []string{"http://api.example.test/"}}}, "task", 1024, time.Second, plan, policy)
	if result.Err != nil || result.Output != "observed" || len(outputs) != 1 || !removed["worker"] || !removed["guard"] {
		t.Fatalf("scoped run result=%+v outputs=%+v removed=%v", result, outputs, removed)
	}
}

func TestWildcardRunRejectsClosedParent(t *testing.T) {
	previous := newEngageRunnerForRun
	t.Cleanup(func() { newEngageRunnerForRun = previous })
	called := false
	newEngageRunnerForRun = func(context.Context, *RoE) (*engageRunner, error) {
		called = true
		return nil, errors.New("runner should not start")
	}
	parent := &engageRunner{closed: true, slots: make(chan struct{}, 1)}
	plan := engageEgressPlan{Dynamic: true, IPs: []string{"10.20.0.6"}}
	result, _ := parent.RunScoped(context.Background(), []pipelineStage{{Binary: "curl", Args: []string{"http://api.example.test/"}}}, "task", 1024, time.Second, plan, secgate.DefaultPolicy())
	if result.Err == nil || called {
		t.Fatalf("closed runner launched an action: err=%v called=%v", result.Err, called)
	}
}

func TestWildcardRunReportsGuardCleanupFailure(t *testing.T) {
	previous := newEngageRunnerForRun
	t.Cleanup(func() { newEngageRunnerForRun = previous })
	newEngageRunnerForRun = func(context.Context, *RoE) (*engageRunner, error) {
		return &engageRunner{guard: "guard", workers: map[string]string{}, remove: func(context.Context, string) error {
			return errors.New("cleanup refused")
		}, runFn: func(context.Context, []pipelineStage, string, int, time.Duration) (runResult, []isolatedStageResult) {
			return runResult{Output: "partial"}, []isolatedStageResult{{Stdout: "partial"}}
		}}, nil
	}
	parent := &engageRunner{slots: make(chan struct{}, 1)}
	plan := engageEgressPlan{Dynamic: true, IPs: []string{"10.20.0.6"}}
	result, outputs := parent.RunScoped(context.Background(), []pipelineStage{{Binary: "curl", Args: []string{"http://api.example.test/"}}}, "task", 1024, time.Second, plan, secgate.DefaultPolicy())
	if len(outputs) != 1 || !strings.Contains(result.Output, "partial") || result.Err == nil || !strings.Contains(result.Err.Error(), "cleanup refused") {
		t.Fatalf("cleanup failure or partial output lost: result=%+v outputs=%+v", result, outputs)
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
	// The operator home is resolved here and passed as an argument, so the check
	// is against this machine's home rather than one spelling of it. A literal
	// path is absent from any container whatever the runner mounts, so it would
	// pass on every other machine while a real mount of their home leaked.
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Fatalf("cannot resolve the operator home to prove it is unreachable: %v", err)
	}
	probe := "import os, sys; print(os.getenv('BLKCHAIN_OPERATOR_SENTINEL', 'absent')); print(os.path.exists(sys.argv[1])); print(os.getuid())"
	result, stages := runner.Run(ctx, []pipelineStage{{Binary: "python3", Args: []string{"-c", probe, home}}}, "boundary", 65536, 5*time.Second)
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

func TestWildcardActionRunnerLiveBoundary(t *testing.T) {
	if os.Getenv("BLKCHAIN_ENGAGE_RUNNER_E2E") != "1" {
		t.Skip("requires the pinned local Docker runner")
	}
	allowedIP, _ := startDockerHTTPFixture(t, "wildcard-allowed", "wildcard-fixture-ok")
	blockedIP, _ := startDockerHTTPFixture(t, "wildcard-blocked", "blocked-fixture")
	roe, err := ParseRoE(strings.NewReader("## In Scope\n*.example.test\n"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	runner, err := newEngageRunner(ctx, roe)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	plan, err := planWildcardEgress(ctx, roe.Scope, []pipelineStage{{Binary: "curl", Args: []string{"http://api.example.test:8080/"}}},
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP(allowedIP)}}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	result, stages := runner.RunScoped(ctx, []pipelineStage{{Binary: "curl", Args: []string{"--max-time", "5", "http://api.example.test:8080/"}}}, "wildcard", 65536, 8*time.Second, plan, roe.Policy)
	if result.Err != nil || len(stages) != 1 || stages[0].ExitCode != 0 || !strings.Contains(result.Output, "wildcard-fixture-ok") {
		t.Fatalf("pinned wildcard command failed: result=%+v stages=%+v", result, stages)
	}
	result, stages = runner.RunScoped(ctx, []pipelineStage{{Binary: "curl", Args: []string{"--connect-timeout", "2", "--max-time", "3", "http://" + blockedIP + ":8080/"}}}, "wildcard", 65536, 5*time.Second, plan, roe.Policy)
	if len(stages) != 1 || (result.Err == nil && stages[0].ExitCode == 0) || strings.Contains(result.Output, "blocked-fixture") {
		t.Fatalf("action guard reached another IP: result=%+v stages=%+v", result, stages)
	}
}

func TestEngageRawWorkerAddsOnlyRawSocketCapability(t *testing.T) {
	image := "sha256:" + strings.Repeat("a", 64)
	raw := strings.Join(engageRawWorkerArgs("rawworker", "guard", image, "", nil), " ")
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
	general := strings.Join(engageWorkerArgs("worker", "guard", image, "", nil), " ")
	if strings.Contains(general, "NET_RAW") {
		t.Fatalf("general worker gained NET_RAW: %s", general)
	}
	if !strings.Contains(general, "--user 1000:1000") {
		t.Fatalf("general worker is not unprivileged: %s", general)
	}
}

// TestBothWorkerPoolsPinHostsReadOnly is the reconciliation between the
// host-pin file and the raw-socket pool: the pins are mounted read-only into
// both workers, so a raw command resolves scoped names the same way an
// enumeration command does and neither can rewrite the file.
func TestBothWorkerPoolsPinHostsReadOnly(t *testing.T) {
	image := "sha256:" + strings.Repeat("a", 64)
	want := "--mount type=bind,src=/tmp/pins/hosts,dst=/etc/hosts,readonly"
	for name, args := range map[string][]string{
		"general": engageWorkerArgs("worker", "guard", image, "/tmp/pins/hosts", nil),
		"raw":     engageRawWorkerArgs("rawworker", "guard", image, "/tmp/pins/hosts", nil),
	} {
		if s := strings.Join(args, " "); !strings.Contains(s, want) {
			t.Errorf("%s worker does not mount the host pins read-only: %s", name, s)
		}
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

// The container bound follows the policy's own parallelism. A task in flight
// can hold one general worker and one raw-socket worker, so each parallel slot
// authorizes two containers; a bound below that refuses a worker the sealed
// policy already allowed and stalls the rest of the engagement.
func TestEngageRunnerWorkerCapFollowsParallelism(t *testing.T) {
	for _, tc := range []struct{ parallel, want int }{{1, 2}, {4, 8}, {8, 16}} {
		r := &engageRunner{slots: make(chan struct{}, tc.parallel)}
		if got := r.workerCap(); got != tc.want {
			t.Errorf("parallel %d: worker cap = %d, want %d", tc.parallel, got, tc.want)
		}
	}
	if got := (&engageRunner{}).workerCap(); got != 2 {
		t.Errorf("worker cap without slots = %d, want 2", got)
	}

	// The bound is still enforced: the check precedes any docker call, so a
	// refused worker touches no daemon.
	r := &engageRunner{guard: "guard", slots: make(chan struct{}, 2), workers: map[string]string{}, rawWorkers: map[string]string{}}
	for i := 0; i < 2; i++ {
		r.workers[strconv.Itoa(i)] = "worker" + strconv.Itoa(i)
		r.rawWorkers[strconv.Itoa(i)] = "rawworker" + strconv.Itoa(i)
	}
	if _, err := r.worker(context.Background(), "new", false); err == nil || !strings.Contains(err.Error(), "cap reached") {
		t.Errorf("worker past the bound was not refused: %v", err)
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

// The reaper considers only containers this package named, so nothing else on
// the host can be selected however it is labeled.
func TestRunnerListingIgnoresForeignContainers(t *testing.T) {
	listing := strings.Join([]string{
		"blk-guard-aaaa\t111",
		"blk-worker-bbbb\t111",
		"blk-rawworker-cccc\t222",
		"postgres\t111",
		"blkchain-qdrant\t111",
		"blk-web-browser\t111",
		"\t111",
		"blk-guard-dddd\t",
	}, "\n")
	got := parseRunnerContainers(listing)
	want := []string{"blk-guard-aaaa", "blk-worker-bbbb", "blk-rawworker-cccc", "blk-guard-dddd"}
	if len(got) != len(want) {
		t.Fatalf("selected %+v, want only the runner containers %v", got, want)
	}
	for i, name := range want {
		if got[i].name != name {
			t.Errorf("selected[%d] = %q, want %q", i, got[i].name, name)
		}
	}
}

// A container is removed only when its owner process is proven gone. A live
// owner, an owner whose liveness cannot be established, and a container with no
// owner label are all left alone, so a concurrent engagement is never disturbed.
func TestOrphanedRunnersRemoveOnlyProvenDeadOwners(t *testing.T) {
	listed := []runnerContainer{
		{name: "blk-guard-live", owner: "111"},
		{name: "blk-worker-live", owner: "111"},
		{name: "blk-guard-dead", owner: "222"},
		{name: "blk-rawworker-dead", owner: "222"},
		{name: "blk-guard-unlabeled", owner: ""},
		{name: "blk-guard-garbled", owner: "not-a-pid"},
	}
	alive := func(pid int) bool { return pid == 111 }

	orphaned, unjudged := orphanedRunners(listed, alive)

	if strings.Join(orphaned, ",") != "blk-guard-dead,blk-rawworker-dead" {
		t.Errorf("orphaned = %v, want only the containers whose owner is gone", orphaned)
	}
	if strings.Join(unjudged, ",") != "blk-guard-unlabeled,blk-guard-garbled" {
		t.Errorf("unjudged = %v, want the containers with no usable owner", unjudged)
	}
}

// ownerAlive answers yes unless the process is proven absent, so the reaper
// errs towards leaving a container in place.
func TestOwnerAliveOnlyReportsAbsentForNoSuchProcess(t *testing.T) {
	if !ownerAlive(os.Getpid()) {
		t.Error("this process reported as gone")
	}
	if !ownerAlive(0) || !ownerAlive(-1) {
		t.Error("a pid that names no process must not be treated as gone")
	}
	// A pid this high is not in use; the reaper may judge it gone.
	if ownerAlive(1 << 30) {
		t.Error("an unused pid reported as alive")
	}
}

// Every runner container carries the owner label, which is what makes the
// reaper able to tell a leftover from a live run's container.
func TestRunnerContainersCarryTheOwnerLabel(t *testing.T) {
	for _, args := range [][]string{
		engageWorkerArgs("w", "guard", "image", "", nil),
		engageRawWorkerArgs("w", "guard", "image", "", nil),
	} {
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "--label "+runnerOwnerLabel+"="+strconv.Itoa(os.Getpid())) {
			t.Errorf("worker args carry no owner label: %s", joined)
		}
	}
}
