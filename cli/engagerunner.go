package main

import (
	"blkchain/cli/internal/secgate"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed runner/Dockerfile runner/execute.py runner/packages-amd64.lock runner/packages-arm64.lock
var engageRunnerFiles embed.FS

type engageRunner struct {
	mu           sync.Mutex
	guard, image string
	workers      map[string]string
	rawWorkers   map[string]string
	hosts        []string
	hostsDir     string
	hostsFile    string
	slots        chan struct{}
	closed       bool
	foothold     *footholdTransport
	remove       func(context.Context, string) error
	resolve      func(context.Context, string) ([]net.IPAddr, error)
	runFn        func(context.Context, []pipelineStage, string, int, time.Duration) (runResult, []isolatedStageResult)
}

func engageWorkerArgs(name, guard, image, hostsFile string, env []string) []string {
	return workerArgs(name, guard, image, hostsFile, env, false)
}

// engageRawWorkerArgs builds the raw-socket worker. It differs from the general
// worker in exactly two ways: it runs as root and holds CAP_NET_RAW. Docker
// exposes no ambient capability, and no-new-privileges blocks the
// file-capability route, so an unprivileged process keeps an empty effective set
// however the capability is added: masscan, tcpdump, and the nmap raw scan modes
// need a root process or they fail with a permission error. Every other control
// is unchanged: read-only rootfs, the rest of the capability set dropped,
// no-new-privileges, the same memory, cpu, pid and file limits, the same
// read-only host pins, and the guard's network namespace, so the firewall still
// bounds every destination.
func engageRawWorkerArgs(name, guard, image, hostsFile string, env []string) []string {
	return workerArgs(name, guard, image, hostsFile, env, true)
}

// workerArgs builds a worker container. env names environment variables the
// operator declared for a foothold carrier; their values are forwarded from this
// process so a carrier can authenticate, and nothing else from the operator
// environment crosses into the worker.
func workerArgs(name, guard, image, hostsFile string, env []string, raw bool) []string {
	// The raw worker runs as uid 0 but holds only NET_RAW, so it has no
	// CAP_DAC_OVERRIDE and cannot write a scratch mount owned by another uid. Its
	// /work must therefore be root-owned; it is still a private tmpfs per
	// container.
	user, work := "1000:1000", "/work:rw,nosuid,nodev,size=128m,uid=1000,gid=1000"
	if raw {
		user, work = "0:0", "/work:rw,nosuid,nodev,size=128m,uid=0,gid=0"
	}
	args := []string{"run", "-d", "--name", name, "--network", "container:" + guard, "--read-only", "--cap-drop", "ALL"}
	args = append(args, runnerOwnerArgs()...)
	if raw {
		args = append(args, "--cap-add", "NET_RAW")
	}
	args = append(args, "--security-opt", "no-new-privileges", "--user", user, "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "--ulimit", "nofile=256:256", "--ulimit", "fsize=67108864:67108864", "--tmpfs", work, "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m", "--env", "HOME=/work", "--env", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "--entrypoint", "/bin/sh")
	if hostsFile != "" {
		args = append(args, "--mount", "type=bind,src="+hostsFile+",dst=/etc/hosts,readonly")
	}
	for _, name := range env {
		args = append(args, "--env", name)
	}
	args = append(args, image, "-c", "exec sleep 86400")
	return args
}

// runnerOwnerLabel marks every container this process creates with the pid that
// owns it, so a later run can tell its own leftovers from a concurrent run's
// live containers.
const runnerOwnerLabel = "blkchain.owner-pid"

// runnerNamePrefixes are the names this package gives its containers. The reaper
// uses them to recognize leftovers from a build that predates the owner label.
var runnerNamePrefixes = []string{"blk-guard-", "blk-worker-", "blk-rawworker-"}

// runnerOwnerArgs are the label arguments every runner container carries.
func runnerOwnerArgs() []string {
	return []string{"--label", runnerOwnerLabel + "=" + strconv.Itoa(os.Getpid())}
}

// ownerAlive reports whether pid still names a live process. Signal 0 delivers
// nothing and only asks the question. A permission error means the pid belongs
// to someone else and is alive, so both error cases that are not "no such
// process" answer yes: the reaper must never remove a container whose owner it
// cannot prove is gone.
func ownerAlive(pid int) bool {
	if pid <= 0 {
		return true
	}
	err := syscall.Kill(pid, 0)
	return !errors.Is(err, syscall.ESRCH)
}

// runnerContainer is one container the reaper considered.
type runnerContainer struct {
	name  string
	owner string
}

// parseRunnerContainers reads the reaper's docker listing: one container per
// line as name and owner label, tab separated. Lines for containers this
// package did not name are dropped, so the reaper never considers anything
// else running on the host. It is pure, so the selection is unit tested.
func parseRunnerContainers(listing string) []runnerContainer {
	var out []runnerContainer
	for _, line := range strings.Split(listing, "\n") {
		name, owner, _ := strings.Cut(strings.TrimSpace(line), "\t")
		if name == "" {
			continue
		}
		ours := false
		for _, prefix := range runnerNamePrefixes {
			if strings.HasPrefix(name, prefix) {
				ours = true
				break
			}
		}
		if ours {
			out = append(out, runnerContainer{name: name, owner: strings.TrimSpace(owner)})
		}
	}
	return out
}

// orphanedRunners splits the listed containers into the ones safe to remove and
// the ones left alone. A container is orphaned only when its owner label names a
// process that no longer exists, so a concurrent engagement is never disturbed:
// a live run's owner is alive by definition. A container with no owner label
// predates the label and cannot be judged, so it is reported rather than
// removed.
func orphanedRunners(listed []runnerContainer, alive func(int) bool) (orphaned, unjudged []string) {
	for _, c := range listed {
		pid, err := strconv.Atoi(c.owner)
		if c.owner == "" || err != nil {
			unjudged = append(unjudged, c.name)
			continue
		}
		if !alive(pid) {
			orphaned = append(orphaned, c.name)
		}
	}
	return orphaned, unjudged
}

// reapOrphanedRunners removes runner containers whose owning process is gone,
// which is what a blk killed outright leaves behind: its deferred cleanup never
// runs and its guard and workers survive indefinitely. It is best-effort, so a
// docker failure here never fails the engagement that called it. Containers it
// cannot judge are named on stderr once, for the operator to remove.
func reapOrphanedRunners(ctx context.Context, remove func(context.Context, string) error) {
	listing, err := runnerDocker(ctx, nil, "ps", "-a", "--no-trunc",
		"--format", "{{.Names}}\t{{.Label \""+runnerOwnerLabel+"\"}}")
	if err != nil {
		return
	}
	orphaned, unjudged := orphanedRunners(parseRunnerContainers(listing), ownerAlive)
	for _, name := range orphaned {
		_ = remove(ctx, name)
	}
	if len(unjudged) > 0 {
		fmt.Fprintf(os.Stderr, "blk: %d runner %s with no owner label left in place: %s\n",
			len(unjudged), plural(len(unjudged), "container"), strings.Join(unjudged, ", "))
	}
}

// pipelineNeedsRawSocket reports whether any stage needs the raw-socket worker.
// A pipeline runs in one worker, so one raw stage takes the whole pipeline
// there. The decision reads the tool catalog and the argv only.
func pipelineNeedsRawSocket(stages []pipelineStage) bool {
	for _, s := range stages {
		if rawSocketCommand(s.Binary, s.Args) {
			return true
		}
	}
	return false
}

// Docker rejects --add-host with container networking, so workers mount this generated file.
func writeRunnerHosts(hosts []string) (dir, path string, err error) {
	if len(hosts) > 8192 {
		return "", "", errors.New("runner host pin limit reached")
	}
	var data strings.Builder
	data.WriteString("127.0.0.1 localhost\n::1 localhost\n")
	for _, line := range hosts {
		fields := strings.Fields(line)
		if strings.ContainsAny(line, "\r\n\x00") || len(fields) != 2 || net.ParseIP(fields[0]) == nil {
			return "", "", errors.New("invalid runner host pin")
		}
		data.WriteString(line)
		data.WriteByte('\n')
		if data.Len() > 1<<20 {
			return "", "", errors.New("runner host pins exceed 1 MiB")
		}
	}
	dir, err = os.MkdirTemp("/tmp", "blk-engage-hosts-")
	if err != nil {
		return "", "", err
	}
	path = filepath.Join(dir, "hosts")
	if err = os.WriteFile(path, []byte(data.String()), 0600); err == nil {
		err = os.Chmod(path, 0644)
	}
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", "", err
	}
	return dir, path, nil
}

func engageFirewall(in, out, protected []string, v6 bool) (string, error) {
	var b strings.Builder
	b.WriteString("*filter\n:INPUT DROP [0:0]\n:OUTPUT DROP [0:0]\n:FORWARD DROP [0:0]\n-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	deny := []string{"127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "0.0.0.0/8"}
	if v6 {
		deny = []string{"::1/128", "fe80::/10", "ff00::/8", "::/128", "2002::/16", "2001::/32"}
	}
	write := func(entries []string, verdict string) error {
		for _, entry := range entries {
			var ip net.IP
			if parsed, network, err := net.ParseCIDR(entry); err == nil {
				ip = parsed
				entry = network.String()
			} else {
				ip = net.ParseIP(entry)
				if ip != nil {
					entry = ip.String()
				}
			}
			if ip == nil {
				return fmt.Errorf("firewall entry must be an IP or CIDR")
			}
			if (ip.To4() == nil) != v6 {
				continue
			}
			fmt.Fprintf(&b, "-A OUTPUT -d %s -j %s\n", entry, verdict)
		}
		return nil
	}
	if err := write(append(append(deny, out...), protected...), "DROP"); err != nil {
		return "", err
	}
	if err := write(in, "ACCEPT"); err != nil {
		return "", err
	}
	b.WriteString("COMMIT\n")
	return b.String(), nil
}

func runnerDocker(ctx context.Context, input []byte, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = bytes.NewReader(input)
	var output bytes.Buffer
	w := &lockedWriter{w: &cappedWriter{cap: 1 << 20, buf: &output}}
	cmd.Stdout = w
	cmd.Stderr = w
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("isolated runner: docker command failed: %w: %s", err, terminalSafe(output.String()))
	}
	return strings.TrimSpace(output.String()), nil
}

func defaultRunnerTag() string {
	names, _ := engageRunnerFiles.ReadDir("runner")
	h := sha256.New()
	for _, entry := range names {
		data, _ := engageRunnerFiles.ReadFile("runner/" + entry.Name())
		h.Write([]byte(entry.Name()))
		h.Write(data)
	}
	return "blkchain-engage-runner:" + hex.EncodeToString(h.Sum(nil))
}

func setupEngageRunner(ctx context.Context) error {
	dir, err := os.MkdirTemp("", "blk-runner-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	entries, err := engageRunnerFiles.ReadDir("runner")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		data, err := engageRunnerFiles.ReadFile("runner/" + entry.Name())
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(dir, entry.Name()), data, 0600); err != nil {
			return err
		}
	}
	_, err = runnerDocker(ctx, nil, "build", "--tag", defaultRunnerTag(), dir)
	return err
}

func runnerName(prefix string) string {
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	return prefix + hex.EncodeToString(id[:])
}

func newEngageRunner(ctx context.Context, roe *RoE) (result *engageRunner, err error) {
	p := roe.Policy
	image := p.RunnerImage
	if image == "" {
		image = defaultRunnerTag()
	}
	check, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	imageID, err := runnerDocker(check, nil, "image", "inspect", "--format", "{{.Id}}", image)
	if err != nil {
		return nil, errors.New("isolated runner image unavailable; run blk engage setup before the engagement")
	}
	if !strings.HasPrefix(imageID, "sha256:") || len(imageID) != 71 {
		return nil, errors.New("invalid runner image identity")
	}
	// The carrier is constructed before any container exists, so a missing key,
	// an unset environment variable, or an unbuildable transport fails the
	// engagement at setup.
	transport, err := newFootholdTransport(p.Foothold)
	if err != nil {
		return nil, err
	}
	// Remove what an earlier blk left behind when it was killed before its
	// cleanup could run. Containers belonging to a live run are untouched.
	reapOrphanedRunners(check, func(ctx context.Context, name string) error {
		_, err := runnerDocker(ctx, nil, "rm", "-f", name)
		return err
	})
	guardName := runnerName("blk-guard-")
	r := &engageRunner{image: imageID, workers: map[string]string{}, rawWorkers: map[string]string{}, slots: make(chan struct{}, p.Parallel), foothold: transport}
	ok := false
	defer func() {
		if !ok {
			if cleanupErr := r.Close(); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("isolated runner cleanup failed: %w", cleanupErr))
			}
		}
	}()
	in, out, hosts, err := runnerScope(ctx, roe.Scope)
	if err != nil {
		return nil, err
	}
	// The foothold is a code-derived destination the operator declared, so its
	// address is pinned directly rather than extracted from a carrier's argv.
	commandIPs := append(runnerCommandIPs(roe.Scope), footholdPinIPs(p.Foothold, hosts)...)
	r.hosts = hosts
	guardArgs := append([]string{"run", "-d", "--name", guardName, "--network", "bridge", "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges", "--user", "0:0", "--memory", "64m", "--cpus", "0.25", "--pids-limit", "16"}, runnerOwnerArgs()...)
	guardArgs = append(guardArgs, "--entrypoint", "/bin/sh", imageID, "-c", "exec sleep 86400")
	_, err = runnerDocker(check, nil, guardArgs...)
	if err != nil {
		return nil, err
	}
	r.guard = guardName
	gateway, err := runnerDocker(check, nil, "exec", r.guard, "python3", "-c", "import socket; print(socket.gethostbyname('host.docker.internal'))")
	protected := operatorAddresses()
	if err == nil && net.ParseIP(gateway) != nil {
		protected = append(protected, gateway)
	}
	bridge, err := runnerDocker(check, nil, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", r.guard)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(bridge) != nil {
		protected = append(protected, bridge)
	}
	if err := roe.Scope.PinNetwork(in, append(out, protected...)); err != nil {
		return nil, err
	}
	for _, v6 := range []bool{false, true} {
		rules, err := engageFirewall(commandIPs, out, protected, v6)
		if err != nil {
			return nil, err
		}
		bin := "iptables-restore"
		if v6 {
			bin = "ip6tables-restore"
		}
		if _, err = runnerDocker(check, []byte(rules), "exec", "-i", r.guard, bin); err != nil {
			return nil, err
		}
	}
	ok = true
	return r, nil
}

func operatorAddresses() []string {
	var out []string
	addresses, _ := net.InterfaceAddrs()
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil {
			out = append(out, ip.String())
		}
	}
	return out
}

func runnerScope(ctx context.Context, scope *secgate.Scope) (in, out, hosts []string, err error) {
	entries, excluded := scope.Entries()
	resolve := func(list []string, exclude bool) ([]string, error) {
		var result []string
		if len(list) > 256 {
			return nil, errors.New("runner scope exceeds 256 entries")
		}
		for _, entry := range list {
			if strings.HasPrefix(entry, "*.") {
				continue
			}
			if net.ParseIP(entry) != nil || strings.Contains(entry, "/") {
				result = append(result, entry)
				continue
			}
			lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
			ips, e := net.DefaultResolver.LookupIPAddr(lookup, entry)
			cancel()
			if e != nil || len(ips) == 0 || len(ips) > 32 {
				return nil, fmt.Errorf("cannot pin scoped hostname %s", entry)
			}
			for _, ip := range ips {
				result = append(result, ip.IP.String())
				if !exclude {
					hosts = append(hosts, ip.IP.String()+" "+entry)
				}
			}
		}
		return result, nil
	}
	in, err = resolve(entries, false)
	if err != nil {
		return
	}
	out, err = resolve(excluded, true)
	sort.Strings(hosts)
	return
}

// footholdPinIPs returns the foothold's addresses for the guard's accept list.
// An IP declaration pins itself; a hostname declaration must be an explicit
// in-scope entry, so runnerScope has already resolved it into the host pin lines
// and its addresses are read back from there.
func footholdPinIPs(f *secgate.Foothold, hosts []string) []string {
	if f == nil {
		return nil
	}
	if ip := net.ParseIP(f.Host); ip != nil {
		return []string{ip.String()}
	}
	var out []string
	for _, line := range hosts {
		address, name, ok := strings.Cut(line, " ")
		if ok && strings.EqualFold(strings.TrimSpace(name), f.Host) {
			out = append(out, address)
		}
	}
	return out
}

func runnerCommandIPs(scope *secgate.Scope) []string {
	entries, _ := scope.Entries()
	var allowed []string
	for _, entry := range entries {
		if net.ParseIP(entry) != nil {
			allowed = append(allowed, entry)
		} else if _, _, err := net.ParseCIDR(entry); err == nil {
			allowed = append(allowed, entry)
		}
	}
	return allowed
}

type engageEgressPlan struct {
	IPs     []string
	Hosts   []string
	Dynamic bool
}

func planWildcardEgress(ctx context.Context, scope *secgate.Scope, stages []pipelineStage, resolve func(context.Context, string) ([]net.IPAddr, error)) (engageEgressPlan, error) {
	if err := ctx.Err(); err != nil {
		return engageEgressPlan{}, err
	}
	if scope == nil {
		return engageEgressPlan{}, errors.New("engagement scope missing")
	}
	var targets []string
	var nets []*net.IPNet
	for _, stage := range stages {
		found, foundNets, ok := secgate.ExtractTargetSet(secgate.Command{Binary: stage.Binary, Args: stage.Args})
		if !ok || len(targets)+len(nets)+len(found)+len(foundNets) > 16 {
			return engageEgressPlan{}, errors.New("command targets cannot be verified within the limit")
		}
		targets = append(targets, found...)
		nets = append(nets, foundNets...)
	}
	plan := engageEgressPlan{}
	for _, target := range targets {
		if !scope.InScope(target) {
			return engageEgressPlan{}, errors.New("command target is outside the engagement scope")
		}
		plan.Dynamic = plan.Dynamic || scope.WildcardHost(target)
	}
	// A network target is authorized on the rule the gate applies: one in-scope
	// CIDR covers the whole range and nothing excluded overlaps it. It names no
	// hostname, so it never makes the plan dynamic.
	for _, n := range nets {
		if !scope.NetworkInScope(n) {
			return engageEgressPlan{}, errors.New("command network is outside the engagement scope")
		}
	}
	if !plan.Dynamic {
		return plan, nil
	}
	if resolve == nil {
		return engageEgressPlan{}, errors.New("command resolver missing")
	}
	seen := map[string]bool{}
	hosts := map[string]string{}
	// An authorized range is pinned as a range, which both the action guard's
	// firewall and the narrowed scope accept, so a sweep still reaches it when
	// another target of the same action made the plan dynamic.
	for _, n := range nets {
		entry := n.String()
		if seen[entry] {
			continue
		}
		if len(plan.IPs) >= 32 {
			return engageEgressPlan{}, errors.New("command destination address limit reached")
		}
		plan.IPs = append(plan.IPs, entry)
		seen[entry] = true
	}
	add := func(ip net.IP) error {
		if ip == nil || !ip.IsGlobalUnicast() {
			return errors.New("command destination has an unsafe address")
		}
		address := ip.String()
		if !seen[address] {
			if len(plan.IPs) >= 32 {
				return errors.New("command destination address limit reached")
			}
			plan.IPs = append(plan.IPs, address)
			seen[address] = true
		}
		return nil
	}
	for _, target := range targets {
		if ip := net.ParseIP(target); ip != nil {
			if !scope.WebAddressAllowed(target, ip) {
				return engageEgressPlan{}, errors.New("command destination is outside the engagement scope")
			}
			if err := add(ip); err != nil {
				return engageEgressPlan{}, err
			}
			continue
		}
		lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
		addresses, err := resolve(lookup, target)
		cancel()
		if err := ctx.Err(); err != nil {
			return engageEgressPlan{}, err
		}
		if err != nil || len(addresses) == 0 || len(addresses) > 32 {
			return engageEgressPlan{}, errors.New("command hostname cannot be resolved within the limit")
		}
		var chosen net.IP
		for _, address := range addresses {
			ip := address.IP
			if !scope.WebAddressAllowed(target, ip) {
				return engageEgressPlan{}, errors.New("command hostname resolves outside the engagement scope")
			}
			if err := add(ip); err != nil {
				return engageEgressPlan{}, err
			}
			if chosen == nil || (chosen.To4() == nil && ip.To4() != nil) {
				chosen = ip
			}
		}
		hosts[strings.ToLower(target)] = chosen.String()
	}
	sort.Strings(plan.IPs)
	for host, ip := range hosts {
		plan.Hosts = append(plan.Hosts, ip+" "+host)
	}
	sort.Strings(plan.Hosts)
	return plan, nil
}

// RunScoped gives a wildcard action its own network guard and checked IP list.
func (r *engageRunner) RunScoped(ctx context.Context, stages []pipelineStage, dir string, limit int, timeout time.Duration, plan engageEgressPlan, policy *secgate.Policy) (runResult, []isolatedStageResult) {
	if !plan.Dynamic {
		return r.Run(ctx, stages, dir, limit, timeout)
	}
	if r == nil || r.slots == nil || policy == nil || len(plan.IPs) == 0 {
		return runResult{Err: errors.New("action-scoped runner configuration missing")}, nil
	}
	if err := ctx.Err(); err != nil {
		return runResult{Err: err}, nil
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return runResult{Err: errors.New("isolated runner stopped")}, nil
	}
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	case <-ctx.Done():
		return runResult{Err: ctx.Err()}, nil
	}
	scope, err := secgate.BuildScope(secgate.ScopeSpec{In: plan.IPs})
	if err != nil {
		return runResult{Err: err}, nil
	}
	// An action-scoped runner exists for a wildcard command whose own targets
	// were just resolved, and a pivoted action never takes this path: it skips
	// the egress plan, so its plan is never dynamic. Stripping the foothold from
	// this runner's policy copy keeps the foothold's address out of a deliberately
	// narrow accept list and avoids provisioning carrier secrets into a worker
	// that cannot use them.
	narrowed := *policy
	narrowed.Foothold = nil
	worker, err := newEngageRunnerForRun(ctx, &RoE{Scope: scope, Policy: &narrowed})
	if err != nil {
		return runResult{Err: err}, nil
	}
	worker.hosts = append([]string(nil), plan.Hosts...)
	result, outputs := worker.Run(ctx, stages, dir, limit, timeout)
	if err := worker.Close(); err != nil {
		result.Err = errors.Join(result.Err, fmt.Errorf("action-scoped runner cleanup failed: %w", err))
	}
	return result, outputs
}

// workerCap bounds the containers both pools hold together. A task in flight
// can hold one general worker and one raw-socket worker, so each parallel slot
// authorizes two containers; anything lower refuses a worker the sealed policy
// already allowed. A runner built without slots still gets a bound.
func (r *engageRunner) workerCap() int {
	slots := cap(r.slots)
	if slots < 1 {
		slots = 1
	}
	return 2 * slots
}

// worker returns the container for an executor directory, creating it on first
// use. raw selects the privileged raw-socket worker, which is created only when
// a command actually needs the capability, so an enumeration command never runs
// in it. Both pools share one cap and the same read-only host pins.
func (r *engageRunner) worker(ctx context.Context, dir string, raw bool) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return "", errors.New("runner stopped")
	}
	pool, name, args := r.workers, "blk-worker-", engageWorkerArgs
	if raw {
		pool, name, args = r.rawWorkers, "blk-rawworker-", engageRawWorkerArgs
	}
	if id := pool[dir]; id != "" {
		return id, nil
	}
	if len(r.workers)+len(r.rawWorkers) >= r.workerCap() {
		return "", errors.New("runner worker cap reached")
	}
	id := runnerName(name)
	if len(r.hosts) > 0 && r.hostsFile == "" {
		var err error
		r.hostsDir, r.hostsFile, err = writeRunnerHosts(r.hosts)
		if err != nil {
			return "", err
		}
	}
	var env []string
	if r.foothold != nil {
		env = r.foothold.env
	}
	if _, err := runnerDocker(ctx, nil, args(id, r.guard, r.image, r.hostsFile, env)...); err != nil {
		return "", err
	}
	// Carrier secrets are written by the worker itself, so the files carry its
	// own owner and a 0600 mode. A worker that cannot be provisioned is removed
	// rather than left usable without its carrier.
	for _, path := range r.foothold.secretPaths() {
		if _, err := runnerDocker(ctx, r.foothold.secrets[path], "exec", "-i", id, "python3", "-c", footholdSecretWriter, path); err != nil {
			if rmErr := r.removeContainer(ctx, id); rmErr != nil {
				err = errors.Join(err, rmErr)
			}
			return "", fmt.Errorf("foothold carrier provisioning failed: %w", err)
		}
	}
	pool[dir] = id
	return id, nil
}

func (r *engageRunner) removeContainer(ctx context.Context, id string) error {
	if r.remove != nil {
		return r.remove(ctx, id)
	}
	_, err := runnerDocker(ctx, nil, "rm", "-f", id)
	return err
}

// Release removes both of a directory's workers. A directory that ran a raw
// command holds a privileged container, so releasing only the general worker
// would leave it running for the rest of the engagement.
func (r *engageRunner) Release(dir string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var failures []error
	for _, pool := range []map[string]string{r.workers, r.rawWorkers} {
		id := pool[dir]
		if id == "" {
			continue
		}
		if err := r.removeContainer(ctx, id); err != nil {
			failures = append(failures, fmt.Errorf("remove worker %s: %w", id, err))
			continue
		}
		delete(pool, dir)
	}
	return errors.Join(failures...)
}

func (r *engageRunner) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var failures []error
	for _, pool := range []map[string]string{r.workers, r.rawWorkers} {
		for dir, id := range pool {
			if err := r.removeContainer(ctx, id); err != nil {
				failures = append(failures, fmt.Errorf("remove worker %s: %w", id, err))
			} else {
				delete(pool, dir)
			}
		}
	}
	if r.guard != "" {
		if err := r.removeContainer(ctx, r.guard); err != nil {
			failures = append(failures, fmt.Errorf("remove network guard %s: %w", r.guard, err))
		} else {
			r.guard = ""
		}
	}
	if r.hostsDir != "" && len(r.workers) == 0 && len(r.rawWorkers) == 0 {
		if err := os.RemoveAll(r.hostsDir); err != nil {
			failures = append(failures, fmt.Errorf("remove runner host pins: %w", err))
		} else {
			r.hostsDir, r.hostsFile = "", ""
		}
	}
	return errors.Join(failures...)
}

type isolatedStageResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	Dropped  int64  `json:"dropped"`
}

// launcherRequest builds the JSON the worker's launcher reads from stdin. env
// names the environment variables the launcher copies from the container into each
// command's environment, which is the same set workerArgs forwards into the
// container.
func launcherRequest(stages []pipelineStage, limit int, timeout time.Duration, env []string) ([]byte, error) {
	return json.Marshal(map[string]any{"stages": stages, "limit": limit, "timeout": timeout.Seconds(), "env": env})
}

// footholdEnvNames returns the environment variable names the operator declared
// for the foothold carrier. workerArgs forwards them into the worker container;
// the launcher replaces the environment of every command it starts, so it needs
// the names too or a carrier never receives the value it authenticates with.
func (r *engageRunner) footholdEnvNames() []string {
	if r == nil || r.foothold == nil {
		return nil
	}
	return r.foothold.env
}

func (r *engageRunner) Run(ctx context.Context, stages []pipelineStage, dir string, limit int, timeout time.Duration) (runResult, []isolatedStageResult) {
	if r.runFn != nil {
		return r.runFn(ctx, stages, dir, limit, timeout)
	}
	select {
	case r.slots <- struct{}{}:
	case <-ctx.Done():
		return runResult{Err: ctx.Err()}, nil
	}
	defer func() { <-r.slots }()
	id, err := r.worker(ctx, dir, pipelineNeedsRawSocket(stages))
	if err != nil {
		return runResult{Err: err}, nil
	}
	data, err := launcherRequest(stages, limit, timeout, r.footholdEnvNames())
	if err != nil {
		return runResult{Err: err}, nil
	}
	script, err := engageRunnerFiles.ReadFile("runner/execute.py")
	if err != nil {
		return runResult{Err: err}, nil
	}
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", id, "python3", "-c", string(script))
	cmd.Stdin = bytes.NewReader(data)
	cmd.WaitDelay = 2 * time.Second
	var output, stderr bytes.Buffer
	cmd.Stdout = &cappedWriter{cap: limit*6 + (64 << 10), buf: &output}
	cmd.Stderr = &cappedWriter{cap: 8192, buf: &stderr}
	err = cmd.Run()
	if ctx.Err() != nil {
		r.Release(dir)
		return runResult{Err: ctx.Err(), Output: stderr.String()}, nil
	}
	if err != nil {
		return runResult{Err: fmt.Errorf("isolated command failed: %s", terminalSafe(stderr.String()))}, nil
	}
	var result struct {
		Stages   []isolatedStageResult `json:"stages"`
		TimedOut bool                  `json:"timed_out"`
		Error    string                `json:"error"`
	}
	if json.Unmarshal(output.Bytes(), &result) != nil || len(result.Stages) != len(stages) {
		return runResult{Err: errors.New("invalid isolated command response")}, nil
	}
	var combined strings.Builder
	for index, stage := range result.Stages {
		if index == len(result.Stages)-1 {
			combined.WriteString(stage.Stdout)
		}
		if !stages[index].DiscardStderr {
			combined.WriteString(stage.Stderr)
		}
	}
	if result.Error != "" {
		err = errors.New("isolated command start failed: " + result.Error)
	} else if len(result.Stages) > 0 && result.Stages[len(result.Stages)-1].ExitCode != 0 && !result.TimedOut {
		err = fmt.Errorf("exit status %d", result.Stages[len(result.Stages)-1].ExitCode)
	}
	return runResult{Output: combined.String(), TimedOut: result.TimedOut, Err: err}, result.Stages
}
