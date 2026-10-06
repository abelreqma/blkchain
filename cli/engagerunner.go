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
	"strings"
	"sync"
	"time"
)

//go:embed runner/Dockerfile runner/execute.py runner/packages-amd64.lock runner/packages-arm64.lock
var engageRunnerFiles embed.FS

type engageRunner struct {
	mu           sync.Mutex
	guard, image string
	workers      map[string]string
	hosts        []string
	slots        chan struct{}
	closed       bool
	remove       func(context.Context, string) error
	runFn        func(context.Context, []pipelineStage, string, int, time.Duration) (runResult, []isolatedStageResult)
}

func engageWorkerArgs(name, guard, image string, hosts []string) []string {
	args := []string{"run", "-d", "--name", name, "--network", "container:" + guard, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "1000:1000", "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "--ulimit", "nofile=256:256", "--ulimit", "fsize=67108864:67108864", "--tmpfs", "/work:rw,nosuid,nodev,size=128m,uid=1000,gid=1000", "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m", "--env", "HOME=/work", "--env", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "--entrypoint", "/bin/sh"}
	args = append(args, image, "-c", "exec sleep 86400")
	return args
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
	guardName := runnerName("blk-guard-")
	r := &engageRunner{image: imageID, workers: map[string]string{}, slots: make(chan struct{}, p.Parallel)}
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
	commandIPs := runnerCommandIPs(roe.Scope)
	r.hosts = hosts
	_, err = runnerDocker(check, nil, "run", "-d", "--name", guardName, "--network", "bridge", "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges", "--user", "0:0", "--memory", "64m", "--cpus", "0.25", "--pids-limit", "16", "--entrypoint", "/bin/sh", imageID, "-c", "exec sleep 86400")
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

func (r *engageRunner) worker(ctx context.Context, dir string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return "", errors.New("runner stopped")
	}
	if id := r.workers[dir]; id != "" {
		return id, nil
	}
	if len(r.workers) >= 8 {
		return "", errors.New("runner worker cap reached")
	}
	id := runnerName("blk-worker-")
	if _, err := runnerDocker(ctx, nil, engageWorkerArgs(id, r.guard, r.image, r.hosts)...); err != nil {
		return "", err
	}
	r.workers[dir] = id
	if len(r.hosts) > 0 {
		if _, err := runnerDocker(ctx, []byte(strings.Join(r.hosts, "\n")+"\n"), "exec", "-i", "--user", "0:0", id, "sh", "-c", "cat >> /etc/hosts"); err != nil {
			if cleanupErr := r.removeContainer(ctx, id); cleanupErr != nil {
				return "", errors.Join(err, fmt.Errorf("remove failed worker %s: %w", id, cleanupErr))
			}
			delete(r.workers, dir)
			return "", err
		}
	}
	return id, nil
}

func (r *engageRunner) removeContainer(ctx context.Context, id string) error {
	if r.remove != nil {
		return r.remove(ctx, id)
	}
	_, err := runnerDocker(ctx, nil, "rm", "-f", id)
	return err
}

func (r *engageRunner) Release(dir string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.workers[dir]
	if id == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := r.removeContainer(ctx, id); err != nil {
		return fmt.Errorf("remove worker %s: %w", id, err)
	}
	delete(r.workers, dir)
	return nil
}

func (r *engageRunner) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var failures []error
	for dir, id := range r.workers {
		if err := r.removeContainer(ctx, id); err != nil {
			failures = append(failures, fmt.Errorf("remove worker %s: %w", id, err))
		} else {
			delete(r.workers, dir)
		}
	}
	if r.guard != "" {
		if err := r.removeContainer(ctx, r.guard); err != nil {
			failures = append(failures, fmt.Errorf("remove network guard %s: %w", r.guard, err))
		} else {
			r.guard = ""
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
	id, err := r.worker(ctx, dir)
	if err != nil {
		return runResult{Err: err}, nil
	}
	data, err := json.Marshal(map[string]any{"stages": stages, "limit": limit, "timeout": timeout.Seconds()})
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
