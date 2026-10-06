package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// executorRunnerImage is the image the per-command sandbox runs. It is the same
// content-addressed tag the isolated runner uses, whose name is a digest over
// the embedded build inputs, so `blk engage setup` builds the one image both
// execution paths need. A hardcoded image digest cannot serve here: a digest is
// not reproducible across builds or architectures, so nothing would ever produce
// it again and the sandbox would fail with "No such image" under --pull never.
func executorRunnerImage() string { return defaultRunnerTag() }

const executorFirewallScript = `set -eu
iptables -P OUTPUT DROP
iptables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P INPUT DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
work="$1"
shift
while [ "$1" != "--" ]; do
  iptables -A OUTPUT -d "$1/32" -j ACCEPT
  shift
done
shift
limit="$1"
shift
exec timeout -s KILL "$limit" capsh --drop=all --gid=1000 --uid=1000 --caps= -- -c 'set -e; cp -R -P /blk-inputs/. "$1"/; shift; exec "$@"' blk-run "$work" "$@"`

func newContainerCommand(ctx context.Context, binary string, args []string, scratch string, egress executorEgress) (*exec.Cmd, func() error, error) {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return nil, nil, fmt.Errorf("isolated executor requires Docker: %w", err)
	}
	reserved, err := dockerReservedIPs(ctx, docker)
	if err != nil {
		return nil, nil, err
	}
	for _, allowed := range egress.IPs {
		ip := net.ParseIP(allowed)
		for _, blocked := range reserved {
			if ip.Equal(blocked) {
				return nil, nil, fmt.Errorf("executor cannot reach Docker host gateway %s", allowed)
			}
		}
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}
	name := "blkchain-exec-" + hex.EncodeToString(nonce[:])
	workDir, err := filepath.Abs(scratch)
	if err != nil {
		return nil, nil, err
	}
	dockerArgs := []string{
		"run", "--rm", "--pull", "never", "--name", name, "-i",
		"--network", "bridge", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
		"--mount", "type=bind,src=" + workDir + ",dst=/blk-inputs,readonly",
		"--tmpfs", workDir + ":rw,noexec,nosuid,size=64m,mode=0700,uid=1000,gid=1000", "--workdir", workDir,
		"--user", "0:0", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
		"--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "SETPCAP",
		"--security-opt", "no-new-privileges", "--memory", "512m", "--cpus", "2", "--pids-limit", "64",
	}
	hosts := make([]string, 0, len(egress.Hosts))
	for host := range egress.Hosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		dockerArgs = append(dockerArgs, "--add-host", host+":"+egress.Hosts[host])
	}
	dockerArgs = append(dockerArgs, executorRunnerImage(), "/bin/sh", "-c", executorFirewallScript, "blk-init", workDir)
	dockerArgs = append(dockerArgs, egress.IPs...)
	limit := 300 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		limit = time.Until(deadline)
	}
	seconds := int((limit + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	if seconds > 1800 {
		seconds = 1800
	}
	dockerArgs = append(dockerArgs, "--", fmt.Sprint(seconds), binary)
	dockerArgs = append(dockerArgs, args...)
	cmd := exec.CommandContext(ctx, docker, dockerArgs...)
	cmd.Dir = workDir
	cleanup := func() error {
		stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for attempt := 0; attempt < 3; attempt++ {
			stop := exec.CommandContext(stopCtx, docker, "rm", "-f", name)
			stop.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
			stop.Stdout, stop.Stderr = io.Discard, io.Discard
			_ = stop.Run()
			inspect := exec.CommandContext(stopCtx, docker, "inspect", name)
			inspect.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
			output, err := inspect.CombinedOutput()
			missing := strings.ToLower(string(output))
			if err != nil && (strings.Contains(missing, "no such object") || strings.Contains(missing, "no such container")) {
				return nil
			}
			if stopCtx.Err() != nil {
				break
			}
		}
		return errors.New("executor container removal could not be confirmed")
	}
	return cmd, cleanup, nil
}

func dockerReservedIPs(ctx context.Context, docker string) ([]net.IP, error) {
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	bridge := exec.CommandContext(checkCtx, docker, "network", "inspect", "bridge", "--format", `{{range .IPAM.Config}}{{.Gateway}} {{.Subnet}} {{end}}`)
	bridge.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	data, err := bridge.Output()
	if err != nil {
		return nil, fmt.Errorf("executor cannot inspect Docker bridge gateway: %w", err)
	}
	reserved := make([]net.IP, 0, 3)
	for _, field := range strings.Fields(string(data)) {
		if ip := net.ParseIP(field); ip != nil {
			reserved = append(reserved, ip)
		} else if ip := ipv4SubnetBroadcast(field); ip != nil {
			reserved = append(reserved, ip)
		}
	}
	if len(reserved) == 0 {
		return nil, fmt.Errorf("executor Docker bridge has no verifiable gateway")
	}
	alias := exec.CommandContext(checkCtx, docker, "run", "--rm", "--pull", "never", "--network", "bridge",
		"--read-only", "--user", "1000:1000", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--memory", "64m", "--pids-limit", "16", executorRunnerImage(),
		"/bin/sh", "-c", "getent ahostsv4 host.docker.internal || true")
	alias.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	data, err = alias.Output()
	if err != nil {
		return nil, fmt.Errorf("executor cannot inspect Docker host gateway alias: %w", err)
	}
	aliases, err := parseDockerHostAliases(data, runtime.GOOS == "darwin")
	if err != nil {
		return nil, err
	}
	reserved = append(reserved, aliases...)
	return reserved, nil
}

func parseDockerHostAliases(data []byte, required bool) ([]net.IP, error) {
	aliases := []net.IP{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			if ip := net.ParseIP(fields[0]); ip != nil {
				aliases = append(aliases, ip)
			}
		}
	}
	if required && len(aliases) == 0 {
		return nil, errors.New("executor cannot verify Docker host gateway alias")
	}
	return aliases, nil
}

func ipv4SubnetBroadcast(cidr string) net.IP {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	ones, bits := network.Mask.Size()
	v4 := network.IP.To4()
	if bits != 32 || ones >= 31 || v4 == nil {
		return nil
	}
	return net.IPv4(v4[0]|^network.Mask[0], v4[1]|^network.Mask[1],
		v4[2]|^network.Mask[2], v4[3]|^network.Mask[3])
}
