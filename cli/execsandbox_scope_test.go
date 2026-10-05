package main

import (
	"context"
	"net"
	"strings"
	"testing"

	"blkchain/cli/internal/secgate"
)

func TestExecutorEgressRequiresExactScopedTarget(t *testing.T) {
	scope, err := secgate.ParseScope(strings.NewReader("192.0.2.1\n10.7.0.0/16\n!10.7.9.9\n"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := withExecutorScope(context.Background(), scope)
	plan, err := resolveExecutorEgress(ctx, "curl", []string{"http://192.0.2.1:8080/"})
	if err != nil || len(plan.IPs) != 1 || plan.IPs[0] != "192.0.2.1" {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	plan, err = resolveExecutorEgress(ctx, "nmap", []string{"10.7.1.2"})
	if err != nil || len(plan.IPs) != 1 || plan.IPs[0] != "10.7.1.2" {
		t.Fatalf("private in-scope target plan=%+v err=%v", plan, err)
	}
	for _, args := range [][]string{{"10.7.9.9"}, {"198.51.100.2"}, {"10.7.0.0/16"}} {
		if _, err := resolveExecutorEgress(ctx, "nmap", args); err == nil {
			t.Fatalf("unsafe target accepted: %v", args)
		}
	}
	if _, err := resolveExecutorEgress(context.Background(), "curl", []string{"http://192.0.2.1/"}); err == nil {
		t.Fatal("network target without a scope accepted")
	}
	plan, err = resolveExecutorEgress(ctx, "id", nil)
	if err != nil || len(plan.IPs) != 0 {
		t.Fatalf("targetless command plan=%+v err=%v", plan, err)
	}
}

func TestExecutorEgressRejectsOperatorInterface(t *testing.T) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil || ip.To4() == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		scope, err := secgate.ParseScope(strings.NewReader(ip.String() + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := resolveExecutorEgress(withExecutorScope(context.Background(), scope), "curl", []string{"http://" + ip.String() + "/"}); err == nil {
			t.Fatalf("operator interface %s accepted as a target", ip)
		}
		return
	}
	t.Skip("no non-loopback IPv4 interface")
}

func TestIPv4SubnetBroadcast(t *testing.T) {
	if got := ipv4SubnetBroadcast("172.17.0.0/16"); got == nil || got.String() != "172.17.255.255" {
		t.Fatalf("Docker bridge broadcast=%v", got)
	}
	if got := ipv4SubnetBroadcast("10.0.0.254/31"); got != nil {
		t.Fatalf("/31 has no directed broadcast: %v", got)
	}
}

func TestDockerHostAliasDiscoveryFailsClosed(t *testing.T) {
	for _, output := range []string{"", "not-an-ip host.docker.internal\n"} {
		if _, err := parseDockerHostAliases([]byte(output), true); err == nil {
			t.Fatalf("invalid Docker host alias accepted: %q", output)
		}
	}
	aliases, err := parseDockerHostAliases([]byte("192.168.65.254 STREAM host.docker.internal\n"), true)
	if err != nil || len(aliases) != 1 || aliases[0].String() != "192.168.65.254" {
		t.Fatalf("aliases=%v err=%v", aliases, err)
	}
}

func TestExecutorEgressRejectsLoopbackEvenWhenScoped(t *testing.T) {
	scope, err := secgate.ParseScope(strings.NewReader("127.0.0.1\n169.254.169.254\n10.7.0.0/16\n255.255.255.255\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"127.0.0.1", "169.254.169.254", "10.7.255.255", "255.255.255.255"} {
		if _, err := resolveExecutorEgress(withExecutorScope(context.Background(), scope), "curl", []string{"http://" + target + ":8080/"}); err == nil {
			t.Fatalf("runner-local or broadcast target accepted: %s", target)
		}
	}
	if plan, err := resolveExecutorEgress(withExecutorScope(context.Background(), scope), "curl", []string{"http://10.7.1.255:8080/"}); err != nil || len(plan.IPs) != 1 {
		t.Fatalf("valid /16 host ending in .255 was rejected: plan=%+v err=%v", plan, err)
	}
}
