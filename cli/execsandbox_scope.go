package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"blkchain/cli/internal/secgate"
)

type executorScopeKey struct{}
type executorStopKey struct{}

func withExecutorScope(ctx context.Context, scope *secgate.Scope) context.Context {
	return context.WithValue(ctx, executorScopeKey{}, scope)
}

func withExecutorStop(ctx context.Context, stop context.CancelCauseFunc) context.Context {
	return context.WithValue(ctx, executorStopKey{}, stop)
}

func stopExecutorRun(ctx context.Context, err error) {
	if stop, ok := ctx.Value(executorStopKey{}).(context.CancelCauseFunc); ok {
		stop(err)
	}
}

type executorEgress struct {
	IPs   []string
	Hosts map[string]string
}

func resolveExecutorEgress(ctx context.Context, binary string, args []string) (executorEgress, error) {
	targets, ok := secgate.ExtractTargets(secgate.Command{Binary: binary, Args: args})
	if !ok {
		return executorEgress{}, errors.New("executor target cannot be verified")
	}
	if len(targets) == 0 {
		return executorEgress{}, nil
	}
	if len(targets) > 16 {
		return executorEgress{}, errors.New("executor target count exceeds 16")
	}
	scope, _ := ctx.Value(executorScopeKey{}).(*secgate.Scope)
	if scope == nil {
		return executorEgress{}, errors.New("executor network target requires an engagement scope")
	}
	localAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return executorEgress{}, errors.New("executor cannot verify operator host addresses")
	}
	localIPs := make([]net.IP, 0, len(localAddrs))
	for _, addr := range localAddrs {
		if ip, _, err := net.ParseCIDR(addr.String()); err == nil {
			localIPs = append(localIPs, ip)
		}
	}
	plan := executorEgress{Hosts: map[string]string{}}
	seen := map[string]bool{}
	for _, host := range targets {
		if !scope.InScope(host) {
			return executorEgress{}, errors.New("executor target is outside the engagement scope")
		}
		ip := net.ParseIP(host)
		if ip == nil {
			lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			resolved, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
			cancel()
			if err != nil || len(resolved) == 0 || len(resolved) > 16 {
				return executorEgress{}, errors.New("executor hostname cannot be resolved within the limit")
			}
			for _, addr := range resolved {
				if !scope.InScope(addr.IP.String()) {
					return executorEgress{}, errors.New("executor hostname resolves outside the engagement scope")
				}
				if ip == nil || (ip.To4() == nil && addr.IP.To4() != nil) {
					ip = addr.IP
				}
			}
			plan.Hosts[host] = ip.String()
		}
		if ip.To4() == nil {
			return executorEgress{}, errors.New("executor IPv6 egress is unavailable in the isolated runner")
		}
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.Equal(net.IPv4bcast) || scope.IsDirectedBroadcast(ip) {
			return executorEgress{}, errors.New("executor cannot map this target into the isolated network")
		}
		for _, local := range localIPs {
			if ip.Equal(local) {
				return executorEgress{}, errors.New("executor target is an operator host interface")
			}
		}
		canonical := strings.ToLower(ip.String())
		if !seen[canonical] {
			plan.IPs = append(plan.IPs, canonical)
			seen[canonical] = true
		}
	}
	return plan, nil
}
