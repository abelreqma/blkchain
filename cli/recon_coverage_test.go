package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

func TestNetworkCoverageRequiresCompletedMatchingTechnique(t *testing.T) {
	scanOutput := "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n80/tcp open http\n" + nmapDone
	command := func(binary string, args []string, output string) []observedReconAction {
		return []observedReconAction{{command: secgate.Command{Binary: binary, Args: args}, result: runResult{Output: output}}}
	}
	sweep := reconTier{Index: 1, Dimensions: []string{"tcp-sweep", "udp-sweep"}}
	if out := tierOutcomeFromActions(engagement.SurfaceNetwork, sweep, 1, 1, nil); len(out.DimensionsCovered) != 0 {
		t.Fatalf("unrelated evidence covered a network sweep: %+v", out)
	}
	if out := tierOutcomeFromActions(engagement.SurfaceNetwork, sweep, 1, 1, command("nmap", []string{"-sT", "-p", "80", "192.0.2.10"}, scanOutput[:len(scanOutput)-len(nmapDone)])); len(out.DimensionsCovered) != 0 {
		t.Fatalf("incomplete scan covered a sweep: %+v", out)
	}
	noHost := "Nmap scan report for 192.0.2.10\nNmap done: 1 IP address (0 hosts up) scanned in 1.00 seconds\n"
	if out := tierOutcomeFromActions(engagement.SurfaceNetwork, sweep, 1, 1, command("nmap", []string{"-sT", "-p", "80", "192.0.2.10"}, noHost)); len(out.DimensionsCovered) != 0 {
		t.Fatalf("no-host output covered a port sweep: %+v", out)
	}
	tcp := tierOutcomeFromActions(engagement.SurfaceNetwork, sweep, 1, 1, command("nmap", []string{"-sT", "-p", "80", "192.0.2.10"}, scanOutput))
	if !slices.Equal(tcp.DimensionsCovered, []string{"tcp-sweep"}) {
		t.Fatalf("TCP scan coverage = %+v", tcp)
	}
	udp := tierOutcomeFromActions(engagement.SurfaceNetwork, sweep, 1, 1, command("nmap", []string{"-sU", "-p", "161", "192.0.2.10"}, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n161/udp open|filtered snmp\n"+nmapDone))
	if !slices.Equal(udp.DimensionsCovered, []string{"udp-sweep"}) {
		t.Fatalf("UDP scan coverage = %+v", udp)
	}
	version := reconTier{Index: 2, Dimensions: []string{"versions", "safe-scripts"}}
	v := tierOutcomeFromActions(engagement.SurfaceNetwork, version, 1, 1, command("nmap", []string{"-sV", "-p", "80", "192.0.2.10"}, scanOutput))
	if !slices.Equal(v.DimensionsCovered, []string{"versions"}) {
		t.Fatalf("version scan coverage = %+v", v)
	}
	probe := reconTier{Index: 3, Dimensions: []string{"probes"}}
	if out := tierOutcomeFromActions(engagement.SurfaceNetwork, probe, 1, 1, command("curl", []string{"http://192.0.2.10/"}, "HTTP/1.1 200 OK\n")); !slices.Equal(out.DimensionsCovered, []string{"probes"}) {
		t.Fatalf("service probe coverage = %+v", out)
	}
	failed := []observedReconAction{{command: secgate.Command{Binary: "curl", Args: []string{"http://192.0.2.10/"}}, result: runResult{Output: "HTTP/1.1 200 OK", ExitCode: 28}}}
	if out := tierOutcomeFromActions(engagement.SurfaceNetwork, probe, 1, 1, failed); len(out.DimensionsCovered) != 0 {
		t.Fatalf("failed probe covered tier: %+v", out)
	}
}

func TestReconServiceContextUsesObservedOpenPorts(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	exec := genericExecutor{d: engageDeps{Store: st}}
	if open, err := exec.hasObservedService(ctx, "192.0.2.10", false); err != nil || open {
		t.Fatalf("no observation looks open: %v %v", open, err)
	}
	seedOpenService(t, st, "192.0.2.10", "udp", 4500)
	if open, err := exec.hasObservedService(ctx, "192.0.2.10", false); err != nil || !open {
		t.Fatalf("observed UDP port missing: %v %v", open, err)
	}
	context, err := exec.reconServiceContext(ctx, "192.0.2.10")
	if err != nil || !strings.Contains(context, `"port":"udp/4500"`) {
		t.Fatalf("open port context = %q, %v", context, err)
	}
	d := newServiceDispatcher(st)
	probe := secgate.Command{TaskID: "service-fixture", Surface: secgate.SurfaceNetwork, Binary: "nmap", Args: []string{"-sS", "-Pn", "-n", "--source-port", "53", "-p", "8080", "192.0.2.11"}}
	if err := d.Observe(ctx, probe, "Nmap scan report for 192.0.2.11\nPORT STATE SERVICE\n8080/tcp open http\n"+nmapDone); err != nil {
		t.Fatal(err)
	}
	if open, err := exec.hasObservedService(ctx, "192.0.2.11", false); err != nil || open {
		t.Fatalf("source-port candidate unlocked version tier: %v %v", open, err)
	}
	if open, err := exec.hasObservedService(ctx, "192.0.2.11", true); err != nil || !open {
		t.Fatalf("source-port candidate did not unlock validation tier: %v %v", open, err)
	}
	context, err = exec.reconServiceContext(ctx, "192.0.2.11")
	if err != nil || !strings.Contains(context, `"source_port":"53"`) {
		t.Fatalf("source-port candidate context = %q, %v", context, err)
	}
}
