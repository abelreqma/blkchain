package main

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

func seedOpenService(t *testing.T, store *engagement.Store, host, transport string, port int) {
	t.Helper()
	if _, err := store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "service-fixture", Kind: "recon", Surface: engagement.SurfaceNetwork, Status: engagement.StatusActive}}}); err != nil {
		t.Fatal(err)
	}
	scan := "-sT"
	if transport == "udp" {
		scan = "-sU"
	}
	probe := secgate.Command{TaskID: "service-fixture", Binary: "nmap", Args: []string{"-n", "-Pn", scan, "-p", strconv.Itoa(port), host}, Surface: secgate.SurfaceNetwork}
	output := "Nmap scan report for " + host + "\nPORT STATE SERVICE\n" + strconv.Itoa(port) + "/" + transport + " open fixture\n"
	if err := newServiceDispatcher(store).Observe(context.Background(), probe, output); err != nil {
		t.Fatal(err)
	}
}

func TestServiceDispatchNeedsMatchingDiscovery(t *testing.T) {
	ctx := context.Background()
	d := newServiceDispatcher(nil)
	snmp := secgate.Command{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "192.0.2.10"}}
	if reason := d.Check(ctx, snmp); !strings.Contains(reason, "udp/161") {
		t.Fatalf("snmpwalk without discovery = %q", reason)
	}
	probe := secgate.Command{Binary: "nmap", Args: []string{"-n", "-Pn", "-sU", "-p", "161", "192.0.2.10"}}
	if reason := d.Check(ctx, probe); reason != "" {
		t.Fatalf("bounded port discovery denied: %s", reason)
	}
	output := "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n161/udp open|filtered snmp\n"
	if err := d.Observe(ctx, probe, output); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, snmp); reason != "" {
		t.Fatalf("observed UDP/161 denied: %s", reason)
	}
	for _, cmd := range []secgate.Command{
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "192.0.2.11"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "192.0.2.10:162"}},
		{Binary: "curl", Args: []string{"http://192.0.2.10:161/"}},
	} {
		if reason := d.Check(ctx, cmd); reason == "" {
			t.Errorf("unobserved endpoint allowed: %s %v", cmd.Binary, cmd.Args)
		}
	}
	if err := d.Observe(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n161/udp closed snmp\n"); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, snmp); reason == "" {
		t.Fatal("new closed observation did not revoke service dispatch")
	}
}

func TestServiceDispatchPersistsAcrossEngagementResume(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	if _, err := st.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Kind: "recon", Status: engagement.StatusActive}}}); err != nil {
		t.Fatal(err)
	}
	d := newServiceDispatcher(st)
	probe := secgate.Command{TaskID: "t1", Surface: secgate.SurfaceNetwork, Binary: "nmap", Args: []string{"-n", "-Pn", "-sT", "-p", "8080", "192.0.2.10"}}
	if err := d.Observe(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n8080/tcp open http-proxy\n"); err != nil {
		t.Fatal(err)
	}
	observations, err := st.Surfaces(ctx, engagement.SurfaceFilter{Asset: "192.0.2.10", Kind: "service-port", Name: "tcp/8080"})
	if err != nil || len(observations) != 1 || observations[0].EvidenceID <= 0 || observations[0].Value != "open" {
		t.Fatalf("port observation lost provenance: %+v %v", observations, err)
	}
	fresh := newServiceDispatcher(st)
	if reason := fresh.Check(ctx, secgate.Command{Binary: "curl", Args: []string{"http://192.0.2.10:8080/"}}); reason != "" {
		t.Fatalf("persisted port evidence not honored: %s", reason)
	}
	if reason := fresh.Check(ctx, secgate.Command{Binary: "curl", Args: []string{"https://192.0.2.10:8080/"}}); reason != "" {
		t.Fatalf("TCP port should permit protocol checks on that port: %s", reason)
	}
	fresh.state[serviceEndpoint{host: "192.0.2.10", transport: "tcp", port: 8080}] = "open"
	if err := d.Observe(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n8080/tcp closed http-proxy\n"); err != nil {
		t.Fatal(err)
	}
	if reason := fresh.Check(ctx, secgate.Command{Binary: "curl", Args: []string{"http://192.0.2.10:8080/"}}); reason == "" {
		t.Fatal("new persisted closed observation lost to cached open state")
	}
}

func TestServiceDispatchRejectsUnprovenScannerOutput(t *testing.T) {
	ctx := context.Background()
	d := newServiceDispatcher(nil)
	probe := secgate.Command{Binary: "nmap", Args: []string{"-n", "-Pn", "-sT", "-p", "443", "192.0.2.10"}}
	for _, output := range []string{
		"Nmap scan report for 192.0.2.11\n443/tcp open https\n",
		"Nmap scan report for 192.0.2.10\n443/tcp closed https\n",
		"Nmap scan report for 192.0.2.10\n80/tcp open http\n",
	} {
		if err := d.Observe(ctx, probe, output); err != nil {
			t.Fatal(err)
		}
	}
	if reason := d.Check(ctx, secgate.Command{Binary: "curl", Args: []string{"https://192.0.2.10/"}}); reason == "" {
		t.Fatal("unproven TCP/443 was allowed")
	}
}

func TestEngagementGateRequiresServiceEvidence(t *testing.T) {
	ctx := context.Background()
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if _, err := ws.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Kind: "recon", Status: engagement.StatusActive}}}); err != nil {
		t.Fatal(err)
	}
	scope, err := secgate.ParseScope(strings.NewReader("192.0.2.10\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := buildEngageGate(ws, scope, secgate.Auto, nil, nil, t.TempDir(), gatePolicy{}, nil)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	snmp := secgate.Command{TaskID: "t1", Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "192.0.2.10"}, Surface: secgate.SurfaceNetwork, Phase: secgate.PhaseRecon}
	if decision := g.Authorize(ctx, snmp); decision.Allowed || !strings.Contains(decision.Reason, "udp/161") {
		t.Fatalf("undiscovered service verdict = %+v", decision)
	}
	probe := secgate.Command{TaskID: "t1", Binary: "nmap", Args: []string{"-n", "-Pn", "-sU", "-p", "161", "192.0.2.10"}, Surface: secgate.SurfaceNetwork, Phase: secgate.PhaseRecon}
	if decision := g.Authorize(ctx, probe); !decision.Allowed {
		t.Fatalf("discovery denied: %s", decision.Reason)
	}
	if err := g.ServiceObserve(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n161/udp open|filtered snmp\n"); err != nil {
		t.Fatal(err)
	}
	if decision := g.Authorize(ctx, snmp); !decision.Allowed {
		t.Fatalf("observed service denied: %s", decision.Reason)
	}
}

func TestEveryAuditedNetworkToolHasDispatchPolicy(t *testing.T) {
	for _, binary := range externalEngageAllowlist() {
		_, _, err := serviceRequirement(secgate.Command{Binary: binary})
		if err != nil && strings.Contains(err.Error(), "no audited service prerequisite") {
			t.Errorf("%s has no service dispatch policy", binary)
		}
	}
}

func TestServiceDispatchMapsActualTransportAndPort(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  secgate.Command
		want serviceEndpoint
	}{
		{"snmp default", secgate.Command{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "192.0.2.10"}}, serviceEndpoint{"192.0.2.10", "udp", 161}},
		{"snmp custom", secgate.Command{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "192.0.2.10:162"}}, serviceEndpoint{"192.0.2.10", "udp", 162}},
		{"netcat udp", secgate.Command{Binary: "nc", Args: []string{"-u", "192.0.2.10", "161"}}, serviceEndpoint{"192.0.2.10", "udp", 161}},
		{"ldaps custom", secgate.Command{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldaps://192.0.2.10:1636", "-b", "dc=example,dc=test"}}, serviceEndpoint{"192.0.2.10", "tcp", 1636}},
		{"dig server", secgate.Command{Binary: "dig", Args: []string{"@192.0.2.10", "-p", "5353", "example.test"}}, serviceEndpoint{"192.0.2.10", "udp", 5353}},
		{"https custom", secgate.Command{Binary: "curl", Args: []string{"https://192.0.2.10:8443/"}}, serviceEndpoint{"192.0.2.10", "tcp", 8443}},
		{"version scan", secgate.Command{Binary: "nmap", Args: []string{"-n", "-sV", "-p", "443", "192.0.2.10"}}, serviceEndpoint{"192.0.2.10", "tcp", 443}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, discovery, err := serviceRequirement(tc.cmd)
			if err != nil || discovery || len(got) != 1 || got[0] != tc.want {
				t.Fatalf("requirement = %v discovery=%t err=%v; want %v", got, discovery, err, tc.want)
			}
		})
	}
}

func TestMixedProtocolServiceScanNeedsExplicitPortTransport(t *testing.T) {
	cmd := secgate.Command{Binary: "nmap", Args: []string{"-sS", "-sU", "-sV", "-p", "161", "192.0.2.10"}}
	if _, _, err := serviceRequirement(cmd); err == nil {
		t.Fatal("mixed TCP/UDP service scan accepted an ambiguous port")
	}
}

func TestHostnameDiscoveryStaysBoundToCommandTarget(t *testing.T) {
	ctx := context.Background()
	d := newServiceDispatcher(nil)
	probe := secgate.Command{Binary: "nmap", Args: []string{"-n", "-sT", "-p", "443", "app.example.test"}}
	output := "Nmap scan report for app.example.test (192.0.2.10)\nPORT STATE SERVICE\n443/tcp open https\n"
	if err := d.Observe(ctx, probe, output); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, secgate.Command{Binary: "curl", Args: []string{"https://app.example.test/"}}); reason != "" {
		t.Fatalf("named target was not unlocked: %s", reason)
	}
	if reason := d.Check(ctx, secgate.Command{Binary: "curl", Args: []string{"https://192.0.2.10/"}}); reason == "" {
		t.Fatal("scanner address was promoted without an exact target match")
	}
}

func TestObservedPortUnlocksDistinctFollowUps(t *testing.T) {
	ctx := context.Background()
	d := newServiceDispatcher(nil)
	probe := secgate.Command{Binary: "nmap", Args: []string{"-n", "-sT", "-p", "8443", "192.0.2.10"}}
	if err := d.Observe(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n8443/tcp open https\n"); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []secgate.Command{
		{Binary: "curl", Args: []string{"https://192.0.2.10:8443/"}},
		{Binary: "ffuf", Args: []string{"-u", "https://192.0.2.10:8443/FUZZ", "-w", "words"}},
		{Binary: "sslscan", Args: []string{"192.0.2.10:8443"}},
		{Binary: "openssl", Args: []string{"s_client", "-connect", "192.0.2.10:8443"}},
		{Binary: "nmap", Args: []string{"-n", "-sV", "-p", "8443", "192.0.2.10"}},
	} {
		if reason := d.Check(ctx, cmd); reason != "" {
			t.Errorf("observed port blocked %s: %s", cmd.Binary, reason)
		}
	}
	if reason := d.Check(ctx, secgate.Command{Binary: "nmap", Args: []string{"-n", "-sV", "-p", "9443", "192.0.2.10"}}); reason == "" {
		t.Fatal("unobserved port admitted a version scan")
	}
	versionScan := secgate.Command{Binary: "nmap", Args: []string{"-n", "-sV", "-p", "8443", "192.0.2.10"}}
	if err := d.Observe(ctx, versionScan, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n8443/tcp closed https\n"); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, secgate.Command{Binary: "curl", Args: []string{"https://192.0.2.10:8443/"}}); reason == "" {
		t.Fatal("closed version-scan result left the follow-on unlocked")
	}
}

func TestServiceDispatchRejectsHiddenConnectionRoutes(t *testing.T) {
	for _, cmd := range []secgate.Command{
		{Binary: "curl", Args: []string{"-L", "https://192.0.2.10/"}},
		{Binary: "curl", Args: []string{"-sSL", "https://192.0.2.10/"}},
		{Binary: "curl", Args: []string{"--connect-to", "192.0.2.10:443:192.0.2.11:9443", "https://192.0.2.10/"}},
		{Binary: "curl", Args: []string{"--resolve", "app.example.test:443:192.0.2.11", "https://app.example.test/"}},
		{Binary: "curl", Args: []string{"--proxy", "192.0.2.11:8080", "https://192.0.2.10/"}},
		{Binary: "ffuf", Args: []string{"-r", "-u", "https://192.0.2.10/FUZZ"}},
		{Binary: "nmap", Args: []string{"--proxies", "http://192.0.2.11:8080", "-p", "443", "192.0.2.10"}},
		{Binary: "ncat", Args: []string{"--proxy", "192.0.2.11:8080", "192.0.2.10", "443"}},
		{Binary: "openssl", Args: []string{"s_client", "-proxy", "192.0.2.11:8080", "-connect", "192.0.2.10:443"}},
	} {
		if _, _, err := serviceRequirement(cmd); err == nil {
			t.Errorf("hidden route accepted: %s %v", cmd.Binary, cmd.Args)
		}
	}
}

func TestMasscanDiscoveryUnlocksOnlyReportedPort(t *testing.T) {
	ctx := context.Background()
	d := newServiceDispatcher(nil)
	probe := secgate.Command{Binary: "masscan", Args: []string{"--rate", "50", "-p", "22", "192.0.2.10"}}
	if err := d.Observe(ctx, probe, "Discovered open port 22/tcp on 192.0.2.10\nDiscovered open port 23/tcp on 192.0.2.10\nDiscovered open port 22/tcp on 192.0.2.11\n"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, port string
		allowed    bool
	}{
		{"192.0.2.10", "22", true},
		{"192.0.2.10", "23", false},
		{"192.0.2.11", "22", false},
	} {
		cmd := secgate.Command{Binary: "nc", Args: []string{tc.host, tc.port}}
		if got := d.Check(ctx, cmd) == ""; got != tc.allowed {
			t.Errorf("%s:%s allowed=%t, want %t", tc.host, tc.port, got, tc.allowed)
		}
	}
}
