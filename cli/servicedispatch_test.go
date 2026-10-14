package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

const nmapDone = "Nmap done: 1 IP address (1 host up) scanned in 1.00 seconds\n"

func seedOpenService(t *testing.T, store *engagement.Store, host, transport string, port int, vantage ...string) {
	t.Helper()
	if _, err := store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "service-fixture", Kind: "recon", Surface: engagement.SurfaceNetwork, Status: engagement.StatusActive}}}); err != nil {
		t.Fatal(err)
	}
	scan := "-sT"
	if transport == "udp" {
		scan = "-sU"
	}
	probe := secgate.Command{TaskID: "service-fixture", Binary: "nmap", Args: []string{"-n", "-Pn", scan, "-p", strconv.Itoa(port), host}, Surface: secgate.SurfaceNetwork}
	output := "Nmap scan report for " + host + "\nPORT STATE SERVICE\n" + strconv.Itoa(port) + "/" + transport + " open fixture\n" + nmapDone
	d := newServiceDispatcher(store)
	if len(vantage) > 0 {
		d.vantage = func(secgate.Command) string { return vantage[0] }
	}
	if err := d.Observe(context.Background(), probe, output); err != nil {
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
	output := "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n161/udp open|filtered snmp\n" + nmapDone
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
	if err := d.Observe(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n161/udp closed snmp\n"+nmapDone); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, snmp); reason == "" {
		t.Fatal("new closed observation did not revoke service dispatch")
	}
}

func TestIKEScanDispatchNeedsMatchingUDPPort(t *testing.T) {
	ctx := context.Background()
	d := newServiceDispatcher(nil)
	base := []string{"--ikev2", "--nodns", "--sport=0", "--retry=1", "--timeout=1000", "192.0.2.10"}
	ike := secgate.Command{Binary: "ike-scan", Args: base}
	nat := secgate.Command{Binary: "ike-scan", Args: append([]string{"--nat-t"}, base...)}
	if reason := d.Check(ctx, ike); !strings.Contains(reason, "udp/500") {
		t.Fatalf("IKEv2 without discovery = %q", reason)
	}
	if reason := d.Check(ctx, nat); !strings.Contains(reason, "udp/4500") {
		t.Fatalf("NAT-T without discovery = %q", reason)
	}
	probe := secgate.Command{Binary: "nmap", Args: []string{"-n", "-Pn", "-sU", "-p", "500", "192.0.2.10"}}
	if err := d.Observe(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n500/udp open|filtered isakmp\n"+nmapDone); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, ike); reason != "" {
		t.Fatalf("IKEv2 after UDP/500 observation denied: %s", reason)
	}
	if reason := d.Check(ctx, nat); !strings.Contains(reason, "udp/4500") {
		t.Fatalf("UDP/500 unlocked NAT-T on UDP/4500: %s", reason)
	}
	probe.Args[4] = "4500"
	if err := d.Observe(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n4500/udp open|filtered ipsec-nat-t\n"+nmapDone); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, nat); reason != "" {
		t.Fatalf("NAT-T after UDP/4500 observation denied: %s", reason)
	}
}

func TestCompletedScanSkipsExactRepeatAcrossResume(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	if _, err := st.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Kind: "recon", Surface: engagement.SurfaceNetwork, Status: engagement.StatusActive}}}); err != nil {
		t.Fatal(err)
	}
	d := newServiceDispatcher(st)
	cmd := secgate.Command{TaskID: "t1", Surface: secgate.SurfaceNetwork, Binary: "nmap", Args: []string{"-n", "-Pn", "-sT", "-p", "80", "192.0.2.10"}}
	if reason := d.Check(ctx, cmd); reason != "" {
		t.Fatal(reason)
	}
	incomplete := "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n80/tcp open http\n"
	if err := d.Observe(ctx, cmd, incomplete); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, cmd); reason != "" {
		t.Fatalf("incomplete scan blocked retry: %s", reason)
	}
	if err := d.Observe(ctx, cmd, incomplete+nmapDone); err != nil {
		t.Fatal(err)
	}
	fresh := newServiceDispatcher(st)
	if reason := fresh.Check(ctx, cmd); !strings.Contains(reason, "already completed") {
		t.Fatalf("exact repeat permitted after resume: %s", reason)
	}
	changedPort := cmd
	changedPort.Args = []string{"-n", "-Pn", "-sT", "-p", "443", "192.0.2.10"}
	if reason := fresh.Check(ctx, changedPort); reason != "" {
		t.Fatalf("new port denied: %s", reason)
	}
	changedMethod := cmd
	changedMethod.Args = []string{"-n", "-Pn", "-sS", "-p", "80", "192.0.2.10"}
	if reason := fresh.Check(ctx, changedMethod); reason != "" {
		t.Fatalf("different scan method denied: %s", reason)
	}
	fresh.vantage = func(secgate.Command) string { return "approved-foothold" }
	if reason := fresh.Check(ctx, cmd); reason != "" {
		t.Fatalf("different vantage denied: %s", reason)
	}
}

func TestFirewallDiagnosticNeedsSameVantageBaseline(t *testing.T) {
	ctx := context.Background()
	d := newServiceDispatcher(nil)
	baseline := secgate.Command{Binary: "nmap", Args: []string{"-sT", "-Pn", "-n", "-p", "80", "192.0.2.10"}}
	ack := secgate.Command{Binary: "nmap", Args: []string{"-sA", "-Pn", "-n", "-p", "80", "192.0.2.10"}}
	if reason := d.Check(ctx, ack); !strings.Contains(reason, "ordinary port baseline") {
		t.Fatalf("ACK scan before baseline = %q", reason)
	}
	if err := d.Observe(ctx, baseline, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n80/tcp filtered http\n"+nmapDone); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, ack); reason != "" {
		t.Fatalf("ACK scan after baseline denied: %s", reason)
	}
	d.vantage = func(secgate.Command) string { return "foothold" }
	if reason := d.Check(ctx, ack); !strings.Contains(reason, "ordinary port baseline") {
		t.Fatalf("worker baseline leaked to foothold: %q", reason)
	}
}

func TestProtocolRepliesPromoteOnlyMatchingUDPCandidate(t *testing.T) {
	ctx := context.Background()
	d := newServiceDispatcher(nil)
	for _, port := range []int{4500, 8443} {
		probe := secgate.Command{Binary: "nmap", Args: []string{"-sU", "-Pn", "-n", "-p", strconv.Itoa(port), "192.0.2.10"}}
		output := "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n" + strconv.Itoa(port) + "/udp open|filtered unknown\n" + nmapDone
		if err := d.Observe(ctx, probe, output); err != nil {
			t.Fatal(err)
		}
	}
	ike := secgate.Command{Binary: "ike-scan", Args: []string{"--ikev2", "--nat-t", "--nodns", "--sport=0", "--retry=1", "--timeout=1000", "192.0.2.10"}}
	ikeDone := "Ending ike-scan 1.9.6: 1 hosts scanned in 0.320 seconds (3.12 hosts/sec).  0 returned handshake; 1 returned notify\n"
	for _, output := range []string{
		"192.0.2.11\tNotify message 14 (NO-PROPOSAL-CHOSEN)\n" + ikeDone,
		"192.0.2.10\tNotify message 14 (NO-PROPOSAL-CHOSEN)\n",
		"192.0.2.10\tNotify message 14 (NO-PROPOSAL-CHOSEN)\nEnding ike-scan 1.9.6: 1 hosts scanned in 0.320 seconds (3.12 hosts/sec).  0 returned handshake; 0 returned notify\n",
	} {
		if err := d.Observe(ctx, ike, output); err != nil {
			t.Fatal(err)
		}
		state, _ := d.portState(ctx, d.key(ike, serviceEndpoint{host: "192.0.2.10", transport: "udp", port: 4500}))
		if state != "open|filtered" {
			t.Fatalf("unverified IKE output promoted port: %q", state)
		}
	}
	if err := d.Observe(ctx, ike, "192.0.2.10\tNotify message 14 (NO-PROPOSAL-CHOSEN)\n"+ikeDone); err != nil {
		t.Fatal(err)
	}
	state, _ := d.portState(ctx, d.key(ike, serviceEndpoint{host: "192.0.2.10", transport: "udp", port: 4500}))
	if state != "open" {
		t.Fatalf("IKE notify did not promote UDP/4500: %q", state)
	}
	h3 := secgate.Command{Binary: "curl", Args: []string{"--http3-only", "--include", "https://192.0.2.10:8443/"}}
	if err := d.Observe(ctx, h3, "HTTP/2 200 OK\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	state, _ = d.portState(ctx, d.key(h3, serviceEndpoint{host: "192.0.2.10", transport: "udp", port: 8443}))
	if state != "open|filtered" {
		t.Fatalf("HTTP/2 output promoted HTTP/3 port: %q", state)
	}
	if err := d.Observe(ctx, h3, "HTTP/3 200 OK\r\ncontent-type: text/plain\r\n\r\nok"); err != nil {
		t.Fatal(err)
	}
	state, _ = d.portState(ctx, d.key(h3, serviceEndpoint{host: "192.0.2.10", transport: "udp", port: 8443}))
	if state != "open" {
		t.Fatalf("HTTP/3 response did not promote UDP/8443: %q", state)
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
	if err := d.Observe(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n8080/tcp open http-proxy\n"+nmapDone); err != nil {
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
	fresh.state[serviceKey{endpoint: serviceEndpoint{host: "192.0.2.10", transport: "tcp", port: 8080}, vantage: "worker"}] = serviceState{value: "open", observedAt: time.Now().UTC()}
	if err := d.Observe(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n8080/tcp closed http-proxy\n"+nmapDone); err != nil {
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
		if err := d.Observe(ctx, probe, output+nmapDone); err != nil {
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
	if err := g.ServiceObserve(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n161/udp open|filtered snmp\n"+nmapDone); err != nil {
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
		{"dig udp only", secgate.Command{Binary: "dig", Args: []string{"@192.0.2.10", "-p", "5353", "+ignore", "example.test"}}, serviceEndpoint{"192.0.2.10", "udp", 5353}},
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

func TestDNSModesRequireEveryPossibleTransport(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want []serviceEndpoint
	}{
		{[]string{"@192.0.2.10", "example.test", "SOA"}, []serviceEndpoint{{host: "192.0.2.10", transport: "udp", port: 53}, {host: "192.0.2.10", transport: "tcp", port: 53}}},
		{[]string{"@192.0.2.10", "+ignore", "example.test"}, []serviceEndpoint{{host: "192.0.2.10", transport: "udp", port: 53}}},
		{[]string{"@192.0.2.10", "+tcp", "example.test"}, []serviceEndpoint{{host: "192.0.2.10", transport: "tcp", port: 53}}},
		{[]string{"@192.0.2.10", "+tls", "example.test"}, []serviceEndpoint{{host: "192.0.2.10", transport: "tcp", port: 853}}},
		{[]string{"@192.0.2.10", "+https", "example.test"}, []serviceEndpoint{{host: "192.0.2.10", transport: "tcp", port: 443}}},
		{[]string{"@192.0.2.10", "+http-plain-get", "example.test"}, []serviceEndpoint{{host: "192.0.2.10", transport: "tcp", port: 80}}},
		{[]string{"@192.0.2.10", "example.test", "AXFR"}, []serviceEndpoint{{host: "192.0.2.10", transport: "tcp", port: 53}}},
	} {
		got, discovery, err := serviceRequirement(secgate.Command{Binary: "dig", Args: tc.args})
		if err != nil || discovery || !slices.Equal(got, tc.want) {
			t.Errorf("dig %v requires %v, discovery=%t, err=%v; want %v", tc.args, got, discovery, err, tc.want)
		}
	}
	for _, arg := range []string{"+trace", "+tcp", "+tls", "+nohttps"} {
		args := []string{"@192.0.2.10", "+https", arg, "example.test"}
		if _, _, err := serviceRequirement(secgate.Command{Binary: "dig", Args: args}); err == nil {
			t.Errorf("ambiguous or multi-target DNS mode accepted: %v", args)
		}
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
	output := "Nmap scan report for app.example.test (192.0.2.10)\nPORT STATE SERVICE\n443/tcp open https\n" + nmapDone
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
	if err := d.Observe(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n8443/tcp open https\n"+nmapDone); err != nil {
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
	if err := d.Observe(ctx, versionScan, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n8443/tcp closed https\n"+nmapDone); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, secgate.Command{Binary: "curl", Args: []string{"https://192.0.2.10:8443/"}}); reason == "" {
		t.Fatal("closed version-scan result left the follow-on unlocked")
	}
}

func TestUDPVersionProbePromotesOnlyDiscoveredCandidate(t *testing.T) {
	ctx := context.Background()
	d := newServiceDispatcher(nil)
	version := secgate.Command{Binary: "nmap", Args: []string{"-n", "-sU", "-sV", "-p", "161", "192.0.2.10"}}
	positive := "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n161/udp open snmp\n" + nmapDone
	if err := d.Observe(ctx, version, positive); err != nil {
		t.Fatal(err)
	}
	key := d.key(version, serviceEndpoint{host: "192.0.2.10", transport: "udp", port: 161})
	if state, _ := d.portState(ctx, key); state != "" {
		t.Fatalf("version scan created first port evidence: %q", state)
	}
	discovery := secgate.Command{Binary: "nmap", Args: []string{"-n", "-sU", "-p", "161", "192.0.2.10"}}
	if err := d.Observe(ctx, discovery, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n161/udp open|filtered snmp\n"+nmapDone); err != nil {
		t.Fatal(err)
	}
	if err := d.Observe(ctx, version, positive); err != nil {
		t.Fatal(err)
	}
	if state, _ := d.portState(ctx, key); state != "open" {
		t.Fatalf("protocol response did not promote UDP state: %q", state)
	}
}

func TestServiceDispatchRejectsHiddenConnectionRoutes(t *testing.T) {
	for _, cmd := range []secgate.Command{
		{Binary: "curl", Args: []string{"-L", "https://192.0.2.10/"}},
		{Binary: "curl", Args: []string{"-sSL", "https://192.0.2.10/"}},
		{Binary: "curl", Args: []string{"--connect-to", "192.0.2.10:443:192.0.2.11:9443", "https://192.0.2.10/"}},
		{Binary: "curl", Args: []string{"--interface", "en1", "https://192.0.2.10/"}},
		{Binary: "curl", Args: []string{"--local-port=53", "https://192.0.2.10/"}},
		{Binary: "curl", Args: []string{"--resolve", "app.example.test:443:192.0.2.11", "https://app.example.test:8443/"}},
		{Binary: "curl", Args: []string{"--proxy", "192.0.2.11:8080", "https://192.0.2.10/"}},
		{Binary: "ffuf", Args: []string{"-r", "-u", "https://192.0.2.10/FUZZ"}},
		{Binary: "nmap", Args: []string{"--proxies", "http://192.0.2.11:8080", "-p", "443", "192.0.2.10"}},
		{Binary: "nmap", Args: []string{"-sV", "--source-port", "53", "-p", "443", "192.0.2.10"}},
		{Binary: "ncat", Args: []string{"--proxy", "192.0.2.11:8080", "192.0.2.10", "443"}},
		{Binary: "ncat", Args: []string{"-s192.0.2.11", "192.0.2.10", "443"}},
		{Binary: "ncat", Args: []string{"--sctp", "192.0.2.10", "2905"}},
		{Binary: "openssl", Args: []string{"s_client", "-proxy", "192.0.2.11:8080", "-connect", "192.0.2.10:443"}},
		{Binary: "openssl", Args: []string{"s_client", "-bind", "192.0.2.11:0", "-connect", "192.0.2.10:443"}},
		{Binary: "dig", Args: []string{"-b192.0.2.11", "@192.0.2.10", "example.test"}},
	} {
		if _, _, err := serviceRequirement(cmd); err == nil {
			t.Errorf("hidden route accepted: %s %v", cmd.Binary, cmd.Args)
		}
	}
}

func TestScanEvidenceRequiresCompletedNmapRun(t *testing.T) {
	d := newServiceDispatcher(nil)
	ctx := context.Background()
	probe := secgate.Command{Binary: "nmap", Args: []string{"-n", "-sT", "-p", "443", "192.0.2.10"}}
	partial := "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n443/tcp open https\n"
	if err := d.Observe(ctx, probe, partial); err != nil {
		t.Fatal(err)
	}
	request := secgate.Command{Binary: "curl", Args: []string{"https://192.0.2.10/"}}
	if reason := d.Check(ctx, request); reason == "" {
		t.Fatal("incomplete scan unlocked service")
	}
	if err := d.Observe(ctx, probe, partial+"Nmap done: 1 IP address (1 host up) scanned in 1.00 seconds\n"); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, request); reason != "" {
		t.Fatalf("complete scan did not unlock service: %s", reason)
	}
	other := newServiceDispatcher(nil)
	probe.Args = []string{"-n", "-sT", "-p", "443,invalid", "192.0.2.10"}
	if err := other.Observe(ctx, probe, partial+nmapDone); err != nil {
		t.Fatal(err)
	}
	if reason := other.Check(ctx, request); reason == "" {
		t.Fatal("unverified requested port set unlocked service")
	}
}

func TestRangeDiscoveryKeepsReportedPortAndTransport(t *testing.T) {
	d := newServiceDispatcher(nil)
	probe := secgate.Command{Binary: "nmap", Args: []string{"-n", "-sT", "-p", "64000-65000", "192.0.2.10"}}
	if err := d.Observe(context.Background(), probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n65000/tcp open unknown\n65000/udp open unknown\n"+nmapDone); err != nil {
		t.Fatal(err)
	}
	key := d.key(probe, serviceEndpoint{host: "192.0.2.10", transport: "tcp", port: 65000})
	state, err := d.portState(context.Background(), key)
	if err != nil || state != "open" {
		t.Fatalf("reported range port = %q, %v", state, err)
	}
	key.endpoint.transport = "udp"
	if state, _ := d.portState(context.Background(), key); state != "" {
		t.Fatal("unrequested UDP result became service evidence")
	}
}

func TestIPv6AndProtocolNamespacesStaySeparate(t *testing.T) {
	ctx := context.Background()
	d := newServiceDispatcher(nil)
	probe := secgate.Command{Binary: "nmap", Args: []string{"-6", "-n", "-sT", "-p", "443", "2001:db8::10"}}
	if err := d.Observe(ctx, probe, "Nmap scan report for 2001:db8::10\nPORT STATE SERVICE\n443/tcp open https\n"+nmapDone); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, secgate.Command{Binary: "curl", Args: []string{"https://[2001:db8::10]/"}}); reason != "" {
		t.Fatalf("IPv6 TCP observation denied: %s", reason)
	}
	if reason := d.Check(ctx, secgate.Command{Binary: "curl", Args: []string{"--http3-only", "https://[2001:db8::10]/"}}); reason == "" {
		t.Fatal("IPv6 TCP observation authorized UDP/443")
	}
	other := newServiceDispatcher(nil)
	if err := other.Observe(ctx, secgate.Command{Binary: "nmap", Args: []string{"-sY", "-p", "2905", "192.0.2.10"}}, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n2905/sctp open m3ua\n"+nmapDone); err != nil {
		t.Fatal(err)
	}
	if reason := other.Check(ctx, secgate.Command{Binary: "nc", Args: []string{"192.0.2.10", "2905"}}); reason == "" {
		t.Fatal("SCTP observation authorized TCP/2905")
	}
}

func TestDiagnosticScanDoesNotAuthorizeServiceFollowUp(t *testing.T) {
	for _, flags := range [][]string{
		{"-sA"}, {"-sF"}, {"-sN"}, {"-sX"}, {"-sI", "192.0.2.12"},
		{"-sS", "--source-port", "53"}, {"-sS", "-f"}, {"-sS", "-D", "192.0.2.12"}, {"-sS", "-e", "en1"},
	} {
		d := newServiceDispatcher(nil)
		args := append([]string{"-n", "-p", "443"}, flags...)
		args = append(args, "192.0.2.10")
		probe := secgate.Command{Binary: "nmap", Args: args}
		output := "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n443/tcp open https\n" + nmapDone
		if err := d.Observe(context.Background(), probe, output); err != nil {
			t.Fatal(err)
		}
		if reason := d.Check(context.Background(), secgate.Command{Binary: "curl", Args: []string{"https://192.0.2.10/"}}); reason == "" {
			t.Fatalf("diagnostic scan %v authorized a follow-up", flags)
		}
	}
}

func TestNpingPacketReplyDoesNotAuthorizeServiceFollowUp(t *testing.T) {
	ctx := context.Background()
	d := newServiceDispatcher(nil)
	probe := secgate.Command{Binary: "nping", Args: []string{"--tcp", "--flags", "syn", "-c", "1", "--rate", "1", "-p", "443", "192.0.2.10"}}
	if err := d.Observe(ctx, probe, "SENT TCP 192.0.2.10:443\nRCVD TCP SYN/ACK from 192.0.2.10:443\n"); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, secgate.Command{Binary: "curl", Args: []string{"https://192.0.2.10/"}}); reason == "" {
		t.Fatal("packet diagnostic created service evidence")
	}
}

func TestNpingPayloadRequiresDiscoveredUDPPort(t *testing.T) {
	ctx := context.Background()
	d := newServiceDispatcher(nil)
	probe := secgate.Command{Binary: "nping", Args: []string{"--udp", "--data", "0x00000000aabb", "-c", "1", "--rate", "1", "-p", "4500", "192.0.2.10"}}
	endpoints, discovery, err := serviceRequirement(probe)
	if err != nil || discovery || len(endpoints) != 1 || endpoints[0] != (serviceEndpoint{host: "192.0.2.10", transport: "udp", port: 4500}) {
		t.Fatalf("payload prerequisite = %v, discovery=%t, err=%v", endpoints, discovery, err)
	}
	if reason := d.Check(ctx, probe); reason == "" {
		t.Fatal("protocol payload ran without UDP discovery")
	}
	plain := secgate.Command{Binary: "nping", Args: []string{"--udp", "-c", "1", "--rate", "1", "-p", "4500", "192.0.2.10"}}
	if reason := d.Check(ctx, plain); reason != "" {
		t.Fatalf("bounded UDP discovery denied: %s", reason)
	}
	nmap := secgate.Command{Binary: "nmap", Args: []string{"-n", "-sU", "-p", "4500", "192.0.2.10"}}
	if err := d.Observe(ctx, nmap, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n4500/udp open|filtered ipsec-nat-t\n"+nmapDone); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, probe); reason != "" {
		t.Fatalf("observed UDP candidate did not unlock protocol payload: %s", reason)
	}
}

func TestSourcePortCandidateOnlyUnlocksBoundedHTTPValidation(t *testing.T) {
	ctx := context.Background()
	d := newServiceDispatcher(nil)
	request := secgate.Command{Binary: "curl", Args: []string{
		"-q", "--silent", "--show-error", "--include", "--noproxy", "*",
		"--connect-timeout", "3", "--max-time", "8", "--local-port", "53",
		"http://192.0.2.10:8080/",
	}}
	if reason := d.Check(ctx, request); reason == "" {
		t.Fatal("source-port HTTP request ran without discovery")
	}
	probe := secgate.Command{Binary: "nmap", Args: []string{"-sS", "-Pn", "-n", "--source-port", "53", "-p", "8080", "192.0.2.10"}}
	output := "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n8080/tcp open http\n" + nmapDone
	if err := d.Observe(ctx, probe, output); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, request); reason != "" {
		t.Fatalf("source-port candidate did not allow HTTP validation: %s", reason)
	}
	if reason := d.Check(ctx, secgate.Command{Binary: "curl", Args: []string{"http://192.0.2.10:8080/"}}); reason == "" {
		t.Fatal("source-port candidate authorized ordinary route")
	}
	other := request
	other.Args = append([]string(nil), request.Args...)
	other.Args[len(other.Args)-2] = "54"
	if reason := d.Check(ctx, other); reason == "" {
		t.Fatal("source-port candidate authorized another source port")
	}
	unsafe := request
	unsafe.Args = append([]string(nil), request.Args...)
	unsafe.Args = append(unsafe.Args[:len(unsafe.Args)-1], "-X", "POST", unsafe.Args[len(unsafe.Args)-1])
	if reason := d.Check(ctx, unsafe); reason == "" {
		t.Fatal("source-port discovery admitted a state-changing request")
	}
	if err := d.Observe(ctx, request, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	key := d.key(request, serviceEndpoint{host: "192.0.2.10", transport: "tcp", port: 8080})
	if state, _ := d.portState(ctx, key); state != "open" {
		t.Fatalf("HTTP response did not confirm the source-port route: %q", state)
	}
}

func TestSourcePortEvidenceSurvivesResumeWithoutWideningRoute(t *testing.T) {
	ctx := context.Background()
	store := openStore(t)
	if _, err := store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Kind: "recon", Status: engagement.StatusActive}}}); err != nil {
		t.Fatal(err)
	}
	probe := secgate.Command{TaskID: "t1", Surface: secgate.SurfaceNetwork, Binary: "nmap", Args: []string{"-sS", "-Pn", "-n", "--source-port", "53", "-p", "8080", "192.0.2.10"}}
	if err := newServiceDispatcher(store).Observe(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n8080/tcp open http\n"+nmapDone); err != nil {
		t.Fatal(err)
	}
	fresh := newServiceDispatcher(store)
	request := secgate.Command{Surface: secgate.SurfaceNetwork, Binary: "curl", Args: []string{
		"-q", "--silent", "--show-error", "--include", "--noproxy", "*",
		"--connect-timeout", "3", "--max-time", "8", "--local-port", "53", "http://192.0.2.10:8080/",
	}}
	if reason := fresh.Check(ctx, request); reason != "" {
		t.Fatalf("resumed source-port validation denied: %s", reason)
	}
	if reason := fresh.Check(ctx, secgate.Command{Binary: "curl", Args: []string{"http://192.0.2.10:8080/"}}); reason == "" {
		t.Fatal("resumed source-port candidate widened to ordinary route")
	}
	rows, err := store.Surfaces(ctx, engagement.SurfaceFilter{Asset: "192.0.2.10", Kind: "service-port", Name: "tcp/8080"})
	if err != nil || len(rows) != 1 || !strings.Contains(string(rows[0].Detail), `"source_port":"53"`) {
		t.Fatalf("source-port provenance not stored: %+v %v", rows, err)
	}
}

func TestHTTP3RequiresUDPEvidence(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want []serviceEndpoint
	}{
		{[]string{"--http3-only", "https://192.0.2.10:8443/"}, []serviceEndpoint{{host: "192.0.2.10", transport: "udp", port: 8443}}},
		{[]string{"--http3", "https://192.0.2.10:8443/"}, []serviceEndpoint{{host: "192.0.2.10", transport: "tcp", port: 8443}, {host: "192.0.2.10", transport: "udp", port: 8443}}},
	} {
		got, discovery, err := serviceRequirement(secgate.Command{Binary: "curl", Args: tc.args})
		if err != nil || discovery || !slices.Equal(got, tc.want) {
			t.Fatalf("%v requires %v, discovery=%t, err=%v; want %v", tc.args, got, discovery, err, tc.want)
		}
	}
}

func TestCurlResolveNeedsConnectedAddressEvidence(t *testing.T) {
	ctx := context.Background()
	d := newServiceDispatcher(nil)
	cmd := secgate.Command{Binary: "curl", Args: []string{"--resolve", "app.example.test:443:192.0.2.10", "https://app.example.test/"}}
	endpoints, discovery, err := serviceRequirement(cmd)
	if err != nil || discovery || len(endpoints) != 1 || endpoints[0] != (serviceEndpoint{host: "192.0.2.10", transport: "tcp", port: 443}) {
		t.Fatalf("resolved endpoint = %v, discovery=%t, err=%v", endpoints, discovery, err)
	}
	hosts, _, ok := secgate.ExtractTargetSet(cmd)
	if !ok || !slices.Contains(hosts, "app.example.test") || !slices.Contains(hosts, "192.0.2.10") {
		t.Fatalf("scope targets = %v, ok=%t", hosts, ok)
	}
	scope, err := secgate.ParseScope(strings.NewReader("app.example.test\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, violated := secgate.ScopeViolation(scope, cmd); !violated {
		t.Fatal("unapproved resolved IP passed the scope gate")
	}
	probe := secgate.Command{Binary: "nmap", Args: []string{"-n", "-sT", "-p", "443", "192.0.2.10"}}
	if err := d.Observe(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n443/tcp open https\n"+nmapDone); err != nil {
		t.Fatal(err)
	}
	if reason := d.Check(ctx, cmd); reason != "" {
		t.Fatalf("observed connected IP stayed blocked: %s", reason)
	}
	for _, args := range [][]string{
		{"--resolve", "app.example.test:443:192.0.2.10,192.0.2.11", "https://app.example.test/"},
		{"--resolve", "+app.example.test:443:192.0.2.10", "https://app.example.test/"},
		{"--resolve", "*:443:192.0.2.10", "https://app.example.test/"},
		{"--resolve", "app.example.test:443:other.example.test", "https://app.example.test/"},
		{"--resolve", "app.example.test:443:192.0.2.10", "https://app.example.test/", "https://other.example.test/"},
	} {
		if _, _, err := serviceRequirement(secgate.Command{Binary: "curl", Args: args}); err == nil {
			t.Errorf("unverifiable --resolve accepted: %v", args)
		}
	}
}

func TestEngagementGateAllowsScopedCurlResolveAfterDiscovery(t *testing.T) {
	ctx := context.Background()
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if _, err := ws.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Kind: "recon", Status: engagement.StatusActive}}}); err != nil {
		t.Fatal(err)
	}
	scope, err := secgate.ParseScope(strings.NewReader("app.example.test\n192.0.2.10\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := buildEngageGate(ws, scope, secgate.Auto, nil, nil, t.TempDir(), gatePolicy{}, nil)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	cmd := secgate.Command{TaskID: "t1", Binary: "curl", Args: []string{"--resolve", "app.example.test:443:192.0.2.10", "https://app.example.test/"}, Surface: secgate.SurfaceNetwork, Phase: secgate.PhaseRecon}
	if d := g.Authorize(ctx, cmd); d.Allowed || !strings.Contains(d.Reason, "service dispatch") {
		t.Fatalf("unobserved resolved address verdict = %+v", d)
	}
	probe := secgate.Command{TaskID: "t1", Binary: "nmap", Args: []string{"-n", "-Pn", "-sT", "-p", "443", "192.0.2.10"}, Surface: secgate.SurfaceNetwork, Phase: secgate.PhaseRecon}
	if err := g.ServiceObserve(ctx, probe, "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n443/tcp open https\n"+nmapDone); err != nil {
		t.Fatal(err)
	}
	if d := g.Authorize(ctx, cmd); !d.Allowed {
		t.Fatalf("scoped resolved address denied: %+v", d)
	}
}

func TestServiceEvidenceStaysOnItsVantage(t *testing.T) {
	ctx := context.Background()
	store := openStore(t)
	if _, err := store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Kind: "recon", Status: engagement.StatusActive}}}); err != nil {
		t.Fatal(err)
	}
	foothold := &secgate.Foothold{Host: "192.0.2.20", Transport: "ssh", Session: "one", Surfaces: []secgate.Surface{secgate.SurfaceNetwork}}
	gate := &secgate.Gate{Policy: &secgate.Policy{}, AttachedFoothold: foothold}
	attachServiceDispatcher(gate, store)
	probe := secgate.Command{TaskID: "t1", Surface: secgate.SurfaceNetwork, Binary: "nmap", Args: []string{"-n", "-sT", "-p", "443", "192.0.2.10"}}
	output := "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE\n443/tcp open https\n" + nmapDone
	if err := gate.ServiceObserve(ctx, probe, output); err != nil {
		t.Fatal(err)
	}
	request := secgate.Command{Binary: "curl", Args: []string{"https://192.0.2.10/"}, Surface: secgate.SurfaceNetwork}
	if reason := gate.ServiceCheck(ctx, request); reason != "" {
		t.Fatalf("same foothold observation denied: %s", reason)
	}
	request.Surface = secgate.SurfaceWeb
	if reason := gate.ServiceCheck(ctx, request); reason == "" {
		t.Fatal("foothold observation authorized worker web request")
	}
	gate.AttachedFoothold = &secgate.Foothold{Host: foothold.Host, Transport: foothold.Transport, Session: "two", Surfaces: foothold.Surfaces}
	attachServiceDispatcher(gate, store)
	request.Surface = secgate.SurfaceNetwork
	if reason := gate.ServiceCheck(ctx, request); reason == "" {
		t.Fatal("previous carrier observation authorized a different session")
	}
	gate.AttachedFoothold = foothold
	attachServiceDispatcher(gate, store)
	if reason := gate.ServiceCheck(ctx, request); reason != "" {
		t.Fatalf("persisted observation lost its carrier: %s", reason)
	}
	gate.Policy = nil
	gate.AttachedFoothold = nil
	attachServiceDispatcher(gate, store)
	if err := gate.ServiceObserve(ctx, probe, output); err != nil {
		t.Fatal(err)
	}
	web := secgate.Command{Binary: "web-api:GET", Args: []string{"https://192.0.2.10/"}, Surface: secgate.SurfaceWeb}
	if reason := gate.ServiceCheck(ctx, web); reason == "" {
		t.Fatal("worker scan authorized a web broker request")
	}
}

func TestOldServiceObservationRequiresRediscovery(t *testing.T) {
	d := newServiceDispatcher(nil)
	request := secgate.Command{Binary: "curl", Args: []string{"https://192.0.2.10/"}}
	key := d.key(request, serviceEndpoint{host: "192.0.2.10", transport: "tcp", port: 443})
	d.state[key] = serviceState{value: "open", observedAt: time.Now().Add(-serviceEvidenceTTL - time.Minute)}
	if reason := d.Check(context.Background(), request); reason == "" {
		t.Fatal("stale port observation authorized a follow-up")
	}
	d.state[key] = serviceState{value: "open", observedAt: time.Now()}
	if reason := d.Check(context.Background(), request); reason != "" {
		t.Fatalf("fresh observation denied: %s", reason)
	}
	store := openStore(t)
	if _, err := store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Kind: "recon", Status: engagement.StatusActive}}}); err != nil {
		t.Fatal(err)
	}
	id, err := store.RecordEvidence("t1", "stale scan output")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveSurface(context.Background(), engagement.SurfaceRecord{
		ID: serviceRecordID(key), TaskID: "t1", Surface: engagement.SurfaceNetwork,
		Asset: key.endpoint.host, Kind: "service-port", Name: "tcp/443", Value: "open", Source: "nmap", EvidenceID: id,
		ObservedAt: time.Now().Add(-serviceEvidenceTTL - time.Minute).UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}
	if reason := newServiceDispatcher(store).Check(context.Background(), request); reason == "" {
		t.Fatal("stale persisted port observation authorized a follow-up")
	}
}

func TestWebPortDiscoveryUsesConfiguredLoopbackProxy(t *testing.T) {
	targets := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Errorf("proxy received %s, want CONNECT", r.Method)
		}
		targets <- r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	t.Setenv("BLKCHAIN_WEB_PROXY", strings.TrimPrefix(proxy.URL, "http://"))
	scope, err := secgate.ParseScope(strings.NewReader("127.0.0.2\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &secgate.Gate{Scope: scope}
	if probeWebEndpoint(context.Background(), g, serviceEndpoint{host: "127.0.0.2", transport: "tcp", port: 8443}) {
		t.Fatal("proxy-only reachability authorized the worker web path")
	}
	if target := <-targets; target != "127.0.0.2:8443" {
		t.Fatalf("proxy target = %q", target)
	}
}
