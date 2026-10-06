package main

import (
	"os"
	"slices"
	"strings"
	"testing"

	"blkchain/cli/internal/secgate"
)

// infrastructurePackages are packages.list entries that provide no
// model-runnable binary, so the catalog does not claim them: bash and python3
// are denied interpreters that the runner itself uses (execute.py runs the
// worker's commands), and iptables writes the guard's firewall.
var infrastructurePackages = map[string]string{
	"bash":     "the runner's own shell; the classifier denies it as a command",
	"python3":  "runs execute.py, the worker's command shim; the classifier denies it as a command",
	"iptables": "writes the network guard's allowlist firewall",
}

func readPackagesList(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("runner/packages.list")
	if err != nil {
		t.Fatalf("cannot read the package list: %v", err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if cut := strings.Index(line, "#"); cut >= 0 {
			line = line[:cut]
		}
		if p := strings.TrimSpace(line); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// TestCatalogPackagesMatchPackagesList asserts both directions: a catalog tool
// cannot name a package the image does not install, and a package cannot be
// installed without a catalog entry or a recorded infrastructure reason. The
// second direction is what stops the image growing tools no persona can use.
func TestCatalogPackagesMatchPackagesList(t *testing.T) {
	declared := readPackagesList(t)
	for _, p := range catalogPackages() {
		if !slices.Contains(declared, p) {
			t.Errorf("catalog requires package %q, which packages.list does not declare", p)
		}
	}
	for _, p := range declared {
		if slices.Contains(catalogPackages(), p) {
			continue
		}
		if _, ok := infrastructurePackages[p]; ok {
			continue
		}
		t.Errorf("packages.list declares %q, which no catalog tool claims and infrastructurePackages does not explain", p)
	}
}

// TestEveryCatalogToolHasAnAuditRecord asserts no tool can sit in the catalog
// without its flag surface either audited or the outstanding audit written
// down. It is what keeps the pending work visible instead of forgotten.
func TestEveryCatalogToolHasAnAuditRecord(t *testing.T) {
	for _, tl := range toolCatalog {
		note, _ := auditStatus(tl.Binary)
		if strings.TrimSpace(note) == "" {
			t.Errorf("%s has no audit record: add it to auditedBinaries or pendingAudits", tl.Binary)
		}
	}
	for b := range auditedBinaries {
		if _, ok := toolFor(b); !ok {
			t.Errorf("auditedBinaries records %q, which is not in the catalog", b)
		}
	}
	for b := range pendingAudits {
		if _, ok := toolFor(b); !ok {
			t.Errorf("pendingAudits records %q, which is not in the catalog", b)
		}
	}
	for b := range auditedBinaries {
		if _, ok := pendingAudits[b]; ok {
			t.Errorf("%q is recorded as both audited and pending", b)
		}
	}
}

// TestExternalAllowlistCarriesOnlyAuditedEnumTools asserts the allowlist
// contract: an allowlist entry authorizes a binary's whole flag surface, so only
// an audited tierEnum tool may be on it. A tierLocal tool is excluded because in
// external Auto a read utility with an in-scope host operand and a file operand
// would disclose that file; a tierExploit tool is excluded so it can only run
// armed and confirmed.
func TestExternalAllowlistCarriesOnlyAuditedEnumTools(t *testing.T) {
	al := secgate.NewAllowlist(externalEngageAllowlist()...)
	for _, tl := range toolCatalog {
		_, audited := auditStatus(tl.Binary)
		want := tl.Tier == tierEnum && tl.Reach == reachExternal && audited
		if got := al.Permits(tl.Binary); got != want {
			t.Errorf("allowlist permits %s = %t, want %t (tier=%d reach=%d audited=%t)",
				tl.Binary, got, want, tl.Tier, tl.Reach, audited)
		}
	}
}

// TestExploitToolsNeverRunUnattended asserts no exploit-tier binary can be
// reached by the unattended path, whatever the operator's config says, because
// the allowlist the composition root builds comes from the catalog.
func TestExploitToolsNeverRunUnattended(t *testing.T) {
	al := secgate.NewAllowlist(externalEngageAllowlist()...)
	exploit := exploitToolBinaries()
	if len(exploit) == 0 {
		t.Fatal("the catalog declares no exploit-tier tool, so this test proves nothing")
	}
	for _, b := range exploit {
		if al.Permits(b) {
			t.Errorf("exploit-tier %s must not be on the unattended allowlist", b)
		}
	}
}

// TestLocalReachToolsStayOffTheExternalAllowlist pins two controls at once. The
// external profile denies a command with no verifiable target, so a tool with no
// network destination could never run there anyway; and keeping read utilities
// off the list closes the file-disclosure path, where an in-scope host operand
// passes the scope check while a file operand is read.
func TestLocalReachToolsStayOffTheExternalAllowlist(t *testing.T) {
	al := secgate.NewAllowlist(externalEngageAllowlist()...)
	local := localReachBinaries()
	if len(local) == 0 {
		t.Fatal("the catalog declares no local-reach tool, so this test proves nothing")
	}
	for _, b := range local {
		if al.Permits(b) {
			t.Errorf("local-reach %s must not be on the external allowlist", b)
		}
	}
}

// TestPersonaPromptsAvoidUnusableTools asserts no persona is told to run a tool
// the image cannot run, or one that is present but must not be used. Every name
// checked here is a distinctive token, so a match is a real instruction rather
// than an English word.
func TestPersonaPromptsAvoidUnusableTools(t *testing.T) {
	for name, d := range domains {
		for binary, reason := range unavailableTools {
			if strings.Contains(d.Prompt, binary) {
				t.Errorf("the %s prompt names %s, which the image does not ship: %s", name, binary, reason)
			}
		}
		for binary, reason := range discouragedTools {
			if strings.Contains(d.Prompt, binary) {
				t.Errorf("the %s prompt names %s, which must not be used: %s", name, binary, reason)
			}
		}
	}
	// The container persona is not in the domains map; check it by hand.
	for binary := range unavailableTools {
		if strings.Contains(containerPersona.Prompt, binary) {
			t.Errorf("the container prompt names %s, which the image does not ship", binary)
		}
	}
	for binary := range discouragedTools {
		if strings.Contains(containerPersona.Prompt, binary) {
			t.Errorf("the container prompt names %s, which must not be used", binary)
		}
	}
}

// TestPersonaPromptsAvoidUnauditedTools asserts no persona is told to run a tool
// whose flag surface is not audited yet. Such a tool is off the allowlist, so
// naming it would produce a command the gate denies.
func TestPersonaPromptsAvoidUnauditedTools(t *testing.T) {
	for binary := range pendingAudits {
		tl, ok := toolFor(binary)
		if !ok || tl.Reach != reachExternal || tl.Tier != tierEnum {
			continue // exploit-tier and local-reach tools are not allowlist-gated
		}
		for name, d := range domains {
			for _, p := range tl.Personas {
				if p == name && strings.Contains(d.Prompt, binary) {
					t.Errorf("the %s prompt names %s, whose audit is incomplete: %s",
						name, binary, pendingAudits[binary])
				}
			}
		}
	}
}

// TestCatalogIsInternallyConsistent asserts the catalog itself is well formed: no
// duplicate binary, every tool claimed by at least one persona, and every
// persona named by a tool is a registered domain.
func TestCatalogIsInternallyConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, tl := range toolCatalog {
		if seen[tl.Binary] {
			t.Errorf("duplicate catalog entry for %s", tl.Binary)
		}
		seen[tl.Binary] = true
		if len(tl.Personas) == 0 {
			t.Errorf("%s is catalogued but no persona claims it", tl.Binary)
		}
		for _, p := range tl.Personas {
			// containerPersona is deliberately not in the domains map: registering it
			// would make route_skill treat "container" as a persona name and stop the
			// container keyword resolving to the k8s skill bucket.
			if _, ok := domains[p]; !ok && p != containerPersona.Name {
				t.Errorf("%s names persona %q, which is not a registered domain", tl.Binary, p)
			}
		}
	}
}

// TestRawSocketRouting is two-sided: a tool that needs CAP_NET_RAW routes to the
// raw worker, and everything else stays in the general unprivileged worker. The
// routing reads the catalog and argv only, so no prompt or corpus text can move
// a command into the privileged worker.
func TestRawSocketRouting(t *testing.T) {
	raw := []struct {
		binary string
		args   []string
	}{
		{"masscan", []string{"-p80", "127.0.0.1"}},
		{"masscan", nil},
		{"tcpdump", []string{"-c", "1"}},
		{"nmap", []string{"-sS", "-p", "80", "192.0.2.1"}},
		{"nmap", []string{"-sU", "-p", "161", "192.0.2.1"}},
		{"nmap", []string{"-O", "192.0.2.1"}},
		{"nmap", []string{"--traceroute", "-p", "80", "192.0.2.1"}},
	}
	for _, c := range raw {
		if !rawSocketCommand(c.binary, c.args) {
			t.Errorf("%s %v should route to the raw-socket worker", c.binary, c.args)
		}
	}
	general := []struct {
		binary string
		args   []string
	}{
		{"nmap", []string{"-sT", "-p", "80", "192.0.2.1"}},
		{"nmap", []string{"-p", "80", "192.0.2.1"}},
		{"nmap", []string{"-sV", "--top-ports", "100", "192.0.2.1"}},
		{"curl", []string{"http://192.0.2.1/"}},
		{"smbclient", []string{"-L", "192.0.2.1"}},
		{"ffuf", []string{"-u", "http://192.0.2.1/FUZZ", "-w", "words"}},
		{"id", nil},
		{"socat", []string{"-", "TCP:192.0.2.1:80"}},
		// A binary with no catalog entry never reaches the privileged worker.
		{"sh", []string{"-c", "nmap -sS 192.0.2.1"}},
		{"unknown-tool", []string{"-sS"}},
	}
	for _, c := range general {
		if rawSocketCommand(c.binary, c.args) {
			t.Errorf("%s %v should stay in the general unprivileged worker", c.binary, c.args)
		}
	}
}
