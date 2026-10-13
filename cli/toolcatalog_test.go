package main

import (
	"context"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

// catalogPackages returns the distinct apk packages the catalog requires, in
// sorted order. It is the set packages.list must declare.
func catalogPackages() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range toolCatalog {
		if t.Package == "" || seen[t.Package] {
			continue
		}
		seen[t.Package] = true
		out = append(out, t.Package)
	}
	sort.Strings(out)
	return out
}

// localReachBinaries returns the binaries with no network destination:
// host-introspection, analysis and offline tools the LOCAL profile runs under
// per-command confirmation.
func localReachBinaries() []string {
	var out []string
	for _, t := range toolCatalog {
		if t.Reach == reachLocal {
			out = append(out, t.Binary)
		}
	}
	sort.Strings(out)
	return out
}

// exploitToolBinaries returns the tierExploit binaries: the code-owned default
// exploit-tier catalog that the operator's exploit_tools extends. None of them
// may appear in an unattended allowlist.
func exploitToolBinaries() []string {
	var out []string
	for _, t := range toolCatalog {
		if t.Tier == tierExploit {
			out = append(out, t.Binary)
		}
	}
	sort.Strings(out)
	return out
}

// infrastructurePackages are packages.list entries that provide no model-runnable binary, so the catalog does not claim them: bash and python3 are denied interpreters that the runner itself uses (execute.py runs the worker's commands), iptables writes the guard's firewall, and openssh-client is the foothold carrier.
var infrastructurePackages = map[string]string{
	"bash":           "the runner's own shell; the classifier denies it as a command",
	"python3":        "runs execute.py, the worker's command shim; the classifier denies it as a command",
	"iptables":       "writes the network guard's allowlist firewall",
	"openssh-client": "the ssh foothold carrier, invoked only by the code-built transport in foothold.go and absent from the catalog so the model cannot reach it",
	"nmap-nselibs":   "nmap's service detection and script runtime data",
	"nmap-scripts":   "nmap's packaged scripts for bounded service enumeration",
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

// TestCatalogPackagesMatchPackagesList asserts both directions: a catalog tool cannot name a package the image does not install, and a package cannot be installed without a catalog entry or a recorded infrastructure reason. The second direction is what stops the image growing tools no persona can use.
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

// TestEveryCatalogToolHasAnAuditRecord asserts no tool can sit in the catalog without its flag surface either audited or the outstanding audit written down. It is what keeps the pending work visible instead of forgotten.
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

// TestExternalAllowlistCarriesOnlyAuditedNetworkTools asserts the allowlist contract: an entry authorizes a binary's whole flag surface, so only an audited tool may be on it, and only one that addresses a network destination. Both tiers belong on it, because this list is the gate's reachability control and not its autonomy control; TestExploitPhaseAlwaysConfirms covers the control that actually keeps an exploit tool attended.
func TestExternalAllowlistCarriesOnlyAuditedNetworkTools(t *testing.T) {
	al := secgate.NewAllowlist(externalEngageAllowlist()...)
	for _, tl := range toolCatalog {
		_, audited := auditStatus(tl.Binary)
		want := (tl.Reach == reachExternal || tl.Reach == reachScratch) && audited
		if got := al.Permits(tl.Binary); got != want {
			t.Errorf("allowlist permits %s = %t, want %t (tier=%d reach=%d audited=%t)",
				tl.Binary, got, want, tl.Tier, tl.Reach, audited)
		}
	}
}

// A scratch-reach tool is on the external allowlist, so a pivot can run it; a local-reach tool is not, which keeps the file-disclosure path closed.
func TestScratchReachToolsAreOnTheExternalAllowlistAndLocalOnesAreNot(t *testing.T) {
	al := secgate.NewAllowlist(externalEngageAllowlist()...)
	scratch := scratchReachBinaries()
	if len(scratch) == 0 {
		t.Fatal("the catalog declares no scratch-reach tool, so this test proves nothing")
	}
	for _, b := range scratch {
		if !al.Permits(b) {
			t.Errorf("scratch-reach %s must be on the external allowlist", b)
		}
		if _, audited := auditStatus(b); !audited {
			t.Errorf("scratch-reach %s reaches the allowlist without a recorded audit", b)
		}
	}
	for _, b := range localReachBinaries() {
		if al.Permits(b) {
			t.Errorf("local-reach %s must not be on the external allowlist", b)
		}
	}
}

// TestExploitPhaseAlwaysConfirms pins the control that keeps an exploit-tier tool attended. It is the phase, not the allowlist: an exploit or post-ex command is confirmed whatever the mode, while a recon command on an audited enum tool runs unattended in Auto. Keeping exploit tools off the allowlist instead would make them unreachable rather than merely attended.
func TestExploitPhaseAlwaysConfirms(t *testing.T) {
	if len(exploitToolBinaries()) == 0 {
		t.Fatal("the catalog declares no exploit-tier tool, so this test proves nothing")
	}
	scope, err := secgate.ParseScope(strings.NewReader("192.0.2.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	newGate := func(c *countingConfirmer) *secgate.Gate {
		g := &secgate.Gate{
			Mode:    secgate.Auto,
			Scope:   scope,
			Allow:   secgate.NewAllowlist(externalEngageAllowlist()...),
			Confirm: c,
		}
		g.Start()
		return g
	}

	recon := &countingConfirmer{ok: true}
	d := newGate(recon).Authorize(context.Background(), secgate.Command{
		Binary: "nmap", Args: []string{"-p", "80", "-n", "192.0.2.10"}, Phase: secgate.PhaseRecon})
	if !d.Allowed {
		t.Fatalf("a recon command on an audited enum tool should run: %s", d.Reason)
	}
	if recon.calls.Load() != 0 {
		t.Errorf("a recon command in Auto was confirmed %d times, want 0", recon.calls.Load())
	}

	for _, phase := range []secgate.Phase{secgate.PhaseExploit, secgate.PhasePostEx} {
		exploit := &countingConfirmer{ok: true}
		d := newGate(exploit).Authorize(context.Background(), secgate.Command{
			Binary: "secretsdump.py", Args: []string{"CORP/svc:p@192.0.2.10"},
			Phase: phase, Armed: true})
		if !d.Allowed {
			t.Fatalf("an armed %s command on an audited exploit tool should run: %s", phase, d.Reason)
		}
		if exploit.calls.Load() != 1 {
			t.Errorf("an armed %s command was confirmed %d times, want 1", phase, exploit.calls.Load())
		}
	}

	// Unarmed, the same command is refused outright.
	unarmed := &countingConfirmer{ok: true}
	d = newGate(unarmed).Authorize(context.Background(), secgate.Command{
		Binary: "secretsdump.py", Args: []string{"CORP/svc:p@192.0.2.10"},
		Phase: secgate.PhaseExploit})
	if d.Allowed {
		t.Error("an unarmed exploit command must be denied")
	}
}

// TestExploitToolsAreInTheExploitTierCatalog asserts the second allowlist an exploit command must pass: the executor's own per-finding catalog. A tool missing from it is denied even when armed and confirmed.
func TestExploitToolsAreInTheExploitTierCatalog(t *testing.T) {
	task := engagement.Task{ID: "t1", Kind: "exploit", Phase: engagement.PhaseExploit, Objective: "validate the finding"}
	for _, b := range exploitToolBinaries() {
		if _, audited := auditStatus(b); !audited {
			continue
		}
		if !exploitToolPermitted(task, b) {
			t.Errorf("audited exploit tool %s is not on the per-finding exploit-tier catalog", b)
		}
	}
	if exploitToolPermitted(task, "bash") {
		t.Error("the exploit-tier catalog must not permit a shell")
	}
}

// TestLocalReachToolsStayOffTheExternalAllowlist pins two controls at once. The external profile denies a command with no verifiable target, so a tool with no network destination could never run there anyway; and keeping read utilities off the list closes the file-disclosure path, where an in-scope host operand passes the scope check while a file operand is read.
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

// The personas that meet dependency and image material point at the one persona that owns the scanners, and none of them describes the scanners itself.
func TestScannerGuidanceLivesInOnePersona(t *testing.T) {
	referring := map[string]string{
		"k8s":             domains["k8s"].Prompt,
		"target-analysis": domains["target-analysis"].Prompt,
		"container":       containerPersonaPrompt,
	}
	for name, prompt := range referring {
		if prompt == "" {
			t.Fatalf("persona %q has no prompt", name)
		}
		if !strings.Contains(prompt, "vuln-analysis") {
			t.Errorf("the %s prompt does not point at the vuln-analysis persona", name)
		}
		for _, binary := range scratchReachBinaries() {
			if strings.Contains(prompt, binary) {
				t.Errorf("the %s prompt describes %s itself; that guidance belongs to vuln-analysis only", name, binary)
			}
		}
	}
	owner := domains["vuln-analysis"].Prompt
	if owner == "" {
		t.Fatal("the vuln-analysis persona is not registered")
	}
	for _, binary := range scratchReachBinaries() {
		if !strings.Contains(owner, binary) {
			t.Errorf("the vuln-analysis prompt does not name %s", binary)
		}
	}
	if !strings.Contains(owner, "store vulns") {
		t.Error("the vuln-analysis prompt does not say how to read the stored advisories")
	}
	if !strings.Contains(owner, "code-owned") || !strings.Contains(owner, "read-only cache") {
		t.Error("the vuln-analysis prompt does not describe automatic offline scans")
	}
}

// A vuln-analysis task derives a surface the external profile can run, so the persona works from a pivot rather than only under a local scope.
func TestVulnAnalysisKindDerivesAnExternalProfileSurface(t *testing.T) {
	task := engagement.Task{ID: "v1", Kind: "vuln-analysis", Target: "image.tar",
		Objective: "scan the staged image", DoneWhen: "advisories recorded", Status: engagement.StatusTodo}
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if _, err := ws.Store.Apply(engagement.Delta{Kind: "plan", Detail: "seed", Upserts: []engagement.Task{task}}); err != nil {
		t.Fatal(err)
	}
	got, err := ws.Store.GetTask("v1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Surface == engagement.SurfaceLocal {
		t.Error("a vuln-analysis task derives the local surface, which needs a local scope directive")
	}
	if got.Phase != engagement.PhaseRecon {
		t.Errorf("phase = %q, want recon", got.Phase)
	}
	if domainForTask(got).Name != "vuln-analysis" {
		t.Errorf("the task resolves to persona %q", domainForTask(got).Name)
	}
}

// TestPersonaPromptsAvoidUnusableTools asserts no persona is told to run a tool the image cannot run, or one that is present but must not be used. Every name checked here is a distinctive token, so a match is a real instruction rather than an English word.
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

// TestPersonaPromptsAvoidUnauditedTools asserts no persona is told to run a tool whose flag surface is not audited yet. Such a tool is off the allowlist, so naming it would produce a command the gate denies.
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

// TestCatalogIsInternallyConsistent asserts the catalog itself is well formed: no duplicate binary, every tool claimed by at least one persona, and every persona named by a tool is a registered domain.
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
			// containerPersona is deliberately not in the domains map: registering it would make route_skill treat "container" as a persona name and stop the container keyword resolving to the k8s skill bucket.
			if _, ok := domains[p]; !ok && p != containerPersona.Name {
				t.Errorf("%s names persona %q, which is not a registered domain", tl.Binary, p)
			}
		}
	}
}

// TestRawSocketRouting is two-sided: a tool that needs CAP_NET_RAW routes to the raw worker, and everything else stays in the general unprivileged worker. The routing reads the catalog and argv only, so no prompt or corpus text can move a command into the privileged worker.
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
		{"NMAP", []string{"-sS", "-p", "80", "192.0.2.1"}},
		{"Masscan", []string{"-p", "80", "--rate", "100", "192.0.2.1"}},
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
		// Case folding matches the gate, which lowercases every binary it looks up.
		{"NMAP", []string{"-sT", "-p", "80", "192.0.2.1"}},
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

// ambiguousToolNames are catalog binaries whose name is also an ordinary English word in persona prose ("the file", "a host", "mount points"), so a substring match on them proves nothing. Every other catalog name is a distinctive token.
var ambiguousToolNames = map[string]bool{
	"file": true, "host": true, "mount": true, "stat": true,
	"id": true, "ps": true, "nm": true, "nc": true,
	// "version strings as leads", not the binutils tool.
	"strings": true,
}

// TestPromptToolMentionsAreCataloguedAndAudited is the strongest enforceable direction of the wiring contract: wherever a persona prompt names a tool by a distinctive token, that tool must be catalogued for that persona and its flag surface must be audited. Without this a prompt can drift back into naming a tool the gate refuses.
func TestPromptToolMentionsAreCataloguedAndAudited(t *testing.T) {
	prompts := map[string]string{containerPersona.Name: containerPersona.Prompt}
	for name, d := range domains {
		prompts[name] = d.Prompt
	}
	checked := 0
	for persona, prompt := range prompts {
		for _, tl := range toolCatalog {
			if ambiguousToolNames[tl.Binary] || !strings.Contains(prompt, tl.Binary) {
				continue
			}
			checked++
			if !slices.Contains(tl.Personas, persona) {
				t.Errorf("the %s prompt names %s, which the catalog does not list for that persona",
					persona, tl.Binary)
			}
			if _, audited := auditStatus(tl.Binary); !audited {
				note, _ := auditStatus(tl.Binary)
				t.Errorf("the %s prompt names %s, whose audit is incomplete: %s",
					persona, tl.Binary, note)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no prompt names any distinctive tool, so this test proves nothing")
	}
	t.Logf("checked %d prompt tool mentions", checked)
}

// TestExploitTierCatalogNamesOnlyUsableTools closes the loop the other way: every tool the per-finding exploit-tier catalog names must be installed and audited, or recorded as unavailable with the reason. That catalog predates the image work and named five tools, none of which was installed.
func TestExploitTierCatalogNamesOnlyUsableTools(t *testing.T) {
	task := engagement.Task{ID: "t1", Kind: "exploit", Phase: engagement.PhaseExploit}
	named := map[string]bool{}
	for b := range baseExploitTools {
		named[b] = true
	}
	for _, tools := range productExploitTools {
		for b := range tools {
			named[b] = true
		}
	}
	if len(named) == 0 {
		t.Fatal("the exploit-tier catalog is empty, so this test proves nothing")
	}
	for b := range named {
		if _, ok := unavailableTools[b]; ok {
			continue
		}
		tl, catalogued := toolFor(b)
		if !catalogued {
			t.Errorf("the exploit-tier catalog names %s, which is neither catalogued nor recorded as unavailable", b)
			continue
		}
		if _, audited := auditStatus(tl.Binary); !audited {
			t.Errorf("the exploit-tier catalog names %s, whose audit is incomplete", b)
		}
		if !exploitToolPermitted(task, tl.Binary) {
			t.Errorf("%s is in the catalog map but exploitToolPermitted refuses it, which means the key casing is wrong", tl.Binary)
		}
	}
}

// Every persona the catalog assigns a scanner to is told the scanner exists, so a reachable tool is not one the model never learns about.
func TestScannerPersonasNameTheScanners(t *testing.T) {
	for _, tl := range toolCatalog {
		if tl.Reach != reachScratch {
			continue
		}
		for _, persona := range tl.Personas {
			prompt := domains[persona].Prompt
			if persona == "container" {
				prompt = containerPersonaPrompt
			}
			if prompt == "" {
				t.Errorf("persona %q has no prompt, so %s is unreachable to the model", persona, tl.Binary)
				continue
			}
			if !strings.Contains(prompt, tl.Binary) {
				t.Errorf("persona %q does not name %s", persona, tl.Binary)
			}
		}
		if len(tl.Personas) != 1 || tl.Personas[0] != "vuln-analysis" {
			t.Errorf("%s is assigned to %v; the scanners belong to the one vuln-analysis persona", tl.Binary, tl.Personas)
		}
	}
}
