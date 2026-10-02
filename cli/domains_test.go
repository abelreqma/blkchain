package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
)

func TestExecutorPreambleAllowsGatedCommands(t *testing.T) {
	if strings.Contains(executorPreamble, "cannot run commands against targets in this phase") {
		t.Errorf("executorPreamble still contains the stale no-commands sentence: %q", executorPreamble)
	}
}

func TestExecutorPromptsDriveTheOffensiveLifecycle(t *testing.T) {
	for _, want := range []string{"offensive operator", "initial access", "privilege escalation", "lateral movement", "post-exploitation", "rules of engagement", "execution gate"} {
		if !strings.Contains(executorPreamble, want) {
			t.Errorf("executorPreamble missing offensive lifecycle instruction %q", want)
		}
	}
	for _, name := range []string{"web", "ad", "cloud", "k8s", "exploit-dev", "local"} {
		p := domainFor(name).Prompt
		if !strings.Contains(p, "exploit") && !strings.Contains(p, "compromise") {
			t.Errorf("%s prompt has no exploitation objective", name)
		}
		if !strings.Contains(p, "basis_ids") {
			t.Errorf("%s prompt does not preserve follow-on provenance", name)
		}
	}
	for _, want := range []string{"prompt-injection", "tool-use boundary", "UNTRUSTED", "basis_ids"} {
		if !strings.Contains(aiSecDomainPrompt, want) {
			t.Errorf("AI-security prompt missing %q", want)
		}
	}
	for _, want := range []string{"cluster-admin", "exploit/post-ex", "basis_ids"} {
		if !strings.Contains(containerPersonaPrompt, want) {
			t.Errorf("container prompt missing %q", want)
		}
	}
}

func TestOffensiveReconAndExploitSelectorsUseEvidenceAndCoverage(t *testing.T) {
	for _, want := range []string{"hypothesis", "expected signal", "Do not repeat completed probes"} {
		p := reconTierPrompt(engagement.Task{ID: "t1", Objective: "map service"}, "10.0.0.5", reconTier{Name: "service-enum", Dimensions: []string{"ports"}}, reconSelection{})
		if !strings.Contains(p, want) {
			t.Errorf("recon tier prompt missing %q", want)
		}
	}
	for _, want := range []string{"evidence-backed lead", "Do not require discovery of a new host"} {
		if !strings.Contains(reconGradePrompt, want) {
			t.Errorf("recon grader prompt missing %q", want)
		}
	}
	for _, want := range []string{"highest-value uncertainty", "THIS tier only"} {
		if !strings.Contains(reconSelectPrompt, want) {
			t.Errorf("recon selector prompt missing %q", want)
		}
	}
	for _, want := range []string{"concrete prerequisites", "testable impact", "never a command"} {
		if !strings.Contains(exploitSelectPrompt, want) {
			t.Errorf("exploit selector prompt missing %q", want)
		}
	}
}

func TestLocalDomainRegistered(t *testing.T) {
	d := domainFor("local")
	if d.Name != "local" {
		t.Fatalf("domainFor(\"local\").Name = %q, want local", d.Name)
	}
	for _, bad := range []string{"chmod -R"} {
		if strings.Contains(d.Prompt, bad) {
			t.Errorf("local prompt contains destructive guidance %q", bad)
		}
	}
	for _, want := range []string{"sudo -l", "-perm -4000", "getcap", "basis_ids", "no -exec or -delete"} {
		if !strings.Contains(d.Prompt, want) {
			t.Errorf("local prompt missing %q", want)
		}
	}
}

func TestTargetAnalysisDomain(t *testing.T) {
	d := domainFor("target-analysis")
	if d.Name != "target-analysis" {
		t.Fatalf("domainFor(\"target-analysis\").Name = %q", d.Name)
	}
	for _, want := range []string{"file", "ldd", "strings", "readelf", "getcap", "GTFOBins"} {
		if !strings.Contains(d.Prompt, want) {
			t.Errorf("target-analysis prompt missing %q", want)
		}
	}
	for _, bad := range []string{"-exec", "-delete"} {
		if strings.Contains(d.Prompt, bad) {
			t.Errorf("target-analysis prompt contains destructive guidance %q", bad)
		}
	}
}

func TestReconPromptCoversEnumerationSurfaces(t *testing.T) {
	prompt := domainFor("recon").Prompt
	for _, want := range []string{"DNS", "SMB", "LDAP", "SNMP"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("recon prompt missing %q:\n%s", want, prompt)
		}
	}
}

func TestReconPromptMentionsChainedFollowOnTasks(t *testing.T) {
	prompt := domainFor("recon").Prompt
	for _, want := range []string{"plan_add", "basis_ids", "follow-on"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("recon prompt missing %q:\n%s", want, prompt)
		}
	}
}

// TestAllExistingDomainsPresent pins behavior preservation: every persona the
// fixed set shipped is still registered and retrievable after the registry
// conversion. A missing persona changes executor behavior for that kind.
func TestAllExistingDomainsPresent(t *testing.T) {
	for _, name := range []string{"generic", "recon", "web", "ad", "cloud", "k8s", "wifi", "exploit-dev", "target-analysis", "local"} {
		d := domainFor(name)
		if d.Name != name {
			t.Errorf("domainFor(%q).Name = %q, want %q (persona missing)", name, d.Name, name)
		}
		if strings.TrimSpace(d.Prompt) == "" {
			t.Errorf("persona %q has an empty prompt", name)
		}
	}
}

// TestRegisterDomainAddsPersona pins the registration seam: a persona registered
// from another file is retrievable via domainFor without editing domains.go.
func TestRegisterDomainAddsPersona(t *testing.T) {
	const name = "registry-test-domain"
	registerDomain(name, domain{Name: name, Prompt: executorPreamble + "test persona"})
	t.Cleanup(func() { delete(domains, name) })
	if d := domainFor(name); d.Name != name {
		t.Fatalf("domainFor(%q).Name = %q, want the registered persona", name, d.Name)
	}
}

func TestDomainForKnownAndUnknown(t *testing.T) {
	if d := domainFor("web"); d.Name != "web" {
		t.Errorf("domainFor(web).Name = %q", d.Name)
	}
	if d := domainFor("totally-unknown-kind"); d.Name != "generic" {
		t.Errorf("unknown kind should map to generic, got %q", d.Name)
	}
	if d := domainFor("web"); strings.TrimSpace(d.Prompt) == "" {
		t.Error("web domain has empty prompt")
	}
}

func TestDomainForTaskFallsBackToSurface(t *testing.T) {
	cases := []struct {
		name string
		task engagement.Task
		want string
	}{
		{"web exploit", engagement.Task{Kind: "exploit", Surface: engagement.SurfaceWeb}, "web"},
		{"ad exploit", engagement.Task{Kind: "exploit", Surface: engagement.SurfaceAD}, "ad"},
		{"cloud aws exploit", engagement.Task{Kind: "exploit", Surface: engagement.SurfaceCloudAWS}, "cloud"},
		{"container exploit", engagement.Task{Kind: "exploit", Surface: engagement.SurfaceContainer}, "container"},
		{"ai exploit", engagement.Task{Kind: "exploit", Surface: engagement.SurfaceAISecurity}, "ai-security"},
		{"local exploit", engagement.Task{Kind: "exploit", Surface: engagement.SurfaceLocal}, "local"},
		{"network exploit", engagement.Task{Kind: "exploit", Surface: engagement.SurfaceNetwork}, "recon"},
		{"known kind wins", engagement.Task{Kind: "web", Surface: engagement.SurfaceLocal}, "web"},
	}
	for _, tc := range cases {
		if got := domainForTask(tc.task); got.Name != tc.want {
			t.Errorf("%s: domainForTask() = %q, want %q", tc.name, got.Name, tc.want)
		}
	}
}

func TestLocalFindingChainsToTargetAnalysis(t *testing.T) {
	st := openStore(t) // openStore + plan_add harness from plantools_test.go, same package
	add := newPlanAddTool(st)
	ctx := context.Background()

	// The originating local enumeration task.
	if _, err := add.Call(ctx, `{"id":"t1","kind":"local","target":"host","objective":"enumerate privesc"}`); err != nil {
		t.Fatal(err)
	}

	// An exploitable SUID binary finding chains into a target-analysis task whose
	// target names the binary path and whose basis_ids carry the local task's id.
	out, err := add.Call(ctx, `{"id":"t2","kind":"target-analysis","target":"/usr/bin/find","objective":"assess SUID find as a privesc vector","basis_ids":["t1"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "rejected") {
		t.Fatalf("chained target-analysis task was rejected: %q", out)
	}
	got, err := st.GetTask("t2")
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "target-analysis" {
		t.Errorf("Kind = %q, want target-analysis", got.Kind)
	}
	if got.Target != "/usr/bin/find" {
		t.Errorf("Target = %q, want the binary path /usr/bin/find", got.Target)
	}
	if len(got.BasisIDs) != 1 || got.BasisIDs[0] != "t1" {
		t.Errorf("BasisIDs = %v, want [t1]", got.BasisIDs)
	}
	// Provenance is not a scheduling dependency.
	if len(got.DependsOn) != 0 {
		t.Errorf("DependsOn = %v, basis_ids must not create a scheduling dependency", got.DependsOn)
	}
	// The follow-on kind routes to the intended domain.
	if d := domainFor(got.Kind); d.Name != "target-analysis" {
		t.Errorf("domainFor(%q).Name = %q, want target-analysis", got.Kind, d.Name)
	}
}

func TestLocalCredentialFindingChainsToAuth(t *testing.T) {
	st := openStore(t)
	add := newPlanAddTool(st)
	ctx := context.Background()

	if _, err := add.Call(ctx, `{"id":"t1","kind":"local","target":"host","objective":"enumerate privesc"}`); err != nil {
		t.Fatal(err)
	}

	// A discovered credential chains into an auth task carrying the origin as basis.
	out, err := add.Call(ctx, `{"id":"t2","kind":"auth","target":"host","objective":"reuse discovered credential","basis_ids":["t1"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "rejected") {
		t.Fatalf("chained auth task was rejected: %q", out)
	}
	got, err := st.GetTask("t2")
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "auth" {
		t.Errorf("Kind = %q, want auth", got.Kind)
	}
	if len(got.BasisIDs) != 1 || got.BasisIDs[0] != "t1" {
		t.Errorf("BasisIDs = %v, want [t1]", got.BasisIDs)
	}
	if len(got.DependsOn) != 0 {
		t.Errorf("DependsOn = %v, basis_ids must not create a scheduling dependency", got.DependsOn)
	}
	// There is no auth domain in this task; the kind falls back to generic.
	if d := domainFor(got.Kind); d.Name != "generic" {
		t.Errorf("domainFor(%q).Name = %q, want generic (no auth domain exists)", got.Kind, d.Name)
	}
}

func TestProjectionTextShowsCoverageAndDiscoveries(t *testing.T) {
	st := openStore(t) // from plantools_test.go, same package
	if _, err := newPlanAddTool(st).Call(context.Background(), `{"id":"t1","kind":"recon","target":"10.0.0.5","objective":"enumerate"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := newPlanAddTool(st).Call(context.Background(), `{"id":"t2","kind":"web","target":"10.0.0.5","objective":"login flow"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := newRecordEvidenceTool(st).Call(context.Background(), `{"task_id":"t1","quote":"port 22 open"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := newPlanCompleteTool(st).Call(context.Background(), `{"id":"t1"}`); err != nil {
		t.Fatal(err)
	}
	out, err := projectionText(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "t2") {
		t.Errorf("projection missing open task t2:\n%s", out)
	}
	if !strings.Contains(out, "t1") {
		t.Errorf("projection missing discovered task t1:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "coverage") {
		t.Errorf("projection missing coverage line:\n%s", out)
	}
}

func TestProjectionTextShowsVantage(t *testing.T) {
	st := openStore(t)
	// Unset vantage still prints the line with an empty value, so every
	// executor's projection carries the access-state field.
	out, err := projectionText(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Vantage:") {
		t.Errorf("projection missing Vantage line when unset:\n%s", out)
	}
	// A set vantage prints its value.
	v := engagement.VantageInternalFoothold
	if _, err := st.Apply(engagement.Delta{SetVantage: &v}); err != nil {
		t.Fatal(err)
	}
	out2, err := projectionText(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out2, "Vantage: "+string(v)) {
		t.Errorf("projection missing set vantage %q:\n%s", v, out2)
	}
}

func TestProjectionTextCapsLongLists(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	n := projectionMaxPerList + 5
	// Distinct objectives per task: plan_add now rejects a duplicate of an open
	// task on (kind, target, objective, surface), so a cap test must add distinct
	// tasks (as a real run would), not N identical ones.
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("t%d", i)
		if _, err := newPlanAddTool(st).Call(ctx, fmt.Sprintf(`{"id":%q,"kind":"recon","target":"h","objective":"o%d"}`, id, i)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("d%d", i)
		if _, err := newPlanAddTool(st).Call(ctx, fmt.Sprintf(`{"id":%q,"kind":"web","target":"h","objective":"o%d","status":"na"}`, id, i)); err != nil {
			t.Fatal(err)
		}
	}
	out, err := projectionText(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out, "... (+5 more)"); got != 2 {
		t.Errorf("tail count = %d, want 2 (one per list):\n%s", got, out)
	}
	if got := strings.Count(out, "\n- "); got != 2*projectionMaxPerList {
		t.Errorf("listed lines = %d, want %d", got, 2*projectionMaxPerList)
	}
}
