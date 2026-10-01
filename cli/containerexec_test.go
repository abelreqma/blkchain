package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

// containerRunCmdJSON builds a run_command tool-call argument for an nmap probe
// with the given args. Marshaled so embedded hosts/flags are escaped correctly.
func containerRunCmdJSON(args []string) string {
	b, _ := json.Marshal(struct {
		Binary string   `json:"binary"`
		Args   []string `json:"args"`
	}{Binary: "nmap", Args: args})
	return string(b)
}

// containerRecordJSON builds a record_evidence tool-call argument.
func containerRecordJSON(taskID, quote string) string {
	b, _ := json.Marshal(struct {
		TaskID string `json:"task_id"`
		Quote  string `json:"quote"`
	}{TaskID: taskID, Quote: quote})
	return string(b)
}

// containerReconModel drives the container recon-phase executor: within a tier's
// tool loop it proposes one nmap probe (cmdArgs), optionally records an evidence
// quote from its output, then yields; the sufficiency grader is answered "stop"
// so the loop ends after the first tier. A single model serves the per-tier tool
// loops and the grader call, so it branches on message content and tool turns.
type containerReconModel struct {
	cmdArgs []string
	quote   string
}

func (m containerReconModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	for _, mm := range msgs {
		if mm.Role != llms.ChatMessageTypeHuman {
			continue
		}
		for _, p := range mm.Parts {
			tc, ok := p.(llms.TextContent)
			if !ok {
				continue
			}
			if strings.Contains(tc.Text, "Respond with ONLY one JSON object") {
				return finalResp(`{"continue": false}`), nil
			}
		}
	}
	toolTurns := 0
	for _, mm := range msgs {
		if mm.Role == llms.ChatMessageTypeTool {
			toolTurns++
		}
	}
	switch toolTurns {
	case 0:
		return toolCallResp("c1", "run_command", containerRunCmdJSON(m.cmdArgs)), nil
	case 1:
		if m.quote != "" {
			return toolCallResp("c2", "record_evidence", containerRecordJSON("t1", m.quote)), nil
		}
	}
	return finalResp("tier done"), nil
}

// containerCaptureModel records every human prompt it is handed, so a test can
// prove the vantage skew actually reaches the model, then drives one tier (one
// nmap probe + one evidence quote) and answers the grader "stop".
type containerCaptureModel struct {
	prompts *[]string
}

func (m containerCaptureModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	for _, mm := range msgs {
		if mm.Role != llms.ChatMessageTypeHuman {
			continue
		}
		for _, p := range mm.Parts {
			tc, ok := p.(llms.TextContent)
			if !ok {
				continue
			}
			*m.prompts = append(*m.prompts, tc.Text)
			if strings.Contains(tc.Text, "Respond with ONLY one JSON object") {
				return finalResp(`{"continue": false}`), nil
			}
		}
	}
	toolTurns := 0
	for _, mm := range msgs {
		if mm.Role == llms.ChatMessageTypeTool {
			toolTurns++
		}
	}
	switch toolTurns {
	case 0:
		return toolCallResp("c1", "run_command", containerRunCmdJSON([]string{"-sV", "-p", "6443", "10.0.0.5"})), nil
	case 1:
		return toolCallResp("c2", "record_evidence", containerRecordJSON("t1", "Nmap scan report for 10.0.0.5\n6443/tcp open https nginx 1.18.0")), nil
	}
	return finalResp("tier done"), nil
}

func TestContainerPersonaSelectedPerKind(t *testing.T) {
	d := containerDomainFor("container")
	if d.Name != "container" {
		t.Fatalf("containerDomainFor(\"container\").Name = %q, want container (real persona, not fallback)", d.Name)
	}
	if strings.TrimSpace(d.Prompt) == "" {
		t.Fatal("container persona has an empty prompt")
	}
	if d.Prompt == domainFor("generic").Prompt {
		t.Fatal("container persona equals the generic persona; a real persona is required")
	}
	for _, want := range []string{"Kubernetes", "escape", "RBAC"} {
		if !strings.Contains(d.Prompt, want) {
			t.Errorf("container persona prompt missing %q:\n%s", want, d.Prompt)
		}
	}
	if u := containerDomainFor(""); u.Name != "container" {
		t.Errorf("containerDomainFor(\"\").Name = %q, want container (unset kind on this surface)", u.Name)
	}
	if k := containerDomainFor("k8s"); k.Name != "k8s" {
		t.Errorf("containerDomainFor(\"k8s\").Name = %q, want k8s (existing persona preserved)", k.Name)
	}
	// Route_skill contract preserved: the persona is NOT in the shared domains map,
	// so the "container" keyword still resolves to the k8s skill domain.
	if g := domainFor("container"); g.Name != "generic" {
		t.Errorf("domainFor(\"container\").Name = %q, want generic (persona must not pollute the shared map)", g.Name)
	}
	if rd := resolveDomain("container"); rd != "k8s" {
		t.Errorf("resolveDomain(\"container\") = %q, want k8s (route_skill keyword routing preserved)", rd)
	}
}

// TestContainerVantageSkewByVantage pins the vantage-as-context skew: external
// vantages skew to exposed-surface/misconfig discovery, an internal foothold (or
// deeper) skews to in-pod privilege and escape, and an unset vantage adds none.
func TestContainerVantageSkewByVantage(t *testing.T) {
	ext := containerVantageSkew(engagement.VantageExternalUnauth)
	if !strings.Contains(ext, "external") || !strings.Contains(ext, "exposed") {
		t.Errorf("external skew = %q, want exposed-surface framing", ext)
	}
	if a := containerVantageSkew(engagement.VantageExternalAuth); !strings.Contains(a, "external") {
		t.Errorf("external-auth skew = %q, want external framing", a)
	}
	foot := containerVantageSkew(engagement.VantageInternalFoothold)
	if !strings.Contains(foot, "foothold") || !strings.Contains(foot, "escape") {
		t.Errorf("foothold skew = %q, want in-pod/escape framing", foot)
	}
	if ext == foot {
		t.Error("external and foothold skews are identical; the skew must differ by vantage")
	}
	if un := containerVantageSkew(engagement.Vantage("")); un != "" {
		t.Errorf("unset vantage skew = %q, want empty (no skew)", un)
	}
}

// TestContainerTierPromptInjectsVantageSkew: the container tier prompt carries the
// skew when one is given, and omits the skew line when it is empty.
func TestContainerTierPromptInjectsVantageSkew(t *testing.T) {
	task := engagement.Task{ID: "t1", Surface: engagement.SurfaceContainer, Objective: "assess"}
	tier := reconTier{Index: 0, Name: "exposed-surface-discovery", Dimensions: []string{"exposed-ports"}}
	with := containerTierPrompt(task, "10.0.0.5", tier, reconSelection{}, "SKEW-MARKER-XYZ")
	if !strings.Contains(with, "SKEW-MARKER-XYZ") || !strings.Contains(with, "Vantage focus") {
		t.Errorf("tier prompt did not inject the skew:\n%s", with)
	}
	without := containerTierPrompt(task, "10.0.0.5", tier, reconSelection{}, "")
	if strings.Contains(without, "Vantage focus") {
		t.Errorf("tier prompt added a Vantage focus line for an empty skew:\n%s", without)
	}
}

// TestContainerReconUsesVantageSkewEndToEnd proves the skew is WIRED end-to-end
// (NO STUBS): with an external vantage set, the container recon driver reads it
// and the tier prompt the model actually receives carries the external skew.
func TestContainerReconUsesVantageSkewEndToEnd(t *testing.T) {
	var prompts []string
	d := testDeps(t, containerCaptureModel{prompts: &prompts})
	d.ReconTiers = true
	d.Gate = autoGate(t) // scope 10.0.0.0/24
	d.Runs = NewRunOutputs()
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		return runResult{Output: "Nmap scan report for 10.0.0.5\n6443/tcp open https nginx 1.18.0"}
	})
	ext := engagement.VantageExternalUnauth
	if _, err := d.Store.Apply(engagement.Delta{SetVantage: &ext}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "container", Target: "10.0.0.5", Objective: "assess exposed cluster surface",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceContainer,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	ex := executorFor(d, task)
	if _, err := ex.Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	want := containerVantageSkew(engagement.VantageExternalUnauth)
	skewed := false
	for _, p := range prompts {
		if strings.Contains(p, want) {
			skewed = true
			break
		}
	}
	if !skewed {
		t.Fatalf("no tier prompt carried the external vantage skew %q; captured = %v", want, prompts)
	}
}

const containerReconEvidence = "Nmap scan report for 10.0.0.5\n6443/tcp open ssl/https nginx 1.18.0\n"

func containerCorrelate(t *testing.T, d engageDeps, sel exploitSelector) (engagement.Task, error) {
	t.Helper()
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "container", Target: "10.0.0.5", Status: engagement.StatusTodo,
		Phase: engagement.PhaseRecon, Surface: engagement.SurfaceContainer,
	}}}); err != nil {
		t.Fatal(err)
	}
	id, err := d.Store.RecordEvidence("t1", containerReconEvidence)
	if err != nil {
		t.Fatal(err)
	}
	ex := containerExecutor{genericExecutor{d: d}}
	ex.correlateNewEvidence(context.Background(), "t1", []engagement.EvidenceRow{{ID: id, Quote: containerReconEvidence}}, sel)
	return d.Store.GetTask("exploit-10.0.0.5-6443-nginx")
}

func TestContainerDetectionCoverageGapNoSilentDrop(t *testing.T) {
	d := testDeps(t, nil)
	d.Gate = autoGate(t) // scope 10.0.0.0/24
	// MUTATE: no accepted citation for the detection.
	sel := func(ctx context.Context, svc Service) (string, engagement.Citation) {
		return "", engagement.Citation{}
	}
	cand, err := containerCorrelate(t, d, sel)
	if err != nil {
		t.Fatalf("coverage-gap candidate was dropped, not surfaced: %v", err)
	}
	if !cand.CoverageGap {
		t.Error("CoverageGap = false, want true (the no-silent-drop discriminator)")
	}
	if cand.Status != engagement.StatusBlocked {
		t.Errorf("Status = %q, want blocked (non-actionable coverage gap)", cand.Status)
	}
	if cand.Citation != (engagement.Citation{}) {
		t.Errorf("Citation = %+v, want empty for a coverage gap", cand.Citation)
	}
	if !strings.Contains(cand.Objective, "corpus-coverage-gap") {
		t.Errorf("Objective missing the coverage-gap marker: %q", cand.Objective)
	}
	if len(cand.BasisIDs) != 1 || cand.BasisIDs[0] != "t1" {
		t.Errorf("BasisIDs = %v, want [t1] (provenance preserved on the gap record)", cand.BasisIDs)
	}
}

func TestContainerDetectionGroundingAcceptance(t *testing.T) {
	t.Run("keyword-adjacent does not ground", func(t *testing.T) {
		d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("{}")}})
		d.Gate = autoGate(t)
		d.RC = &recSearcher{results: []retrieval.Result{
			chunk("offensive-k8s-attacks", "k8s/etcd.md", "etcd", "etcd direct access on 2379 exposes cluster secrets"),
		}}
		sel := newKBExploitSelector(d.Model, d.RC, d.Cfg)
		cand, err := containerCorrelate(t, d, sel)
		if err != nil {
			t.Fatalf("detection dropped: %v", err)
		}
		if !cand.CoverageGap || cand.Status != engagement.StatusBlocked {
			t.Errorf("CoverageGap=%v Status=%q, want a coverage gap (keyword-adjacent must not falsely ground)", cand.CoverageGap, cand.Status)
		}
	})
	t.Run("product-specific grounds", func(t *testing.T) {
		d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("{}")}})
		d.Gate = autoGate(t)
		d.RC = &recSearcher{results: []retrieval.Result{
			chunk("offensive-web", "web/nginx.md", "nginx CVE", "nginx 1.18.0 known CVE exploitation path"),
		}}
		sel := newKBExploitSelector(d.Model, d.RC, d.Cfg)
		cand, err := containerCorrelate(t, d, sel)
		if err != nil {
			t.Fatalf("grounded detection not persisted: %v", err)
		}
		if cand.CoverageGap || cand.Status != engagement.StatusTodo {
			t.Errorf("CoverageGap=%v Status=%q, want actionable todo (product-specific hit grounds)", cand.CoverageGap, cand.Status)
		}
		if cand.Citation.Source == "" {
			t.Error("grounded candidate has no citation")
		}
	})
}

type containerReconNoRecordModel struct{}

func (containerReconNoRecordModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	var human string
	toolTurns := 0
	for _, m := range msgs {
		if m.Role == llms.ChatMessageTypeTool {
			toolTurns++
		}
		if m.Role != llms.ChatMessageTypeHuman {
			continue
		}
		for _, p := range m.Parts {
			if tc, ok := p.(llms.TextContent); ok {
				human += tc.Text
			}
		}
	}
	if strings.Contains(human, "Respond with ONLY one JSON object") {
		return finalResp(`{"continue": false}`), nil
	}
	if toolTurns == 0 {
		return toolCallResp("c1", "run_command", containerRunCmdJSON([]string{"-sV", "-p", "6443", "10.0.0.5"})), nil
	}
	return finalResp("tier done"), nil
}

func TestContainerReconCodeSideEvidenceAndCandidate(t *testing.T) {
	d := testDeps(t, containerReconNoRecordModel{})
	d.ReconTiers = true
	d.Gate = autoGate(t) // scope 10.0.0.0/24
	d.Runs = NewRunOutputs()
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		return runResult{Output: "Nmap scan report for 10.0.0.5\n6443/tcp open ssl/https nginx 1.18.0"}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "container", Target: "10.0.0.5", Objective: "assess exposed cluster surface",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceContainer,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executorFor(d, task).Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	// Code-side capture: a row exists although the model never recorded one.
	rows, err := d.Store.EvidenceRowsFor("t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no evidence row: the model did not record_evidence and the code-side backstop did not capture it (no-silent-drop violated)")
	}
	// The deterministic detection still yields a candidate; uncited -> coverage-gap.
	cand, err := d.Store.GetTask("exploit-10.0.0.5-6443-nginx")
	if err != nil {
		t.Fatalf("no candidate-or-coverage-gap from the container recon: %v", err)
	}
	if cand.Phase != engagement.PhaseExploit || cand.Armed {
		t.Errorf("candidate = %+v, want unarmed exploit", cand)
	}
	if cand.Status != engagement.StatusBlocked || !cand.CoverageGap {
		t.Errorf("uncited candidate = {Status:%q CoverageGap:%v}, want a blocked coverage-gap", cand.Status, cand.CoverageGap)
	}
}

// TestContainerExecutorRegisteredForSurface pins the registration seam: a
// SurfaceContainer task routes to containerExecutor, while an unregistered
// surface still falls back to genericExecutor.
func TestContainerExecutorRegisteredForSurface(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	ex := executorFor(d, engagement.Task{ID: "t", Surface: engagement.SurfaceContainer, Kind: "k8s"})
	if _, ok := ex.(containerExecutor); !ok {
		t.Fatalf("executorFor(SurfaceContainer) = %T, want containerExecutor", ex)
	}
	other := executorFor(d, engagement.Task{ID: "t2", Surface: engagement.Surface("container-registry-probe-surface"), Kind: "recon"})
	if _, ok := other.(genericExecutor); !ok {
		t.Fatalf("executorFor(unregistered surface) = %T, want genericExecutor fallback", other)
	}
}

// TestContainerLadderTiers pins the container recon ladder: T0 exposed-surface
// discovery -> T1 RBAC/service-account enum -> T2 workload/cluster misconfig ->
// T3 escape-vector probes, in that order.
func TestContainerLadderTiers(t *testing.T) {
	l := ladderFor(engagement.SurfaceContainer)
	want := []struct {
		name string
		dims []string
	}{
		{"exposed-surface-discovery", []string{"exposed-ports", "runtime-sockets"}},
		{"rbac-serviceaccount-enum", []string{"rbac", "service-accounts"}},
		{"workload-cluster-misconfig", []string{"workloads", "misconfig"}},
		{"escape-vector-probes", []string{"escape-vectors"}},
	}
	if len(l) != len(want) {
		t.Fatalf("container ladder has %d tiers, want %d", len(l), len(want))
	}
	for i, w := range want {
		if l[i].Index != i {
			t.Errorf("tier %d Index = %d, want %d", i, l[i].Index, i)
		}
		if l[i].Name != w.name {
			t.Errorf("tier %d Name = %q, want %q", i, l[i].Name, w.name)
		}
		if len(l[i].Dimensions) != len(w.dims) {
			t.Fatalf("tier %d has %d dims, want %d", i, len(l[i].Dimensions), len(w.dims))
		}
		for j, dim := range w.dims {
			if l[i].Dimensions[j] != dim {
				t.Errorf("tier %d dim %d = %q, want %q", i, j, l[i].Dimensions[j], dim)
			}
		}
	}
}

// TestContainerExecutorDeniesOutOfScopeTarget: a container recon task whose
// proposed probe targets an out-of-scope host is denied by the gate (resolve-and-
// pin scope enforcement), so execRunner never runs.
func TestContainerExecutorDeniesOutOfScopeTarget(t *testing.T) {
	d := testDeps(t, containerReconModel{cmdArgs: []string{"-p", "6443", "8.8.8.8"}})
	d.ReconTiers = true
	d.Gate = autoGate(t) // scope 10.0.0.0/24
	d.Runs = NewRunOutputs()
	ran := false
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		ran = true
		return runResult{Output: "should not run"}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "k8s", Target: "8.8.8.8", Objective: "assess exposed cluster surface",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceContainer,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	ex := executorFor(d, task)
	if _, err := ex.Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	if ran {
		t.Fatal("out-of-scope target must be denied by the gate before execRunner runs")
	}
}

// TestContainerExecutorFindingsCarryProvenance: an in-scope container recon task
// records exact-quote evidence, and the code-owned correlation turns a discovered
// service into a candidate task whose BasisIDs trace to the recon task
// (Provenance{TaskID, EvidenceID} -> candidate basis). Hermetic: execRunner is
// stubbed; no real binary runs.
func TestContainerExecutorFindingsCarryProvenance(t *testing.T) {
	quote := "Nmap scan report for 10.0.0.5\n6443/tcp open https nginx 1.18.0"
	d := testDeps(t, containerReconModel{cmdArgs: []string{"-sV", "-p", "6443", "10.0.0.5"}, quote: quote})
	d.ReconTiers = true
	d.Gate = autoGate(t) // scope 10.0.0.0/24
	d.Runs = NewRunOutputs()
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		return runResult{Output: quote}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "k8s", Target: "10.0.0.5", Objective: "assess exposed cluster surface",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceContainer,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	ex := executorFor(d, task)
	if _, err := ex.Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}

	// Evidence was recorded with a real row id: the provenance anchor.
	rows, err := d.Store.EvidenceRowsFor("t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 || rows[0].ID <= 0 {
		t.Fatalf("evidence rows = %+v, want at least one with a positive row id", rows)
	}

	// The discovered service correlated to a candidate task whose basis traces to
	// the recon task that produced the evidence (provenance from evidence to task).
	snap, err := d.Store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found *engagement.Task
	for i := range snap.Tasks {
		if len(snap.Tasks[i].BasisIDs) > 0 && snap.Tasks[i].ID != "t1" {
			found = &snap.Tasks[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no correlated candidate task with provenance; tasks = %+v", snap.Tasks)
	}
	if found.BasisIDs[0] != "t1" {
		t.Fatalf("candidate BasisIDs = %v, want provenance to t1", found.BasisIDs)
	}
}
