package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

// TestCloudExecutorsRegisteredPerSurface pins the registration seam for all four
// cloud surfaces: executorFor returns the surface's own concrete executor type,
// so a cloud/CSP task routes to its registered executor (not the genericExecutor
// fallback). Vantage is context, not a persona axis: every cloud surface shares
// one persona but has its own executor + ladder.
func TestCloudExecutorsRegisteredPerSurface(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	assertType := func(s engagement.Surface, want string) {
		ex := executorFor(d, engagement.Task{ID: "t", Surface: s, Kind: "cloud"})
		got := ""
		switch ex.(type) {
		case cloudExecutor:
			got = "cloudExecutor"
		case cloudAWSExecutor:
			got = "cloudAWSExecutor"
		case cloudGCPExecutor:
			got = "cloudGCPExecutor"
		case cloudAzureExecutor:
			got = "cloudAzureExecutor"
		default:
			got = "fallback"
		}
		if got != want {
			t.Errorf("executorFor(surface=%q) = %s, want %s", s, got, want)
		}
	}
	assertType(engagement.SurfaceCloud, "cloudExecutor")
	assertType(engagement.SurfaceCloudAWS, "cloudAWSExecutor")
	assertType(engagement.SurfaceCloudGCP, "cloudGCPExecutor")
	assertType(engagement.SurfaceCloudAzure, "cloudAzureExecutor")
}

// TestCloudLaddersRegisteredPerSurface: each cloud surface has its own recon
// ladder (not the single-tier genericReconLadder), and the per-CSP ladders refine
// the metadata/IAM tier with provider-specific coverage dimensions.
func TestCloudLaddersRegisteredPerSurface(t *testing.T) {
	cases := []struct {
		surface engagement.Surface
		wantDim string // a distinctive dimension only this surface's ladder defines
	}{
		{engagement.SurfaceCloud, "cloud-metadata"},
		{engagement.SurfaceCloudAWS, "aws-imds"},
		{engagement.SurfaceCloudGCP, "gcp-metadata"},
		{engagement.SurfaceCloudAzure, "azure-imds"},
	}
	for _, c := range cases {
		l := ladderFor(c.surface)
		if len(l) < 2 {
			t.Errorf("ladderFor(%q) = %d tiers, want the multi-tier cloud ladder", c.surface, len(l))
		}
		found := false
		for _, dim := range l.allDimensions() {
			if dim == c.wantDim {
				found = true
			}
		}
		if !found {
			t.Errorf("ladderFor(%q) dimensions %v missing %q", c.surface, l.allDimensions(), c.wantDim)
		}
	}
}

// TestCloudParseFindingsCarryProvenance: the deterministic cloud finding pre-filter
// (cloudMatchFindings) produces a code-derived UNARMED exploit candidate per
// indicator in a verbatim evidence quote, each carrying provenance (basis_ids
// tracing to the task) and the task's cloud surface, with Phase exploit so the gate
// enforces arm + per-action confirm. (RAG grounding + emission happen later in
// cloudCorrelateNewEvidence; this pins the fast-path candidate shape.)
func TestCloudParseFindingsCarryProvenance(t *testing.T) {
	prov := Provenance{TaskID: "t1", EvidenceID: 7}
	cases := []struct {
		name  string
		quote string
	}{
		{"aws-imds-creds", `{"AccessKeyId":"ASIAABCDEFGHIJKLMNOP","SecretAccessKey":"s","Token":"t"}`},
		{"oauth-token", `{"access_token":"ya29.abc","token_type":"Bearer","expires_in":3599}`},
		{"s3-listing", `<ListBucketResult><Name>loot</Name><Contents><Key>secrets.txt</Key></Contents></ListBucketResult>`},
		{"iam-wildcard", `{"Effect":"Allow","Action":"*","Resource":"*"}`},
		{"iam-privesc", `role grants iam:PassRole on the admin role`},
	}
	for _, c := range cases {
		hits := cloudFindingHits(prov, c.quote, engagement.SurfaceCloudAWS)
		if len(hits) == 0 {
			t.Errorf("cloudFindingHits(%s) = no match, want at least one", c.name)
			continue
		}
		got := hits[0].Task
		if got.Phase != engagement.PhaseExploit {
			t.Errorf("%s: Phase = %q, want exploit", c.name, got.Phase)
		}
		if got.Surface != engagement.SurfaceCloudAWS {
			t.Errorf("%s: Surface = %q, want the task's cloud surface", c.name, got.Surface)
		}
		if got.Armed {
			t.Errorf("%s: candidate must be UNARMED (the gate arms at execution time)", c.name)
		}
		if got.Status != engagement.StatusTodo {
			t.Errorf("%s: Status = %q, want todo", c.name, got.Status)
		}
		if len(got.BasisIDs) != 1 || got.BasisIDs[0] != "t1" {
			t.Errorf("%s: BasisIDs = %v, want provenance [t1]", c.name, got.BasisIDs)
		}
		if !strings.HasPrefix(got.ID, "cloud-") {
			t.Errorf("%s: ID = %q, want a cloud- prefixed stable id", c.name, got.ID)
		}
	}
}

// TestCloudParseFindingsRejectsInvalidProvenance: no match without a verified
// evidence-quote id (fail closed, mirroring the shared parsers).
func TestCloudParseFindingsRejectsInvalidProvenance(t *testing.T) {
	bad := Provenance{TaskID: "", EvidenceID: 0}
	if got := cloudFindingHits(bad, `{"AccessKeyId":"ASIAABCDEFGHIJKLMNOP"}`, engagement.SurfaceCloud); got != nil {
		t.Errorf("invalid provenance must produce no match, got %v", got)
	}
}

// TestCloudParseFindingsIgnoresBenignOutput: a clean, non-indicator quote produces
// no match (the pre-filter never invents a cloud finding).
func TestCloudParseFindingsIgnoresBenignOutput(t *testing.T) {
	prov := Provenance{TaskID: "t1", EvidenceID: 1}
	if got := cloudFindingHits(prov, "HTTP/1.1 403 Forbidden\nAccessDenied", engagement.SurfaceCloud); got != nil {
		t.Errorf("benign output must produce no match, got %v", got)
	}
}

// cloudReconModel drives the live cloud recon executor: within the tier tool loop
// it runs one in-scope curl, records the IMDS credential JSON its output
// disclosed, then yields; the sufficiency grader says stop so the loop ends after
// the first tier. Mirrors reconLiveModel's content-branching across the shared
// per-tier loops and the grader call.
type cloudReconModel struct{}

func (cloudReconModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	for _, m := range msgs {
		if m.Role != llms.ChatMessageTypeHuman {
			continue
		}
		for _, p := range m.Parts {
			tc, ok := p.(llms.TextContent)
			if !ok {
				continue
			}
			if strings.Contains(tc.Text, "Respond with ONLY one JSON object") {
				return finalResp(`{"continue": false}`), nil
			}
			// Recon next-action selector prompt (present when retrieval is available):
			// fail closed to the ladder step with an empty selection.
			if strings.Contains(tc.Text, "Corpus notes (reference only") {
				return finalResp(`{}`), nil
			}
		}
	}
	toolTurns := 0
	for _, m := range msgs {
		if m.Role == llms.ChatMessageTypeTool {
			toolTurns++
		}
	}
	switch toolTurns {
	case 0:
		return toolCallResp("c1", "run_command", `{"binary":"curl","args":["http://10.0.0.5/latest/meta-data/iam/security-credentials/role"]}`), nil
	case 1:
		return toolCallResp("c2", "record_evidence", `{"task_id":"t1","quote":"{\"AccessKeyId\":\"ASIAABCDEFGHIJKLMNOP\",\"SecretAccessKey\":\"s\",\"Token\":\"t\"}"}`), nil
	}
	return finalResp("tier done"), nil
}

func TestCloudReconCorrelatesMetadataCredFinding(t *testing.T) {
	d := testDeps(t, cloudReconModel{})
	d.ReconTiers = true
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	// Grounding corpus: kb_search returns a service-specific offensive-cloud hit (the
	// imds term is present), so the detection is RAG-grounded via the shared
	// acceptCitation gate and the finding is emitted with its citation.
	d.RC = &recSearcher{results: []retrieval.Result{
		chunk("offensive-cloud", "cloud/aws.md", "IMDS", "AWS IMDS role credential theft via 169.254.169.254."),
	}}
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		return runResult{Output: `{"AccessKeyId":"ASIAABCDEFGHIJKLMNOP","SecretAccessKey":"s","Token":"t"}`}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "cloud", Target: "10.0.0.5", Objective: "enumerate cloud surface",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceCloud,
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

	snap, err := d.Store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var cand *engagement.Task
	for i := range snap.Tasks {
		if strings.HasPrefix(snap.Tasks[i].ID, "cloud-") && snap.Tasks[i].Kind == "exploit" && !snap.Tasks[i].CoverageGap {
			cand = &snap.Tasks[i]
			break
		}
	}
	if cand == nil {
		t.Fatalf("no grounded cloud finding created from metadata credential evidence; tasks=%+v", snap.Tasks)
	}
	if cand.Surface != engagement.SurfaceCloud {
		t.Errorf("candidate Surface = %q, want the cloud surface", cand.Surface)
	}
	if cand.Phase != engagement.PhaseExploit || cand.Armed {
		t.Errorf("candidate must be an UNARMED exploit candidate, got phase=%q armed=%v", cand.Phase, cand.Armed)
	}
	if len(cand.BasisIDs) != 1 || cand.BasisIDs[0] != "t1" {
		t.Errorf("candidate BasisIDs = %v, want provenance [t1]", cand.BasisIDs)
	}
	if cand.Citation.Source == "" {
		t.Errorf("RAG-gated finding must carry a corpus citation, got empty citation")
	}
}

// cloudOOSModel proposes a curl to the out-of-scope cloud metadata endpoint, then
// finishes. The gate must deny the probe (scope + resolve-and-pin) so execRunner
// never runs.
type cloudOOSModel struct{}

func (cloudOOSModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	for _, m := range msgs {
		if m.Role != llms.ChatMessageTypeHuman {
			continue
		}
		for _, p := range m.Parts {
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
	for _, m := range msgs {
		if m.Role == llms.ChatMessageTypeTool {
			toolTurns++
		}
	}
	if toolTurns == 0 {
		return toolCallResp("c1", "run_command", `{"binary":"curl","args":["http://169.254.169.254/latest/meta-data/iam/security-credentials/"]}`), nil
	}
	return finalResp("done"), nil
}

// TestCloudOutOfScopeMetadataDenied: the cloud executor's run_command for an
// out-of-scope metadata endpoint (169.254.169.254, not in the 10.0.0.0/24 scope)
// is denied by the gate before execution; execRunner is never invoked.
func TestCloudOutOfScopeMetadataDenied(t *testing.T) {
	d := testDeps(t, cloudOOSModel{})
	d.ReconTiers = true
	d.Gate = autoGate(t) // scope is 10.0.0.0/24; 169.254.169.254 is out of scope
	d.Runs = NewRunOutputs()
	ran := false
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		ran = true
		return runResult{Output: "should not run"}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "cloud", Target: "10.0.0.5", Objective: "enumerate cloud surface",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceCloudAWS,
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
		t.Fatal("out-of-scope metadata endpoint must be denied by the gate; execRunner must not run")
	}
}

// TestCloudExecutorReusesCloudPersona: all four cloud surfaces share the one
// "cloud" persona (vantage is context, not a persona axis).
func TestCloudExecutorReusesCloudPersona(t *testing.T) {
	dom := cloudPersona()
	if dom.Name != "cloud" {
		t.Fatalf("cloudPersona().Name = %q, want cloud", dom.Name)
	}
	if !strings.Contains(strings.ToLower(dom.Prompt), "cloud") {
		t.Errorf("cloud persona prompt should mention cloud: %q", dom.Prompt)
	}
}

// cloudSkewCaptureModel records every human-message text it is shown and returns a
// final response with no tool call, so one tier pass runs (no commands, no
// evidence -> novelty-zero stop) and the tier prompt it received can be inspected.
type cloudSkewCaptureModel struct{ prompts []string }

func (m *cloudSkewCaptureModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	for _, mm := range msgs {
		if mm.Role != llms.ChatMessageTypeHuman {
			continue
		}
		for _, p := range mm.Parts {
			if tc, ok := p.(llms.TextContent); ok {
				m.prompts = append(m.prompts, tc.Text)
			}
		}
	}
	return finalResp("noted"), nil
}

// TestCloudVantageSkewInjected: the current vantage is wired into the cloud recon
// tier prompt (not just the reachability check). At an external vantage the model
// receives the external skew (public-asset / leaked-credential) and NOT the
// post-foothold skew; at an internal foothold it receives the metadata / IAM-privesc
// skew and NOT the external skew. This pins vantage-as-context as actually wired
// (no stub), across the CSP surfaces that inherit cloudExecutor.Run.
func TestCloudVantageSkewInjected(t *testing.T) {
	run := func(t *testing.T, surface engagement.Surface, v engagement.Vantage) []string {
		t.Helper()
		m := &cloudSkewCaptureModel{}
		d := testDeps(t, m)
		d.ReconTiers = true
		d.Gate = autoGate(t)
		d.Runs = NewRunOutputs()
		if _, err := d.Store.Apply(engagement.Delta{SetVantage: &v}); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
			ID: "t1", Kind: "cloud", Target: "10.0.0.5", Objective: "enumerate cloud surface",
			Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: surface,
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
		return m.prompts
	}
	joined := func(ps []string) string { return strings.Join(ps, "\n----\n") }

	// Markers are chosen to be unique to each skew and absent from the ladder tier
	// NAMES (e.g. "public-asset-discovery"), so the assertions test the skew, not a
	// coincidental tier-name substring.
	ext := joined(run(t, engagement.SurfaceCloudAWS, engagement.VantageExternalUnauth))
	if !strings.Contains(ext, "leaked-credential") {
		t.Errorf("external vantage: tier prompt missing the external skew (leaked-credential):\n%s", ext)
	}
	if strings.Contains(ext, "IAM privilege-escalation") {
		t.Errorf("external vantage: tier prompt must NOT carry the post-foothold skew:\n%s", ext)
	}

	foot := joined(run(t, engagement.SurfaceCloudGCP, engagement.VantageInternalFoothold))
	if !strings.Contains(foot, "IAM privilege-escalation") {
		t.Errorf("post-foothold vantage: tier prompt missing the metadata/IAM-privesc skew:\n%s", foot)
	}
	if strings.Contains(foot, "leaked-credential") {
		t.Errorf("post-foothold vantage: tier prompt must NOT carry the external skew:\n%s", foot)
	}
}

// TestCloudVantageSkewUnsetNoSkew: with no vantage set, no skew text is
// appended - the tier prompt is the bare recon prompt.
func TestCloudVantageSkewUnsetNoSkew(t *testing.T) {
	if got := cloudVantageSkew(""); got != "" {
		t.Errorf("unset vantage must produce no skew, got %q", got)
	}
}

// seedCloudTask seeds a recon-phase cloud task for the correlation unit tests.
func seedCloudTask(t *testing.T, d engageDeps, id string, s engagement.Surface) engagement.Task {
	t.Helper()
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: id, Kind: "cloud", Target: "10.0.0.5", Objective: "enumerate",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: s,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask(id)
	if err != nil {
		t.Fatal(err)
	}
	return task
}

// cloudCandidateSplit partitions the stored CLOUD candidates (id prefix "cloud-")
// into grounded, actionable findings and coverage-gap records. The
// DISCRIMINATOR is the Task.CoverageGap BOOL (both kinds share Kind "exploit"),
// not the Objective string or Kind.
func cloudCandidateSplit(t *testing.T, d engageDeps) (findings, gaps []engagement.Task) {
	t.Helper()
	snap, err := d.Store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range snap.Tasks {
		if !strings.HasPrefix(tk.ID, "cloud-") {
			continue
		}
		if tk.CoverageGap {
			gaps = append(gaps, tk)
		} else if tk.Kind == "exploit" {
			findings = append(findings, tk)
		}
	}
	return findings, gaps
}

// awsCredQuote is a verbatim IMDS credential evidence quote that trips exactly the
// imds-aws-creds rule (and no shared parser), so the correlation tests isolate
// the cloud finding path.
const awsCredQuote = `{"AccessKeyId":"ASIAABCDEFGHIJKLMNOP","SecretAccessKey":"s","Token":"t"}`

// cloudCorrelateOne drives cloudCorrelateNewEvidence over a single recorded evidence
// quote, isolating the cloud finding path for the grounding tests.
func cloudCorrelateOne(t *testing.T, d engageDeps, quote string) {
	t.Helper()
	task := seedCloudTask(t, d, "t1", engagement.SurfaceCloudAWS)
	rid, err := d.Store.RecordEvidence("t1", quote)
	if err != nil {
		t.Fatal(err)
	}
	e := cloudExecutor{genericExecutor{d: d}}
	e.cloudCorrelateNewEvidence(context.Background(), task, []engagement.EvidenceRow{{ID: rid, Quote: quote}}, nil)
}

func TestCloudFindingRAGGateMutate(t *testing.T) {
	t.Run("grounded", func(t *testing.T) {
		d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
		d.Gate = autoGate(t)
		// Service-specific hit (the imds term is present) -> acceptCitation grounds it.
		d.RC = &recSearcher{results: []retrieval.Result{
			chunk("offensive-cloud", "cloud/aws.md", "IMDS", "AWS IMDS role credential theft via 169.254.169.254."),
		}}
		cloudCorrelateOne(t, d, awsCredQuote)

		findings, gaps := cloudCandidateSplit(t, d)
		if len(findings) != 1 {
			t.Fatalf("grounded: want 1 actionable finding, got %d (%+v)", len(findings), findings)
		}
		if findings[0].Status != engagement.StatusTodo {
			t.Errorf("grounded finding must be Status=todo (armable), got %q", findings[0].Status)
		}
		if findings[0].CoverageGap {
			t.Errorf("grounded finding must have CoverageGap=false")
		}
		if findings[0].Citation.Source == "" {
			t.Errorf("grounded finding must carry a corpus citation")
		}
		if findings[0].Armed {
			t.Errorf("grounded finding must be UNARMED until the operator arms it")
		}
		if len(gaps) != 0 {
			t.Errorf("grounded path must not produce a coverage-gap: %+v", gaps)
		}
	})

	t.Run("coverage-removed", func(t *testing.T) {
		d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
		d.Gate = autoGate(t)
		d.RC = &recSearcher{results: nil} // corpus coverage removed for this detection
		cloudCorrelateOne(t, d, awsCredQuote)

		findings, gaps := cloudCandidateSplit(t, d)
		if len(findings) != 0 {
			t.Errorf("no accepted citation must mean no actionable finding, got %+v", findings)
		}
		if len(gaps) != 1 {
			t.Fatalf("coverage removed must surface exactly one coverage-gap (no silent drop), got %d", len(gaps))
		}
		if !gaps[0].CoverageGap {
			t.Errorf("coverage-gap must set the CoverageGap bool (the discriminator)")
		}
		if gaps[0].Status != engagement.StatusBlocked {
			t.Errorf("coverage-gap must be Status=blocked (not armable), got %q", gaps[0].Status)
		}
		if gaps[0].Citation != (engagement.Citation{}) {
			t.Errorf("coverage-gap must have an empty Citation, got %+v", gaps[0].Citation)
		}
		if !strings.Contains(gaps[0].Objective, "corpus-coverage-gap") {
			t.Errorf("coverage-gap must carry the shared Objective marker, got %q", gaps[0].Objective)
		}
		if len(gaps[0].BasisIDs) != 1 || gaps[0].BasisIDs[0] != "t1" {
			t.Errorf("coverage-gap must keep provenance, got %v", gaps[0].BasisIDs)
		}
	})
}

// TestCloudFindingRejectsFalseGrounding is the INVERSE false-grounding test for
// the citation-acceptance contract: a keyword-adjacent/generic top hit that does NOT
// mention the rule's service term must NOT ground (MinCitationScore is 0.0, so the
// service term is the acceptance gate) - it becomes a coverage-gap, never an
// actionable finding.
func TestCloudFindingRejectsFalseGrounding(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	d.Gate = autoGate(t)
	// Generic cloud hit with NO imds/service term -> acceptCitation rejects it.
	d.RC = &recSearcher{results: []retrieval.Result{
		chunk("misc", "cloud/overview.md", "Intro", "A general overview of cloud computing concepts and benefits."),
	}}
	cloudCorrelateOne(t, d, awsCredQuote)

	findings, gaps := cloudCandidateSplit(t, d)
	if len(findings) != 0 {
		t.Errorf("a keyword-adjacent hit must NOT ground an actionable finding, got %+v", findings)
	}
	if len(gaps) != 1 {
		t.Errorf("a keyword-adjacent hit must surface a coverage-gap, got %d", len(gaps))
	}
}
