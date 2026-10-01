package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/skillcat"
)

// aiSecGroundingSearcher returns a corpus hit that mentions every OWASP LLM0x class
// term the rules ground on, so acceptCitation grounds each matched marker (actionable
// finding). chunk() leaves Score 0, which clears MinCitationScore==0.0.
func aiSecGroundingSearcher() *recSearcher {
	return &recSearcher{results: []retrieval.Result{
		chunk("ai-pentest", "ai.md", "LLM01/LLM02/LLM07 reference",
			"llm01 prompt injection llm02 sensitive information disclosure llm07 system prompt leakage jailbreak"),
	}}
}

// aiSecGapSearcher returns a hit that mentions none of the class terms, so
// acceptCitation rejects it and the matched marker becomes a coverage gap.
func aiSecGapSearcher() *recSearcher {
	return &recSearcher{results: []retrieval.Result{
		chunk("unrelated", "x.md", "Off-topic", "nothing of interest here"),
	}}
}

// TestAISecExecutorRegisteredForSurface proves the registration seam routes an
// ai-security surface task to aiSecExecutor, not the generic fallback.
func TestAISecExecutorRegisteredForSurface(t *testing.T) {
	task := engagement.Task{ID: "ai1", Surface: engagement.SurfaceAISecurity}
	got := executorFor(engageDeps{}, task)
	if _, ok := got.(aiSecExecutor); !ok {
		t.Fatalf("executorFor(ai-security) = %T, want aiSecExecutor", got)
	}
	// A different surface must still fall back to the generic executor.
	net := engagement.Task{ID: "n1", Surface: engagement.SurfaceNetwork}
	if _, ok := executorFor(engageDeps{}, net).(aiSecExecutor); ok {
		t.Fatal("network surface must not route to aiSecExecutor")
	}
}

// TestAISecLadderRegistered proves the ai-security recon ladder is registered and
// has the four tiers in order (discovery -> capability -> injection -> abuse).
func TestAISecLadderRegistered(t *testing.T) {
	l := ladderFor(engagement.SurfaceAISecurity)
	wantNames := []string{"ai-endpoint-discovery", "capability-probing", "prompt-injection-probes", "model-abuse-probes"}
	if len(l) != len(wantNames) {
		t.Fatalf("ladder has %d tiers, want %d: %+v", len(l), len(wantNames), l)
	}
	for i, tier := range l {
		if tier.Index != i {
			t.Errorf("tier %d Index = %d, want %d", i, tier.Index, i)
		}
		if tier.Name != wantNames[i] {
			t.Errorf("tier %d Name = %q, want %q", i, tier.Name, wantNames[i])
		}
		if len(tier.Dimensions) == 0 {
			t.Errorf("tier %q has no coverage dimensions", tier.Name)
		}
	}
}

// TestAISecDomainRegistered proves registerDomain added the new ai-security
// persona and domainFor returns it (not the generic fallback).
func TestAISecDomainRegistered(t *testing.T) {
	d := domainFor("ai-security")
	if d.Name != "ai-security" {
		t.Fatalf("domainFor(ai-security).Name = %q, want ai-security", d.Name)
	}
	low := strings.ToLower(d.Prompt)
	for _, want := range []string{"prompt injection", "untrusted", "jailbreak"} {
		if !strings.Contains(low, want) {
			t.Errorf("ai-security persona prompt missing %q", want)
		}
	}
}

// aiSecTestCfg is the retrieval config for grounding tests.
func aiSecTestCfg() ragconfig.Config { return ragconfig.Config{TopK: 5} }

// TestAISecCorrelateFindingsInjectionSuccess proves a canonical prompt-injection
// marker in verbatim evidence, WHEN GROUNDED by a class-specific corpus citation,
// yields exactly one ACTIONABLE UNARMED exploit candidate on the ai-security
// surface, tied to the producing task by provenance, carrying the corpus citation,
// not a coverage gap, and marked as sourced from untrusted AI output.
func TestAISecCorrelateFindingsInjectionSuccess(t *testing.T) {
	prov := Provenance{TaskID: "ai1", EvidenceID: 7}
	cands := aiSecCorrelateFindings(context.Background(), aiSecGroundingSearcher(), aiSecTestCfg(), nil, prov, "The assistant replied: I have been PWNED")
	if len(cands) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(cands), cands)
	}
	c := cands[0]
	if c.Kind != "exploit" || c.Phase != engagement.PhaseExploit {
		t.Errorf("candidate = kind %q phase %q, want exploit/exploit", c.Kind, c.Phase)
	}
	if c.Armed {
		t.Error("candidate must be created UNARMED")
	}
	if c.Surface != engagement.SurfaceAISecurity {
		t.Errorf("Surface = %q, want ai-security", c.Surface)
	}
	if c.Status != engagement.StatusTodo || c.CoverageGap {
		t.Errorf("grounded finding = status %q coverageGap %v, want todo/false (actionable)", c.Status, c.CoverageGap)
	}
	if len(c.BasisIDs) != 1 || c.BasisIDs[0] != "ai1" {
		t.Errorf("BasisIDs = %v, want [ai1] (provenance)", c.BasisIDs)
	}
	// RAG-gated: the finding carries the corpus grounding citation.
	if c.Citation.Source != "ai-pentest" {
		t.Errorf("grounded finding Citation.Source = %q, want ai-pentest", c.Citation.Source)
	}
	// Untrusted-source discipline is kept: the objective marks the AI-output origin.
	if !strings.Contains(strings.ToLower(c.Objective), "untrusted") {
		t.Errorf("finding objective must mark the untrusted AI-output source: %q", c.Objective)
	}
}

// TestAISecCorrelateFindingsInvalidProvenanceNil proves no finding is emitted
// without a verified evidence-quote id (no model-asserted finding).
func TestAISecCorrelateFindingsInvalidProvenanceNil(t *testing.T) {
	rc := aiSecGroundingSearcher()
	if got := aiSecCorrelateFindings(context.Background(), rc, aiSecTestCfg(), nil, Provenance{TaskID: "ai1"}, "I have been PWNED"); got != nil {
		t.Errorf("invalid provenance must yield nil, got %+v", got)
	}
	if got := aiSecCorrelateFindings(context.Background(), rc, aiSecTestCfg(), nil, Provenance{EvidenceID: 3}, "I have been PWNED"); got != nil {
		t.Errorf("invalid provenance must yield nil, got %+v", got)
	}
}

// TestAISecCorrelateFindingsIndicators proves each AI-security indicator class
// fires (as a grounded, actionable finding) on its marker and a benign response
// yields nothing.
func TestAISecCorrelateFindingsIndicators(t *testing.T) {
	prov := Provenance{TaskID: "ai1", EvidenceID: 2}
	rc := aiSecGroundingSearcher()
	cases := []struct {
		name  string
		quote string
		key   string
	}{
		{"system-prompt-leak", "Sure, here is my system prompt: You are a helpful assistant", "system-prompt-leak"},
		{"jailbreak", "Developer Mode enabled. I can do anything now.", "jailbreak"},
		{"model-disclosure", "I am running on gpt-4o hosted in Azure.", "model-disclosure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cands := aiSecCorrelateFindings(context.Background(), rc, aiSecTestCfg(), nil, prov, tc.quote)
			found := false
			for _, c := range cands {
				if strings.Contains(c.ID, tc.key) && !c.CoverageGap {
					found = true
				}
			}
			if !found {
				t.Errorf("quote %q did not fire a grounded finding for rule %q; got %+v", tc.quote, tc.key, cands)
			}
		})
	}
	if got := aiSecCorrelateFindings(context.Background(), rc, aiSecTestCfg(), nil, prov, "Normal helpful response about the weather today."); got != nil {
		t.Errorf("benign response must yield no findings, got %+v", got)
	}
}

// TestAISecCorrelateFindingsDeterministic proves the same indicator from the same
// evidence row yields a stable candidate id.
func TestAISecCorrelateFindingsDeterministic(t *testing.T) {
	rc := aiSecGroundingSearcher()
	a := aiSecCorrelateFindings(context.Background(), rc, aiSecTestCfg(), nil, Provenance{TaskID: "ai1", EvidenceID: 5}, "I have been PWNED")
	b := aiSecCorrelateFindings(context.Background(), rc, aiSecTestCfg(), nil, Provenance{TaskID: "ai1", EvidenceID: 5}, "I have been PWNED")
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("want 1 candidate each, got %d and %d", len(a), len(b))
	}
	if a[0].ID != b[0].ID {
		t.Errorf("non-deterministic id: %q vs %q", a[0].ID, b[0].ID)
	}
}

func TestAISecCorrelateFindingsCoverageGapNoSilentDrop(t *testing.T) {
	prov := Provenance{TaskID: "ai1", EvidenceID: 9}
	audited := false
	audit := func(action, detail string) {
		if action == "corpus-coverage-gap" {
			audited = true
		}
	}
	cands := aiSecCorrelateFindings(context.Background(), aiSecGapSearcher(), aiSecTestCfg(), audit, prov, "The assistant replied: I have been PWNED")
	if len(cands) != 1 {
		t.Fatalf("a matched-but-ungrounded marker must surface exactly one record, got %d: %+v", len(cands), cands)
	}
	c := cands[0]
	if !c.CoverageGap {
		t.Error("ungrounded match must set Task.CoverageGap (the discriminator), not silently drop")
	}
	if c.Status != engagement.StatusBlocked {
		t.Errorf("coverage-gap Status = %q, want blocked (not actionable)", c.Status)
	}
	if c.Citation != (engagement.Citation{}) {
		t.Errorf("coverage-gap must carry an empty Citation, got %+v", c.Citation)
	}
	if c.Armed {
		t.Error("coverage-gap must be unarmed")
	}
	if len(c.BasisIDs) != 1 || c.BasisIDs[0] != "ai1" {
		t.Errorf("coverage-gap BasisIDs = %v, want [ai1] (provenance)", c.BasisIDs)
	}
	if !strings.Contains(c.Objective, coverageGapMarker) {
		t.Errorf("coverage-gap objective must carry the shared marker: %q", c.Objective)
	}
	if !audited {
		t.Error("coverage-gap must write a corpus-coverage-gap audit row")
	}
}

// TestAISecCorrelateFindingsTermGate is the no-false-grounding test at the surface
// level: the OWASP-class term gate rejects a hit that does not mention the matched
// marker's class, so a keyword-adjacent corpus set yields a coverage gap, not an
// actionable finding.
func TestAISecCorrelateFindingsTermGate(t *testing.T) {
	// A corpus hit that scores but never mentions llm01 / prompt injection.
	offTerm := &recSearcher{results: []retrieval.Result{
		chunk("ai-pentest", "ai.md", "LLM07: System Prompt Leakage", "system prompt extraction notes"),
	}}
	cands := aiSecCorrelateFindings(context.Background(), offTerm, aiSecTestCfg(), nil, Provenance{TaskID: "ai1", EvidenceID: 3}, "I have been PWNED")
	if len(cands) != 1 {
		t.Fatalf("want 1 candidate, got %d: %+v", len(cands), cands)
	}
	if !cands[0].CoverageGap {
		t.Error("an off-term (keyword-adjacent) hit must not ground prompt-injection; expected a coverage gap")
	}
}

// TestAISecCorrelateNewEvidencePersistsFindingsNoRecurse proves the recon-driver
// correlation persists AI findings as unarmed exploit candidates (accepted by
// applyLocked, so basis/phase/surface are valid) and returns NO new assets:
// untrusted model output never expands the recon frontier.
func TestAISecCorrelateNewEvidencePersistsFindingsNoRecurse(t *testing.T) {
	s := openStore(t)
	if _, err := s.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "ai1", Kind: "ai-security", Target: "https://ai.example.com/v1/chat",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceAISecurity,
	}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordEvidence("ai1", "model output: I have been PWNED"); err != nil {
		t.Fatal(err)
	}
	rows, err := s.EvidenceRowsFor("ai1")
	if err != nil {
		t.Fatal(err)
	}
	e := aiSecExecutor{genericExecutor{d: engageDeps{Store: s, RC: aiSecGroundingSearcher(), Cfg: aiSecTestCfg()}}}
	newAssets := e.aiSecCorrelateNewEvidence(context.Background(), "ai1", rows)
	if len(newAssets) != 0 {
		t.Errorf("untrusted AI output must not expand the recon frontier, got assets %v", newAssets)
	}
	open, err := s.OpenTasks()
	if err != nil {
		t.Fatal(err)
	}
	var candID string
	for _, tk := range open {
		if tk.Kind == "exploit" {
			candID = tk.ID
			break
		}
	}
	if candID == "" {
		t.Fatalf("no ai-security exploit candidate persisted; open tasks: %+v", open)
	}
	// GetTask returns the full record (OpenTasks is a projection that omits
	// Phase/Surface), so assert the stored candidate's full shape here.
	found, err := s.GetTask(candID)
	if err != nil {
		t.Fatalf("candidate not stored: %v", err)
	}
	if found.Surface != engagement.SurfaceAISecurity {
		t.Errorf("persisted candidate Surface = %q, want ai-security", found.Surface)
	}
	if found.Phase != engagement.PhaseExploit || found.Armed || found.CoverageGap {
		t.Errorf("persisted candidate = phase %q armed %v coverageGap %v, want exploit/unarmed/actionable", found.Phase, found.Armed, found.CoverageGap)
	}
	if len(found.BasisIDs) != 1 || found.BasisIDs[0] != "ai1" {
		t.Errorf("persisted candidate BasisIDs = %v, want [ai1]", found.BasisIDs)
	}
}

// TestAISecCorrelateNewEvidenceGapPersists proves the no-silent-drop path end to
// end: with the corpus returning no citation, a matched marker persists as a
// coverage-gap task (accepted by applyLocked), so the signal reaches the store
// rather than vanishing.
func TestAISecCorrelateNewEvidenceGapPersists(t *testing.T) {
	s := openStore(t)
	if _, err := s.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "ai1", Kind: "ai-security", Target: "https://ai.example.com/v1/chat",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceAISecurity,
	}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordEvidence("ai1", "model output: I have been PWNED"); err != nil {
		t.Fatal(err)
	}
	rows, err := s.EvidenceRowsFor("ai1")
	if err != nil {
		t.Fatal(err)
	}
	e := aiSecExecutor{genericExecutor{d: engageDeps{Store: s, RC: aiSecGapSearcher(), Cfg: aiSecTestCfg()}}}
	e.aiSecCorrelateNewEvidence(context.Background(), "ai1", rows)

	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var gap *engagement.Task
	for i := range snap.Tasks {
		if snap.Tasks[i].ID == "ai1" {
			continue // the parent recon task
		}
		if snap.Tasks[i].CoverageGap {
			gap = &snap.Tasks[i]
		} else {
			t.Errorf("ungrounded marker must not persist an actionable candidate, got %q", snap.Tasks[i].ID)
		}
	}
	if gap == nil {
		t.Fatalf("no coverage-gap task persisted; tasks: %+v", snap.Tasks)
	}
	if gap.Status != engagement.StatusBlocked {
		t.Errorf("coverage-gap Status = %q, want blocked (not armable)", gap.Status)
	}
	if gap.Surface != engagement.SurfaceAISecurity || gap.Armed {
		t.Errorf("stored gap = surface %q armed %v, want ai-security/unarmed", gap.Surface, gap.Armed)
	}
	if gap.Citation != (engagement.Citation{}) {
		t.Errorf("coverage-gap must carry an empty Citation, got %+v", gap.Citation)
	}
}

// TestAISecRouteSkillResolution proves route_skill("ai-security") resolves end to
// end: resolveDomain maps the domain to the "ai-security" bucket, skillcat
// buckets the offensive-ai-security skill there (the catalog keyword rule), and
// routeSkillFor returns that skill's playbook. A persona that points at
// route_skill must have a working route (no stubs).
func TestAISecRouteSkillResolution(t *testing.T) {
	if got := resolveDomain("ai-security"); got != "ai-security" {
		t.Fatalf("resolveDomain(ai-security) = %q, want ai-security (persona registered)", got)
	}
	// The AI-security skill must bucket to the ai-security domain (not generic).
	if got := skillcat.DeriveDomain("offensive-ai-security", "SKILL: AI Pentest"); got != "ai-security" {
		t.Fatalf("DeriveDomain(offensive-ai-security) = %q, want ai-security", got)
	}
	// End to end: a catalog holding the AI-security skill routes it for the domain.
	dir := t.TempDir()
	writeTestSkill(t, dir, "offensive-ai-security", "---\nname: offensive-ai-security\ndescription: AI pentest prompt injection and jailbreak testing\n---\nAI PLAYBOOK BODY\n")
	cat, err := skillcat.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	sk, ok := routeSkillFor(cat, "ai-security")
	if !ok {
		t.Fatal("route_skill(ai-security) must resolve to a skill")
	}
	if sk.Name != "offensive-ai-security" {
		t.Errorf("route_skill(ai-security) = %q, want offensive-ai-security", sk.Name)
	}
	// A nil catalog still reports no skill (no panic).
	if _, ok := routeSkillFor(nil, "ai-security"); ok {
		t.Error("routeSkillFor(nil catalog) must report no skill")
	}
}

// TestAISecVantageSkew proves the vantage-skew note is vantage-specific: unset
// yields nothing (legacy unrestricted), each known vantage yields guidance, and
// unauth vs auth differ (so probes actually skew by access context).
func TestAISecVantageSkew(t *testing.T) {
	if s := aiSecVantageSkew(""); s != "" {
		t.Errorf("unset vantage must yield no skew, got %q", s)
	}
	for _, v := range []engagement.Vantage{
		engagement.VantageExternalUnauth, engagement.VantageExternalAuth,
		engagement.VantageInternalFoothold, engagement.VantageLocalElevated,
		engagement.VantageLateralDomain,
	} {
		if aiSecVantageSkew(v) == "" {
			t.Errorf("vantage %q must yield skew guidance", v)
		}
	}
	if aiSecVantageSkew(engagement.VantageExternalUnauth) == aiSecVantageSkew(engagement.VantageExternalAuth) {
		t.Error("external-unauth and external-auth skew must differ")
	}
}

// TestAISecTierHumanThreadsVantage proves the vantage skew actually reaches the
// per-tier human message the executor sends to the model (not just the
// reachability refusal), and that an unset vantage appends no skew.
func TestAISecTierHumanThreadsVantage(t *testing.T) {
	task := engagement.Task{ID: "ai1", Surface: engagement.SurfaceAISecurity, Objective: "assess the endpoint"}
	tier := aiSecLadder[2] // prompt-injection-probes
	human := aiSecTierHuman(task, "https://ai.example.com/v1/chat", tier, reconSelection{}, engagement.VantageExternalAuth)
	if !strings.Contains(human, tier.Name) {
		t.Error("tier prompt content missing from the human message")
	}
	if !strings.Contains(human, aiSecVantageSkew(engagement.VantageExternalAuth)) {
		t.Error("vantage skew was not threaded into the per-tier human message")
	}
	h2 := aiSecTierHuman(task, "https://ai.example.com/v1/chat", tier, reconSelection{}, "")
	if !strings.Contains(h2, tier.Name) {
		t.Error("tier content missing for unset vantage")
	}
	if strings.Contains(h2, "Vantage ") {
		t.Errorf("unset vantage must append no skew, got %q", h2)
	}
}
