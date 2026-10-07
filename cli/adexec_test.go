package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/secgate"

	"github.com/tmc/langchaingo/llms"
)

// TestADLadderIsFourTierEnumerationLadder pins the registered SurfaceAD recon
// ladder: four tiers, enumeration -> targeted enum -> finding-driven, replacing
// the generic single-tier fallback. Code owns the tiers; the LLM only proposes
// commands within one.
func TestADLadderIsFourTierEnumerationLadder(t *testing.T) {
	l := ladderFor(engagement.SurfaceAD)
	want := []struct {
		name string
		dims []string
	}{
		{"ad-dc-discovery", []string{"dcs", "domain"}},
		{"ad-anon-enum", []string{"naming-contexts", "null-sessions"}},
		{"ad-auth-enum", []string{"users", "groups", "computers"}},
		{"ad-finding-driven", []string{"spns", "delegation", "acls", "adcs"}},
	}
	if len(l) != len(want) {
		t.Fatalf("ad ladder has %d tiers, want %d", len(l), len(want))
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

// TestExecutorForADReturnsADExecutor pins the registration seam: a SurfaceAD task
// resolves to adExecutor, not the bare genericExecutor fallback.
func TestExecutorForADReturnsADExecutor(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	ex := executorFor(d, engagement.Task{ID: "t", Surface: engagement.SurfaceAD, Kind: "ad"})
	if _, ok := ex.(adExecutor); !ok {
		t.Fatalf("executorFor(SurfaceAD) = %T, want adExecutor", ex)
	}
}

// TestADExecutorRefusesOutOfVantage pins that the AD surface is post-foothold:
// adExecutor refuses an AD task at external-unauth vantage (SurfaceAD is not
// reachable until internal-foothold), then runs it once the vantage advances.
// This exercises adExecutor's delegation to the embedded genericExecutor's
// vantage gate (a custom Run that dropped the delegation would break this).
func TestADExecutorRefusesOutOfVantage(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	d.ReconTiers = false // generic loop; the scripted "done" ends it immediately

	ext := engagement.VantageExternalUnauth
	if _, err := d.Store.Apply(engagement.Delta{SetVantage: &ext}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "ad1", Kind: "ad", Target: "10.0.0.10", Objective: "enumerate the domain",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceAD,
	}}}); err != nil {
		t.Fatal(err)
	}
	ex := adExecutor{genericExecutor{d: d}}

	task, err := d.Store.GetTask("ad1")
	if err != nil {
		t.Fatal(err)
	}
	out, err := ex.Run(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "not reachable at the current vantage") {
		t.Fatalf("ad task at external-unauth must be refused, got %q", out)
	}

	internal := engagement.VantageInternalFoothold
	if _, err := d.Store.Apply(engagement.Delta{SetVantage: &internal}); err != nil {
		t.Fatal(err)
	}
	task2, err := d.Store.GetTask("ad1")
	if err != nil {
		t.Fatal(err)
	}
	out2, err := ex.Run(context.Background(), task2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out2, "not reachable at the current vantage") {
		t.Fatalf("ad task must run after advancing to internal-foothold, got refusal: %q", out2)
	}
}

// adScopedGate builds an Auto gate whose in-scope is an AD subnet CIDR with one DC
// listed out-of-scope, and nmap allowlisted, mirroring how an AD engagement
// expresses domain/tenant scope (DC hosts + subnet CIDR; out-of-scope wins).
func adScopedGate(t *testing.T) *secgate.Gate {
	t.Helper()
	s, err := secgate.ParseScope(strings.NewReader("10.0.0.0/24\n!10.0.0.10\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &secgate.Gate{Mode: secgate.Auto, Scope: s, Allow: secgate.NewAllowlist("nmap")}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestADDomainScopeOutOfScopeFailsClosed(t *testing.T) {
	g := adScopedGate(t)
	ctx := context.Background()

	excluded := secgate.Command{
		Binary: "nmap", Args: []string{"-p", "389", "10.0.0.10"},
		Phase: secgate.PhaseRecon, Surface: secgate.Surface("ad"),
	}
	if d := g.Authorize(ctx, excluded); d.Allowed {
		t.Fatalf("out-of-scope DC 10.0.0.10 must be denied (out wins), got allowed")
	}

	inScope := secgate.Command{
		Binary: "nmap", Args: []string{"-p", "389", "10.0.0.20"},
		Phase: secgate.PhaseRecon, Surface: secgate.Surface("ad"),
	}
	if d := g.Authorize(ctx, inScope); !d.Allowed {
		t.Fatalf("in-scope DC 10.0.0.20 must be allowed, got denied: %s", d.Reason)
	}
}

// TestADPostExRequiresArm pins that an AD exploit/post-ex action is tier-gated:
// an unarmed post-ex command on the AD surface is denied (arm required), the
// control for blast-radius-sensitive AD actions (directory writes, DCSync,
// relay, ...). Per-action confirmation is additionally enforced by the gate's
// confirm tail (covered by the secgate suite). No destructive default: the base
// never reaches this phase; this guards the inherited tier if depth lands later.
func TestADPostExRequiresArm(t *testing.T) {
	g := adScopedGate(t)
	unarmed := secgate.Command{
		Binary: "nmap", Args: []string{"-p", "389", "10.0.0.20"},
		Phase: secgate.PhasePostEx, Surface: secgate.Surface("ad"), Armed: false,
	}
	d := g.Authorize(context.Background(), unarmed)
	if d.Allowed {
		t.Fatalf("unarmed post-ex AD command must be denied, got allowed")
	}
	if !strings.Contains(strings.ToLower(d.Reason), "arm") {
		t.Fatalf("denial reason should name the arm requirement, got %q", d.Reason)
	}
}

// adCorrelateSamba drives the shared correlation path (correlateNewEvidence)
// exactly as adExecutor inherits it, over an nmap -sV quote that yields a
// catalogued AD-host service (Samba smbd on an in-scope DC produced by an AD recon
// task), with the given service selector, and returns the single emitted exploit
// candidate. The term the gate keys on is citationTerm("Samba smbd") == "samba"
// (the shared-SERVICE term for the AD base).
func adCorrelateSamba(t *testing.T, sel exploitSelector) engagement.Task {
	t.Helper()
	d := testDeps(t, nil)
	d.Gate = autoGate(t) // scope 10.0.0.0/24
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "adr1", Kind: "ad", Target: "10.0.0.10", Status: engagement.StatusTodo,
		Phase: engagement.PhaseRecon, Surface: engagement.SurfaceAD,
	}}}); err != nil {
		t.Fatal(err)
	}
	quote := "Nmap scan report for 10.0.0.10\n445/tcp open netbios-ssn Samba smbd 4.15.13\n"
	id, err := d.Store.RecordEvidence("adr1", quote)
	if err != nil {
		t.Fatal(err)
	}
	ex := adExecutor{genericExecutor{d: d}}
	ex.correlateNewEvidence(context.Background(), "adr1", "", []engagement.EvidenceRow{{ID: id, Quote: quote}}, sel)
	return soleExploitCandidate(t, d)
}

// soleExploitCandidate returns the single Kind=="exploit" candidate in the store,
// failing if there is not exactly one (robust to the candidate id scheme).
func soleExploitCandidate(t *testing.T, d engageDeps) engagement.Task {
	t.Helper()
	snap, err := d.Store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var cands []engagement.Task
	for _, tk := range snap.Tasks {
		if tk.Kind == "exploit" {
			cands = append(cands, tk)
		}
	}
	if len(cands) != 1 {
		t.Fatalf("want exactly 1 exploit candidate, got %d: %+v", len(cands), cands)
	}
	return cands[0]
}

func TestADDetectionNoSilentDropOnCorpusGap(t *testing.T) {
	cit := engagement.Citation{Source: "hacktricks", Path: "samba.md", Section: "Samba", Origin: "trusted"}
	grounded := adCorrelateSamba(t, func(ctx context.Context, svc Service) (string, engagement.Citation) {
		return "known-CVE exploitation of Samba", cit
	})
	if grounded.CoverageGap {
		t.Errorf("grounded candidate must not be a coverage gap: %+v", grounded)
	}
	if grounded.Status != engagement.StatusTodo {
		t.Errorf("grounded candidate Status = %q, want todo", grounded.Status)
	}
	if grounded.Citation.Source == "" {
		t.Errorf("grounded candidate must carry a citation, got empty")
	}

	gap := adCorrelateSamba(t, func(ctx context.Context, svc Service) (string, engagement.Citation) {
		return "", engagement.Citation{}
	})
	if !gap.CoverageGap {
		t.Fatalf("mutated case must surface a coverage gap (no silent drop): %+v", gap)
	}
	if gap.Status != engagement.StatusBlocked {
		t.Errorf("coverage-gap candidate Status = %q, want blocked (not armable)", gap.Status)
	}
	if gap.Citation.Source != "" {
		t.Errorf("coverage-gap candidate must have an empty citation, got %+v", gap.Citation)
	}
	if !strings.Contains(gap.Objective, coverageGapMarker) {
		t.Errorf("coverage-gap candidate Objective missing the marker: %q", gap.Objective)
	}
}

// TestADDetectionRejectsNonSpecificCitation pins that the citation acceptance gate
// is SPECIFICITY, not score (MinCitationScore == 0): a high-scoring hit that does
// not mention the service term "samba" is REJECTED -> coverage gap, while a
// product-specific hit at the same score grounds. Exercises the real acceptCitation
// + citationTerm through the AD surface's correlation path.
func TestADDetectionRejectsNonSpecificCitation(t *testing.T) {
	nonSpecific := []retrieval.Result{{
		Score:   0.99,
		Payload: retrieval.Payload{Source: "hacktricks", Path: "smb-enum.md", Section: "SMB Enumeration", Text: "General SMB protocol enumeration notes."},
	}}
	gap := adCorrelateSamba(t, func(ctx context.Context, svc Service) (string, engagement.Citation) {
		c, ok := acceptCitation(nonSpecific, citationTerm(svc.Product))
		if !ok {
			return "", engagement.Citation{}
		}
		return "known-CVE", c
	})
	if !gap.CoverageGap || gap.Status != engagement.StatusBlocked {
		t.Fatalf("a high-score non-specific hit must be rejected -> coverage gap, got %+v", gap)
	}

	// The service term is the full phrase "samba smbd" (citationTerm), matched
	// all-tokens on word boundaries, so a grounding hit must mention BOTH tokens.
	specific := []retrieval.Result{{
		Score:   0.99,
		Payload: retrieval.Payload{Source: "hacktricks", Path: "samba.md", Section: "Samba smbd RCE", Text: "Samba smbd CVE-2017-7494 remote code execution."},
	}}
	grounded := adCorrelateSamba(t, func(ctx context.Context, svc Service) (string, engagement.Citation) {
		c, ok := acceptCitation(specific, citationTerm(svc.Product))
		if !ok {
			return "", engagement.Citation{}
		}
		return "known-CVE", c
	})
	if grounded.CoverageGap || grounded.Status != engagement.StatusTodo {
		t.Fatalf("a product-specific hit at the same score must ground, got %+v", grounded)
	}
}

// TestADDetectionRejectsVendorSiblingCitation pins the citationTerm behavior (full
// lowercased phrase + all-tokens word-boundary match): a sibling hit that mentions
// only PART of the service phrase ("samba" but not "smbd") must NOT ground (the old
// f[0]-only term would have grounded it), while a hit mentioning the FULL phrase
// still grounds under the word-boundary matcher.
func TestADDetectionRejectsVendorSiblingCitation(t *testing.T) {
	sibling := []retrieval.Result{{
		Score:   0.99,
		Payload: retrieval.Payload{Source: "hacktricks", Path: "swat.md", Section: "Samba Web Admin Tool", Text: "Samba Web Administration Tool configuration notes."},
	}}
	gap := adCorrelateSamba(t, func(ctx context.Context, svc Service) (string, engagement.Citation) {
		c, ok := acceptCitation(sibling, citationTerm(svc.Product))
		if !ok {
			return "", engagement.Citation{}
		}
		return "known-CVE", c
	})
	if !gap.CoverageGap || gap.Status != engagement.StatusBlocked {
		t.Fatalf("a sibling hit matching only part of the service phrase must be rejected -> coverage gap, got %+v", gap)
	}

	full := []retrieval.Result{{
		Score:   0.80,
		Payload: retrieval.Payload{Source: "hacktricks", Path: "samba.md", Section: "Samba smbd RCE", Text: "Samba smbd CVE-2017-7494 remote code execution."},
	}}
	grounded := adCorrelateSamba(t, func(ctx context.Context, svc Service) (string, engagement.Citation) {
		c, ok := acceptCitation(full, citationTerm(svc.Product))
		if !ok {
			return "", engagement.Citation{}
		}
		return "known-CVE", c
	})
	if grounded.CoverageGap || grounded.Status != engagement.StatusTodo {
		t.Fatalf("a full-phrase hit must still ground under the word-boundary matcher, got %+v", grounded)
	}
}

// TestADCoverageGapNotDispatchedAndNotArmable is the point-5b combined per-surface
// soundness test: an AD coverage-gap candidate (deterministic detector matched, no
// accepted citation -> Status blocked + CoverageGap) is non-actionable on BOTH
// enforcement seams - the model never auto-dispatches it, and the operator arm seam
// (armTask) REJECTS it. Non-vacuous: removing the dispatch skip makes it dispatch;
// removing the armTask guard makes the arm succeed.
func TestADCoverageGapNotDispatchedAndNotArmable(t *testing.T) {
	d := testDeps(t, nil)
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "adgap", Kind: "exploit", Target: "10.0.0.10:445", Objective: "uncited AD coverage-gap",
		Status: engagement.StatusBlocked, Phase: engagement.PhaseExploit, Surface: engagement.SurfaceAD, CoverageGap: true,
	}}}); err != nil {
		t.Fatal(err)
	}

	var ran atomic.Int32
	exec := func(ctx context.Context, d engageDeps, id string) (string, error) {
		ran.Add(1)
		return id, nil
	}
	out, err := newDispatchBatchToolWith(d, exec).Call(context.Background(), `{"task_ids":["adgap"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if ran.Load() != 0 {
		t.Errorf("an ad coverage-gap candidate must NOT be dispatched: ran=%d", ran.Load())
	}
	if !strings.Contains(out, "blocked") {
		t.Errorf("ad coverage-gap must be skipped with a blocked note: out=%q", out)
	}

	if err := armTask(context.Background(), d.Store, "adgap"); err == nil {
		t.Fatal("armTask must REJECT an ad coverage-gap (blocked) task, got nil error")
	}
	got, err := d.Store.GetTask("adgap")
	if err != nil {
		t.Fatal(err)
	}
	if got.Armed {
		t.Error("ad coverage-gap task must remain unarmed after a rejected arm")
	}
	if got.Status != engagement.StatusBlocked {
		t.Errorf("ad coverage-gap task status = %q, want blocked (unchanged)", got.Status)
	}
}

// TestADLogicGapGatedSamePath is the completeness arm: the shared logic-gap path
// (groundCandidate via engageDeps.RC) gates identically. The AD path rarely emits
// logic-gap candidates, but correlateNewEvidence runs correlateLogicGaps on every
// quote, so an AD evidence quote that trips the force-browse rule must ground with
// a corpus hit and surface a coverage gap without one.
func TestADLogicGapGatedSamePath(t *testing.T) {
	run := func(t *testing.T, results []retrieval.Result) engagement.Task {
		t.Helper()
		d := testDeps(t, nil)
		d.Gate = autoGate(t)
		d.RC = &recSearcher{results: results}
		if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
			ID: "adr2", Kind: "ad", Target: "10.0.0.10", Status: engagement.StatusTodo,
			Phase: engagement.PhaseRecon, Surface: engagement.SurfaceAD,
		}}}); err != nil {
			t.Fatal(err)
		}
		quote := "serviceConnectionPoint keyword: https://dc.corp.local/admin\n"
		id, err := d.Store.RecordEvidence("adr2", quote)
		if err != nil {
			t.Fatal(err)
		}
		ex := adExecutor{genericExecutor{d: d}}
		ex.correlateNewEvidence(context.Background(), "adr2", "", []engagement.EvidenceRow{{ID: id, Quote: quote}}, nil)
		return soleExploitCandidate(t, d)
	}

	// The force-browse rule grounds on its skill term "forced browsing", matched
	// all-tokens on word boundaries, so the hit must mention both "forced" and
	// "browsing".
	grounded := run(t, []retrieval.Result{{
		Score:   0.9,
		Payload: retrieval.Payload{Source: "offensive-business-logic", Path: "fb.md", Section: "Forced Browsing", Text: "Forced browsing to privileged admin paths (missing function-level access control)."},
	}})
	if grounded.CoverageGap || grounded.Status != engagement.StatusTodo {
		t.Errorf("grounded logic-gap candidate must be todo, got %+v", grounded)
	}

	gap := run(t, nil)
	if !gap.CoverageGap || gap.Status != engagement.StatusBlocked {
		t.Errorf("logic-gap with no citation must be a coverage gap, got %+v", gap)
	}
}
