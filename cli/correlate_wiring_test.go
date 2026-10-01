package main

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

// TestCorrelateNewEvidenceInScopeAndCandidates: the live recon wiring parses a
// tier pass's evidence into in-scope new assets (for per-asset recursion) and
// persisted candidate exploit tasks, and drops an out-of-scope asset.
func TestCorrelateNewEvidenceInScopeAndCandidates(t *testing.T) {
	d := testDeps(t, nil)
	d.Gate = autoGate(t) // scope 10.0.0.0/24
	ex := genericExecutor{d: d}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "10.0.0.5", Status: engagement.StatusTodo,
		Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}
	quote := "Nmap scan report for 10.0.0.42\n" +
		"22/tcp open ssh OpenSSH 8.2p1\n" +
		"Nmap scan report for 8.8.8.8\n"
	id, err := d.Store.RecordEvidence("t1", quote)
	if err != nil {
		t.Fatal(err)
	}
	rows := []engagement.EvidenceRow{{ID: id, Quote: quote}}

	// nil selector = no grounding available. Per the citation-gate contract a
	// deterministic catalog match with no accepted citation is NOT dropped and NOT
	// emitted as an actionable candidate: it is surfaced as a non-actionable
	// coverage-gap (Status blocked, empty Citation, Objective marker). In-scope
	// asset recursion is unaffected.
	newAssets := ex.correlateNewEvidence(context.Background(), "t1", rows, nil)
	if len(newAssets) != 1 || newAssets[0] != "10.0.0.42" {
		t.Fatalf("newAssets = %v, want [10.0.0.42] (8.8.8.8 is out of scope and dropped)", newAssets)
	}
	cand, err := d.Store.GetTask("exploit-10.0.0.42-22-openssh")
	if err != nil {
		t.Fatalf("candidate exploit task not persisted (no-silent-drop violated): %v", err)
	}
	if cand.Phase != engagement.PhaseExploit || cand.Armed {
		t.Errorf("candidate = %+v, want unarmed exploit", cand)
	}
	if cand.Status != engagement.StatusBlocked {
		t.Errorf("uncited catalog match Status = %q, want blocked (non-actionable coverage-gap)", cand.Status)
	}
	if cand.Citation != (engagement.Citation{}) {
		t.Errorf("coverage-gap candidate must have empty Citation, got %+v", cand.Citation)
	}
	if !strings.Contains(cand.Objective, "corpus-coverage-gap") {
		t.Errorf("coverage-gap candidate Objective missing the gap marker: %q", cand.Objective)
	}
	if len(cand.BasisIDs) != 1 || cand.BasisIDs[0] != "t1" {
		t.Errorf("candidate BasisIDs = %v, want [t1]", cand.BasisIDs)
	}
}

// TestCorrelateNewEvidenceCandidateCarriesCitation: when the selector advises a
// technique, the persisted candidate carries the structured corpus citation
// (source/path/section/cwe_class + origin) so the REPL can render the source line.
func TestCorrelateNewEvidenceCandidateCarriesCitation(t *testing.T) {
	d := testDeps(t, nil)
	d.Gate = autoGate(t) // scope 10.0.0.0/24
	ex := genericExecutor{d: d}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "10.0.0.5", Status: engagement.StatusTodo,
		Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}
	quote := "Nmap scan report for 10.0.0.5\n22/tcp open ssh OpenSSH 8.2p1\n"
	id, err := d.Store.RecordEvidence("t1", quote)
	if err != nil {
		t.Fatal(err)
	}
	rows := []engagement.EvidenceRow{{ID: id, Quote: quote}}
	cit := engagement.Citation{Source: "offensive-rce", Path: "ssh.md", Section: "SSH", CWEClass: "rce", Origin: "trusted"}
	sel := func(ctx context.Context, svc Service) (string, engagement.Citation) {
		return "CVE-2020-15778", cit
	}

	ex.correlateNewEvidence(context.Background(), "t1", rows, sel)

	cand, err := d.Store.GetTask("exploit-10.0.0.5-22-openssh")
	if err != nil {
		t.Fatalf("candidate exploit task not persisted: %v", err)
	}
	if cand.Citation != cit {
		t.Fatalf("candidate citation = %+v, want %+v", cand.Citation, cit)
	}
	if !strings.Contains(cand.Objective, "CVE-2020-15778") {
		t.Errorf("candidate objective missing the advised technique: %q", cand.Objective)
	}
}

func TestCorrelateNewEvidenceMutateCoverageGap(t *testing.T) {
	d := testDeps(t, nil)
	d.Gate = autoGate(t)
	ex := genericExecutor{d: d}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "10.0.0.5", Status: engagement.StatusTodo,
		Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}
	quote := "Nmap scan report for 10.0.0.5\n22/tcp open ssh OpenSSH 8.2p1\n"
	id, err := d.Store.RecordEvidence("t1", quote)
	if err != nil {
		t.Fatal(err)
	}
	rows := []engagement.EvidenceRow{{ID: id, Quote: quote}}
	// Corpus coverage REMOVED: the selector grounds nothing for a known catalog match.
	coverageRemoved := func(ctx context.Context, svc Service) (string, engagement.Citation) {
		return "", engagement.Citation{}
	}
	ex.correlateNewEvidence(context.Background(), "t1", rows, coverageRemoved)

	cand, err := d.Store.GetTask("exploit-10.0.0.5-22-openssh")
	if err != nil {
		t.Fatalf("coverage-gap candidate was DROPPED (no-silent-drop violated): %v", err)
	}
	if cand.Status != engagement.StatusBlocked {
		t.Errorf("Status = %q, want blocked (non-actionable); an uncited match must NOT be a todo candidate", cand.Status)
	}
	if !cand.CoverageGap {
		t.Errorf("CoverageGap = false, want true (structured discriminator for the UI/Auditor)")
	}
	if cand.Citation != (engagement.Citation{}) {
		t.Errorf("coverage-gap Citation = %+v, want empty", cand.Citation)
	}
	if !strings.Contains(cand.Objective, "corpus-coverage-gap") {
		t.Errorf("Objective missing gap marker: %q", cand.Objective)
	}
}

func TestCorrelateNewEvidenceLogicGapGated(t *testing.T) {
	quote := "GET /api/orders?order_id=1001 HTTP/1.1\n"
	seed := func(d engageDeps) string {
		if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
			ID: "t1", Kind: "web", Target: "10.0.0.5", Status: engagement.StatusTodo,
			Phase: engagement.PhaseRecon, Surface: engagement.SurfaceWeb,
		}}}); err != nil {
			t.Fatal(err)
		}
		id, err := d.Store.RecordEvidence("t1", quote)
		if err != nil {
			t.Fatal(err)
		}
		return "bizlogic-idor-t1-" + strconv.FormatInt(id, 10)
	}

	t.Run("no corpus -> coverage-gap blocked", func(t *testing.T) {
		d := testDeps(t, nil) // RC nil: logic-gap grounding cannot find a citation
		d.Gate = autoGate(t)
		gapID := seed(d)
		rows, _ := d.Store.EvidenceRowsFor("t1")
		genericExecutor{d: d}.correlateNewEvidence(context.Background(), "t1", rows, nil)
		cand, err := d.Store.GetTask(gapID)
		if err != nil {
			t.Fatalf("logic-gap candidate dropped: %v", err)
		}
		if cand.Status != engagement.StatusBlocked {
			t.Errorf("Status = %q, want blocked (ungrounded logic-gap)", cand.Status)
		}
	})

	t.Run("corpus covers technique -> grounded todo", func(t *testing.T) {
		d := testDeps(t, nil)
		d.Gate = autoGate(t)
		d.RC = &recSearcher{results: []retrieval.Result{
			chunk("offensive-idor", "idor.md", "IDOR", "insecure direct object reference abuse"),
		}}
		gapID := seed(d)
		rows, _ := d.Store.EvidenceRowsFor("t1")
		genericExecutor{d: d}.correlateNewEvidence(context.Background(), "t1", rows, nil)
		cand, err := d.Store.GetTask(gapID)
		if err != nil {
			t.Fatalf("logic-gap candidate missing: %v", err)
		}
		if cand.Status != engagement.StatusTodo {
			t.Errorf("Status = %q, want todo (grounded)", cand.Status)
		}
		if cand.Citation.Source != "offensive-idor" {
			t.Errorf("Citation.Source = %q, want offensive-idor", cand.Citation.Source)
		}
	})
}

func TestLogicGapClassTermGate(t *testing.T) {
	quote := "GET /api/orders?order_id=1001 HTTP/1.1\n" // trips the idor rule (term "idor")
	seed := func(d engageDeps) string {
		if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
			ID: "t1", Kind: "web", Target: "10.0.0.5", Status: engagement.StatusTodo,
			Phase: engagement.PhaseRecon, Surface: engagement.SurfaceWeb,
		}}}); err != nil {
			t.Fatal(err)
		}
		id, err := d.Store.RecordEvidence("t1", quote)
		if err != nil {
			t.Fatal(err)
		}
		return "bizlogic-idor-t1-" + strconv.FormatInt(id, 10)
	}

	t.Run("off-class citation -> coverage-gap blocked (no false grounding)", func(t *testing.T) {
		d := testDeps(t, nil)
		d.Gate = autoGate(t)

		d.RC = &recSearcher{results: []retrieval.Result{
			chunk("offensive-xss", "xss.md", "XSS", "cross-site scripting payloads and filter evasion"),
		}}
		gapID := seed(d)
		rows, _ := d.Store.EvidenceRowsFor("t1")
		genericExecutor{d: d}.correlateNewEvidence(context.Background(), "t1", rows, nil)
		cand, err := d.Store.GetTask(gapID)
		if err != nil {
			t.Fatalf("logic-gap candidate dropped (no-silent-drop violated): %v", err)
		}
		if cand.Status != engagement.StatusBlocked {
			t.Errorf("Status = %q, want blocked (off-class citation must not ground)", cand.Status)
		}
		if cand.Citation.Source != "" {
			t.Errorf("Citation.Source = %q, want empty (no accepted citation)", cand.Citation.Source)
		}
	})

	t.Run("in-class citation -> grounded todo", func(t *testing.T) {
		d := testDeps(t, nil)
		d.Gate = autoGate(t)
		d.RC = &recSearcher{results: []retrieval.Result{
			chunk("offensive-idor", "idor.md", "IDOR", "insecure direct object reference abuse"),
		}}
		gapID := seed(d)
		rows, _ := d.Store.EvidenceRowsFor("t1")
		genericExecutor{d: d}.correlateNewEvidence(context.Background(), "t1", rows, nil)
		cand, err := d.Store.GetTask(gapID)
		if err != nil {
			t.Fatalf("logic-gap candidate missing: %v", err)
		}
		if cand.Status != engagement.StatusTodo {
			t.Errorf("Status = %q, want todo (in-class citation grounds)", cand.Status)
		}
	})
}

// TestVantageAdvanceUnlocksLockedSurface: a local-surface task is refused at
// external-unauth; a simulated access-yielding exploit advances the vantage,
// which seeds new-vantage recon (per-asset T0) and unlocks the local surface so
// the task runs.
func TestVantageAdvanceUnlocksLockedSurface(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	d.ReconTiers = false // generic loop; the scripted "done" ends it immediately

	ext := engagement.VantageExternalUnauth
	if _, err := d.Store.Apply(engagement.Delta{SetVantage: &ext}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "loc", Kind: "local", Target: "10.0.0.5", Objective: "enumerate", Status: engagement.StatusTodo,
		Phase: engagement.PhaseRecon, Surface: engagement.SurfaceLocal,
	}}}); err != nil {
		t.Fatal(err)
	}
	ex := genericExecutor{d: d}

	task, err := d.Store.GetTask("loc")
	if err != nil {
		t.Fatal(err)
	}
	out, err := ex.Run(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "not reachable at the current vantage") {
		t.Fatalf("local task at external-unauth must be refused, got %q", out)
	}

	// Simulated successful access-yielding exploit advances the vantage.
	if err := advanceVantage(context.Background(), d.Store, engagement.VantageInternalFoothold, "10.0.0.5", ""); err != nil {
		t.Fatalf("advanceVantage: %v", err)
	}
	if _, err := d.Store.GetTask(reconTaskID("10.0.0.5") + "-local"); err != nil {
		t.Fatalf("advance did not seed a per-asset local recon T0 task: %v", err)
	}

	task2, err := d.Store.GetTask("loc")
	if err != nil {
		t.Fatal(err)
	}
	out2, err := ex.Run(context.Background(), task2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out2, "not reachable at the current vantage") {
		t.Fatalf("local task must run after the vantage advance, got refusal: %q", out2)
	}
}
