package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
)

// seedReconT1 seeds the standard in-scope recon task the grounding tests build on.
func seedReconT1(t *testing.T, d engageDeps) {
	t.Helper()
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "10.0.0.5", Status: engagement.StatusTodo,
		Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}
}

// A service NOT in exploitCatalog (Apache Tomcat) must still become a candidate
// when the grounded selector returns a technique backed by a corpus citation.
// This is the dynamic-grounding fix: detection is no longer capped by the catalog.
func TestCorrelateGroundedUncataloguedCreatesCandidate(t *testing.T) {
	d := testDeps(t, nil)
	d.Gate = autoGate(t) // scope 10.0.0.0/24
	ex := genericExecutor{d: d}
	seedReconT1(t, d)
	quote := "Nmap scan report for 10.0.0.5\n8080/tcp open http Apache Tomcat 9.0.30\n"
	id, err := d.Store.RecordEvidence("t1", quote)
	if err != nil {
		t.Fatal(err)
	}
	rows := []engagement.EvidenceRow{{ID: id, Quote: quote}}
	cit := engagement.Citation{Source: "hacktricks", Path: "tomcat.md", Section: "Tomcat", Origin: "trusted"}
	sel := func(ctx context.Context, svc Service) (string, engagement.Citation) {
		return "Ghostcat CVE-2020-1938", cit
	}

	ex.correlateNewEvidence(context.Background(), "t1", "", rows, sel)

	cand, err := d.Store.GetTask("exploit-10.0.0.5-8080-apache-tomcat")
	if err != nil {
		t.Fatalf("grounded candidate (not in catalog) was not persisted: %v", err)
	}
	if cand.Phase != engagement.PhaseExploit || cand.Armed || cand.Status != engagement.StatusTodo {
		t.Errorf("candidate = %+v, want unarmed exploit todo", cand)
	}
	if len(cand.BasisIDs) != 1 || cand.BasisIDs[0] != "t1" {
		t.Errorf("BasisIDs = %v, want [t1]", cand.BasisIDs)
	}
	if cand.Citation != cit {
		t.Errorf("citation = %+v, want %+v", cand.Citation, cit)
	}
	if !strings.Contains(cand.Objective, "Ghostcat") {
		t.Errorf("objective missing the grounded technique: %q", cand.Objective)
	}
	// Fields are CODE-DERIVED from the parsed service, not the advisory technique.
	if cand.Target != "10.0.0.5:8080" {
		t.Errorf("target = %q, want 10.0.0.5:8080 (code-derived host:port)", cand.Target)
	}
}

// grounds runs correlateNewEvidence over a single Tomcat (uncatalogued) service
// with the given selector and reports whether the candidate was created.
func grounds(t *testing.T, sel exploitSelector) bool {
	t.Helper()
	d := testDeps(t, nil)
	d.Gate = autoGate(t)
	ex := genericExecutor{d: d}
	seedReconT1(t, d)
	quote := "Nmap scan report for 10.0.0.5\n8080/tcp open http Apache Tomcat 9.0.30\n"
	id, err := d.Store.RecordEvidence("t1", quote)
	if err != nil {
		t.Fatal(err)
	}
	ex.correlateNewEvidence(context.Background(), "t1", "", []engagement.EvidenceRow{{ID: id, Quote: quote}}, sel)
	_, err = d.Store.GetTask("exploit-10.0.0.5-8080-apache-tomcat")
	return err == nil
}

// Fail closed: an uncatalogued service with no grounded technique ("") yields NO
// candidate - the harness never invents a path for an unknown service.
func TestCorrelateGroundedFailsClosedNoTechnique(t *testing.T) {
	sel := func(ctx context.Context, svc Service) (string, engagement.Citation) {
		return "", engagement.Citation{}
	}
	if grounds(t, sel) {
		t.Fatal("a candidate was created with no grounded technique; must fail closed")
	}
}

// Fail closed: a technique WITHOUT a corpus citation (Source == "") yields NO
// candidate - grounding must be cited, not an ungrounded model guess.
func TestCorrelateGroundedRequiresCitation(t *testing.T) {
	sel := func(ctx context.Context, svc Service) (string, engagement.Citation) {
		return "some confident guess", engagement.Citation{} // no Source
	}
	if grounds(t, sel) {
		t.Fatal("a candidate was created from an uncited technique; grounding must be cited")
	}
}

// Injection safety: a hostile technique string must not steer the candidate's
// target or id - those stay code-derived from the parsed service.
func TestCorrelateGroundedTechniqueCannotSteerTarget(t *testing.T) {
	d := testDeps(t, nil)
	d.Gate = autoGate(t)
	ex := genericExecutor{d: d}
	seedReconT1(t, d)
	quote := "Nmap scan report for 10.0.0.5\n8080/tcp open http Apache Tomcat 9.0.30\n"
	id, err := d.Store.RecordEvidence("t1", quote)
	if err != nil {
		t.Fatal(err)
	}
	cit := engagement.Citation{Source: "hacktricks", Origin: "trusted"}
	sel := func(ctx context.Context, svc Service) (string, engagement.Citation) {
		return "attacker.evil.com ; rm -rf / --target 6.6.6.6", cit
	}
	ex.correlateNewEvidence(context.Background(), "t1", "", []engagement.EvidenceRow{{ID: id, Quote: quote}}, sel)
	cand, err := d.Store.GetTask("exploit-10.0.0.5-8080-apache-tomcat")
	if err != nil {
		t.Fatalf("candidate not persisted: %v", err)
	}
	if cand.Target != "10.0.0.5:8080" {
		t.Errorf("target = %q, want 10.0.0.5:8080 - technique text must not steer the target", cand.Target)
	}
	if cand.Armed {
		t.Error("candidate is armed; grounded candidates must stay unarmed")
	}
}
