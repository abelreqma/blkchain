package main

import (
	"strings"
	"testing"

	eng "blkchain/cli/internal/engagement"
)

// exploitCandidates returns the unarmed exploit and post-ex tasks (the detections
// that need arming), and nothing else.
func TestExploitCandidatesFilter(t *testing.T) {
	e := eng.Engagement{Tasks: []eng.Task{
		{ID: "t1", Kind: "recon", Objective: "enumerate", Phase: eng.PhaseRecon},
		{ID: "t2", Kind: "web", Objective: "SQLi on /login", Phase: eng.PhaseExploit, Surface: eng.SurfaceWeb, BasisIDs: []string{"F-2"}},
		{ID: "t3", Kind: "web", Objective: "already armed", Phase: eng.PhaseExploit, Armed: true},
		{ID: "t4", Kind: "local", Objective: "sudo abuse", Phase: eng.PhasePostEx},
		{ID: "t5", Kind: "report", Objective: "write up", Phase: eng.PhaseReport},
	}}
	got := exploitCandidates(e)
	if len(got) != 2 {
		t.Fatalf("want 2 candidates (unarmed exploit + post-ex), got %d: %+v", len(got), got)
	}
	if got[0].ID != "t2" || got[1].ID != "t4" {
		t.Fatalf("wrong candidates: %s, %s", got[0].ID, got[1].ID)
	}
}

// renderCandidates shows each detection's label, surface, armed state, basis, and
// the source (finding-evidence fallback until structured provenance lands); empty
// renders a clear empty state.
func TestRenderCandidates(t *testing.T) {
	noColor(t)
	cands := []eng.Task{
		{ID: "t2", Kind: "web", Objective: "SQLi on /login", Phase: eng.PhaseExploit, Surface: eng.SurfaceWeb, BasisIDs: []string{"F-2"}},
	}
	out := renderCandidates(cands)
	for _, w := range []string{"SQLi on /login", "web", "unarmed", "basis", "F-2", "source", "finding evidence"} {
		if !strings.Contains(out, w) {
			t.Errorf("renderCandidates missing %q:\n%s", w, out)
		}
	}
	if empty := renderCandidates(nil); !strings.Contains(empty, "no exploit candidates") {
		t.Errorf("empty state = %q", empty)
	}
}

// candidatesBlock reads the view's snapshot; a nil view says no engagement is
// running, and a snapshot with candidates renders them.
func TestCandidatesBlock(t *testing.T) {
	noColor(t)
	if got := candidatesBlock(nil); !strings.Contains(got, "no engagement") {
		t.Errorf("nil view = %q", got)
	}
	stub := newStubEngagement("acme")
	stub.setSnapshot(eng.Engagement{Tasks: []eng.Task{
		{ID: "t2", Kind: "web", Objective: "SQLi on /login", Phase: eng.PhaseExploit, Surface: eng.SurfaceWeb},
	}})
	if got := candidatesBlock(stub); !strings.Contains(got, "SQLi on /login") {
		t.Errorf("candidatesBlock dropped the candidate:\n%s", got)
	}
}

// /candidates has a dispatch case and does not panic in either state.
func TestCandidatesCommandDispatches(t *testing.T) {
	m := newTestModel(t)
	if _, cmd := m.dispatchInput("/candidates"); cmd == nil {
		t.Fatalf("/candidates with no engagement should still print something")
	}
	stub := newStubEngagement("acme")
	stub.setSnapshot(eng.Engagement{Tasks: []eng.Task{{ID: "t2", Kind: "web", Objective: "SQLi on /login", Phase: eng.PhaseExploit}}})
	m.engagement = stub
	if _, cmd := m.dispatchInput("/candidates"); cmd == nil {
		t.Fatalf("/candidates with an engagement should print the list")
	}
}

// candidateNotice is the one-line detection notice committed when a new candidate
// appears: the label, surface, and the source fallback.
func TestCandidateNotice(t *testing.T) {
	noColor(t)
	out := candidateNotice(eng.Task{ID: "t2", Kind: "web", Objective: "SQLi on /login", Phase: eng.PhaseExploit, Surface: eng.SurfaceWeb})
	for _, w := range []string{"candidate", "SQLi on /login", "web", "finding evidence"} {
		if !strings.Contains(out, w) {
			t.Errorf("candidateNotice missing %q: %q", w, out)
		}
	}
}

// unnoticedCandidates returns only the candidates not already in the noticed set.
func TestUnnoticedCandidates(t *testing.T) {
	noticed := map[string]bool{"t1": true}
	cands := []eng.Task{{ID: "t1"}, {ID: "t2"}, {ID: "t3"}}
	got := unnoticedCandidates(noticed, cands)
	if len(got) != 2 || got[0].ID != "t2" || got[1].ID != "t3" {
		t.Fatalf("unnoticedCandidates = %+v; want t2,t3", got)
	}
}

// A candidateScanMsg prints a notice for each newly-seen candidate and marks it
// noticed, so a candidate is announced exactly once across polls.
func TestCandidateScanNoticesNewOnlyOnce(t *testing.T) {
	m := newTestModel(t)
	m.noticedCandidates = map[string]bool{"t1": true}
	cands := []eng.Task{
		{ID: "t1", Kind: "web", Objective: "old", Phase: eng.PhaseExploit},
		{ID: "t2", Kind: "web", Objective: "SQLi", Phase: eng.PhaseExploit},
	}
	nm, cmd := m.Update(candidateScanMsg{cands: cands})
	m = nm.(model)
	if !m.noticedCandidates["t2"] {
		t.Fatalf("t2 should be marked noticed")
	}
	if cmd == nil {
		t.Fatalf("a new candidate should produce a notice command")
	}
	// A second scan with the same candidates announces nothing new.
	nm, cmd = m.Update(candidateScanMsg{cands: cands})
	if cmd != nil {
		t.Fatalf("no new candidates should produce no notice: %v", cmd)
	}
}

// candidateSource renders the structured provenance when a Citation is present
// (kb source/section/cwe for trusted, a web lead + untrusted flag for web), and
// the finding-evidence fallback when the Citation is empty.
func TestCandidateSource(t *testing.T) {
	if got, unt := candidateSource(eng.Task{}); got != candidateSourceFallback || unt {
		t.Fatalf("empty citation = (%q,%v); want fallback,false", got, unt)
	}
	trusted := eng.Task{Citation: eng.Citation{Source: "owasp-wstg", Section: "4.9.1 SQLi", CWEClass: "CWE-89", Origin: "trusted"}}
	got, unt := candidateSource(trusted)
	for _, w := range []string{"kb", "owasp-wstg", "4.9.1 SQLi", "CWE-89"} {
		if !strings.Contains(got, w) {
			t.Errorf("trusted source %q missing %q", got, w)
		}
	}
	if unt {
		t.Errorf("a trusted citation must not be untrusted")
	}
	web := eng.Task{Citation: eng.Citation{Source: "nvd", Path: "nvd.nist.gov/vuln/CVE-2023-1234", Origin: "untrusted"}}
	gw, uw := candidateSource(web)
	if !uw {
		t.Errorf("a web origin must be untrusted")
	}
	if !strings.Contains(gw, "web") {
		t.Errorf("untrusted source should lead with 'web': %q", gw)
	}
}

// renderCandidates shows the structured source when present (and the untrusted tag
// for web), and the fallback when a candidate has no citation.
func TestRenderCandidatesStructuredSource(t *testing.T) {
	noColor(t)
	out := renderCandidates([]eng.Task{
		{ID: "t2", Kind: "web", Objective: "SQLi", Phase: eng.PhaseExploit, Surface: eng.SurfaceWeb,
			Citation: eng.Citation{Source: "owasp-wstg", Section: "4.9.1", CWEClass: "CWE-89", Origin: "trusted"}},
		{ID: "t3", Kind: "network", Objective: "CVE", Phase: eng.PhaseExploit,
			Citation: eng.Citation{Source: "nvd", Origin: "untrusted"}},
	})
	for _, w := range []string{"owasp-wstg", "CWE-89", "untrusted"} {
		if !strings.Contains(out, w) {
			t.Errorf("render missing %q:\n%s", w, out)
		}
	}
	out2 := renderCandidates([]eng.Task{{ID: "t4", Kind: "web", Objective: "x", Phase: eng.PhaseExploit}})
	if !strings.Contains(out2, "finding evidence") {
		t.Errorf("a candidate with no citation should fall back:\n%s", out2)
	}
}
