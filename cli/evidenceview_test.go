package main

import (
	"strings"
	"testing"

	eng "blkchain/cli/internal/engagement"
)

// evidenceBlock lists the current engagement's verified evidence per task (via the
// on-demand accessor), omitting tasks with none; a nil view says no engagement.
func TestEvidenceBlock(t *testing.T) {
	noColor(t)
	if got := evidenceBlock(nil); !strings.Contains(got, "no engagement") {
		t.Fatalf("nil view = %q", got)
	}
	SetEngageEvidenceSource(func(taskID string) ([]eng.EvidenceRow, error) {
		if taskID == "t2" {
			return []eng.EvidenceRow{{ID: 1, Quote: "You have an error in your SQL syntax"}}, nil
		}
		return nil, nil
	})
	t.Cleanup(func() { SetEngageEvidenceSource(nil) })
	stub := newStubEngagement("acme")
	stub.setSnapshot(eng.Engagement{Tasks: []eng.Task{
		{ID: "t1", Kind: "recon", Objective: "scan"},
		{ID: "t2", Kind: "web", Objective: "SQLi"},
	}})
	out := evidenceBlock(stub)
	for _, w := range []string{"evidence", "web: SQLi", "E1", "SQL syntax"} {
		if !strings.Contains(out, w) {
			t.Errorf("evidenceBlock missing %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "recon: scan") {
		t.Errorf("a task with no evidence should be omitted:\n%s", out)
	}
}

// With a registered source but no evidence on any task, the view says so.
func TestEvidenceBlockNoEvidence(t *testing.T) {
	noColor(t)
	SetEngageEvidenceSource(func(string) ([]eng.EvidenceRow, error) { return nil, nil })
	t.Cleanup(func() { SetEngageEvidenceSource(nil) })
	stub := newStubEngagement("x")
	stub.setSnapshot(eng.Engagement{Tasks: []eng.Task{{ID: "t1", Kind: "web", Objective: "x"}}})
	if got := evidenceBlock(stub); !strings.Contains(got, "no evidence") {
		t.Fatalf("got %q", got)
	}
}

// Evidence quotes are sanitized (captured tool output), and a quote truncated by
// the accessor is marked.
func TestEvidenceBlockSanitizesAndMarksTruncated(t *testing.T) {
	noColor(t)
	long := strings.Repeat("a", maxEvidenceQuoteBytes+100)
	SetEngageEvidenceSource(func(string) ([]eng.EvidenceRow, error) {
		return []eng.EvidenceRow{
			{ID: 7, Quote: "safe\x1b[31mred"},
			{ID: 8, Quote: long},
		}, nil
	})
	t.Cleanup(func() { SetEngageEvidenceSource(nil) })
	stub := newStubEngagement("x")
	stub.setSnapshot(eng.Engagement{Tasks: []eng.Task{{ID: "t1", Kind: "web", Objective: "x"}}})
	out := evidenceBlock(stub)
	if strings.Contains(out, "\x1b[31m") {
		t.Fatalf("evidence quote must be sanitized of raw escapes:\n%q", out)
	}
	if !strings.Contains(out, "truncated") {
		t.Fatalf("a truncated quote should be marked:\n%s", out)
	}
}

// /evidence has a dispatch case and does not panic in either state.
func TestEvidenceCommandDispatches(t *testing.T) {
	m := newTestModel(t)
	if _, cmd := m.dispatchInput("/evidence"); cmd == nil {
		t.Fatalf("/evidence should always print something")
	}
}
