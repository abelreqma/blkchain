package main

import (
	"testing"

	"blkchain/cli/internal/engagement"
)

func validProv() Provenance { return Provenance{TaskID: "t1", EvidenceID: 1} }

func assertCandidateInvariants(t *testing.T, cands []engagement.Task) {
	t.Helper()
	for _, c := range cands {
		if c.Armed {
			t.Errorf("candidate %s is Armed, want unarmed", c.ID)
		}
		if c.Phase != engagement.PhaseExploit {
			t.Errorf("candidate %s Phase = %q, want exploit", c.ID, c.Phase)
		}
		if c.Status != engagement.StatusTodo {
			t.Errorf("candidate %s Status = %q, want todo", c.ID, c.Status)
		}
		if len(c.BasisIDs) != 1 || c.BasisIDs[0] != "t1" {
			t.Errorf("candidate %s BasisIDs = %v, want [t1]", c.ID, c.BasisIDs)
		}
	}
}

func ids(cands []engagement.Task) []string {
	out := make([]string, len(cands))
	for i, c := range cands {
		out[i] = c.ID
	}
	return out
}

func TestLogicGapIDOR(t *testing.T) {
	cands := correlateLogicGaps(validProv(), "GET /app?id=1001 HTTP/1.1")
	if len(cands) != 1 || cands[0].ID != "bizlogic-idor-t1-1" {
		t.Fatalf("got ids %v, want [bizlogic-idor-t1-1]", ids(cands))
	}
	assertCandidateInvariants(t, cands)
}

func TestLogicGapForceBrowse(t *testing.T) {
	cands := correlateLogicGaps(validProv(), "POST /admin/users")
	if len(cands) != 1 || cands[0].ID != "bizlogic-force-browse-t1-1" {
		t.Fatalf("got ids %v, want [bizlogic-force-browse-t1-1]", ids(cands))
	}
	assertCandidateInvariants(t, cands)
}

func TestLogicGapPriceTamper(t *testing.T) {
	cands := correlateLogicGaps(validProv(), "item price=19 submitted")
	if len(cands) != 1 || cands[0].ID != "bizlogic-price-tamper-t1-1" {
		t.Fatalf("got ids %v, want [bizlogic-price-tamper-t1-1]", ids(cands))
	}
	assertCandidateInvariants(t, cands)
}

func TestLogicGapWorkflow(t *testing.T) {
	cands := correlateLogicGaps(validProv(), "checkout ?step=3&next=confirm")
	if len(cands) != 1 || cands[0].ID != "bizlogic-workflow-t1-1" {
		t.Fatalf("got ids %v, want [bizlogic-workflow-t1-1]", ids(cands))
	}
	assertCandidateInvariants(t, cands)
}

func TestLogicGapLimitBypass(t *testing.T) {
	cands := correlateLogicGaps(validProv(), "Only one per customer per account")
	if len(cands) != 1 || cands[0].ID != "bizlogic-limit-bypass-t1-1" {
		t.Fatalf("got ids %v, want [bizlogic-limit-bypass-t1-1]", ids(cands))
	}
	assertCandidateInvariants(t, cands)
}

func TestLogicGapMultiple(t *testing.T) {
	cands := correlateLogicGaps(validProv(), "GET /admin?id=5&price=10")
	want := []string{"bizlogic-idor-t1-1", "bizlogic-force-browse-t1-1", "bizlogic-price-tamper-t1-1"}
	got := ids(cands)
	if len(got) != len(want) {
		t.Fatalf("got ids %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got ids %v, want %v (rule order)", got, want)
		}
	}
	assertCandidateInvariants(t, cands)
}

func TestLogicGapNoIndicators(t *testing.T) {
	if cands := correlateLogicGaps(validProv(), "Nmap scan report for 10.0.0.5"); len(cands) != 0 {
		t.Fatalf("got %v, want none", ids(cands))
	}
}

func TestLogicGapInvalidProvenance(t *testing.T) {
	if cands := correlateLogicGaps(Provenance{TaskID: "", EvidenceID: 0}, "/admin?id=1"); cands != nil {
		t.Fatalf("got %v, want nil for invalid provenance", ids(cands))
	}
}

func TestLogicGapFalsePositives(t *testing.T) {
	if cands := correlateLogicGaps(validProv(), "path /administrator uuid=5"); len(cands) != 0 {
		t.Fatalf("got %v, want none (/administrator and uuid= must not match)", ids(cands))
	}
}

func TestLogicGapDedup(t *testing.T) {
	cands := correlateLogicGaps(validProv(), "id=1 and id=2 and id=3")
	if len(cands) != 1 || cands[0].ID != "bizlogic-idor-t1-1" {
		t.Fatalf("got ids %v, want one idor candidate (dedup per rule)", ids(cands))
	}
}
