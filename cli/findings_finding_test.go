package main

import "testing"

var findProv = Provenance{TaskID: "t1", EvidenceID: 5}

func TestParseFindingsOpenPortAndVersion(t *testing.T) {
	quote := "Nmap scan report for 10.0.0.5\n" +
		"22/tcp open ssh OpenSSH 8.2p1 Ubuntu\n"
	got := parseFindings(findProv, quote)
	if len(got) != 2 {
		t.Fatalf("got %d findings %+v, want 2 (open-port + version-disclosure)", len(got), got)
	}
	if got[0].Title != "open-port" || got[0].Severity != SeverityInfo || got[0].Port != 22 || got[0].Host != "10.0.0.5" {
		t.Errorf("finding[0] = %+v, want open-port Info port 22 host 10.0.0.5", got[0])
	}
	if got[1].Title != "version-disclosure" || got[1].Severity != SeverityLow || got[1].Port != 22 {
		t.Errorf("finding[1] = %+v, want version-disclosure Low port 22", got[1])
	}
	if got[1].Detail != "OpenSSH 8.2p1" {
		t.Errorf("version-disclosure Detail = %q, want %q", got[1].Detail, "OpenSSH 8.2p1")
	}
	for i := range got {
		if got[i].Prov != findProv {
			t.Errorf("finding[%d].Prov = %+v, want %+v", i, got[i].Prov, findProv)
		}
	}
}

func TestParseFindingsNoVersionNoDisclosure(t *testing.T) {
	got := parseFindings(findProv, "443/tcp open https\n")
	if len(got) != 1 || got[0].Title != "open-port" {
		t.Fatalf("a service with no version yields only open-port, got %+v", got)
	}
}

func TestParseFindingsAnonymousAccess(t *testing.T) {
	got := parseFindings(findProv, "Anonymous FTP login allowed (FTP code 230)\n")
	if len(got) != 1 || got[0].Title != "anonymous-access" || got[0].Severity != SeverityMedium {
		t.Fatalf("anonymous marker parse = %+v, want one anonymous-access Medium", got)
	}
}

func TestParseFindingsNegatedAnonymousNotFlagged(t *testing.T) {
	for _, line := range []string{"No anonymous access\n", "Anonymous access: disabled\n"} {
		if got := parseFindings(findProv, line); len(got) != 0 {
			t.Fatalf("negated line %q must yield no findings, got %+v", line, got)
		}
	}
}

func TestParseFindingsInvalidProvenance(t *testing.T) {
	if got := parseFindings(Provenance{}, "22/tcp open ssh\n"); got != nil {
		t.Fatalf("invalid provenance must yield nil, got %+v", got)
	}
}
