package main

import "testing"

var tlsProv = Provenance{TaskID: "t1", EvidenceID: 11}

func TestParseTLSDeprecatedProtocols(t *testing.T) {
	// sslscan "enabled" style, plus a modern protocol that must NOT be flagged.
	quote := "  SSLv2     disabled\n" +
		"  TLSv1.0   enabled\n" +
		"  TLSv1.1   enabled\n" +
		"  TLSv1.2   enabled\n" +
		"  TLSv1.3   enabled\n"
	got := parseTLSInfo(tlsProv, quote)
	var protos []string
	for _, r := range got {
		if r.Issue != "deprecated-protocol" {
			t.Errorf("record %+v has Issue %q, want deprecated-protocol", r, r.Issue)
		}
		if r.Prov != tlsProv {
			t.Errorf("record %+v Prov = %+v, want %+v", r, r.Prov, tlsProv)
		}
		protos = append(protos, r.Protocol)
	}
	if len(protos) != 2 || protos[0] != "TLSv1.0" || protos[1] != "TLSv1.1" {
		t.Fatalf("flagged protocols = %v, want [TLSv1.0 TLSv1.1] (SSLv2 disabled, TLSv1.2/1.3 not deprecated)", protos)
	}
}

func TestParseTLSNmapSectionHeader(t *testing.T) {
	quote := "| ssl-enum-ciphers:\n|   TLSv1.0:\n|     ciphers:\n|   TLSv1.2:\n"
	got := parseTLSInfo(tlsProv, quote)
	if len(got) != 1 || got[0].Protocol != "TLSv1.0" || got[0].Issue != "deprecated-protocol" {
		t.Fatalf("nmap section header parse = %+v, want one TLSv1.0 deprecated-protocol", got)
	}
}

func TestParseTLSSelfSigned(t *testing.T) {
	got := parseTLSInfo(tlsProv, "  Certificate: Self-signed certificate detected\n")
	if len(got) != 1 || got[0].Issue != "self-signed" {
		t.Fatalf("self-signed parse = %+v, want one self-signed record", got)
	}
}

func TestParseTLSCleanBlock(t *testing.T) {
	quote := "  TLSv1.2   enabled\n  TLSv1.3   enabled\n"
	if got := parseTLSInfo(tlsProv, quote); len(got) != 0 {
		t.Fatalf("clean modern block must yield no records, got %+v", got)
	}
}

func TestParseTLSNegatedSummaryNotFlagged(t *testing.T) {
	// A summary line reporting the ABSENCE of deprecated protocols names them but
	// must not produce positive deprecated-protocol records.
	quote := "No deprecated protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1) offered\n" +
		"Certificate is not self-signed\n"
	if got := parseTLSInfo(tlsProv, quote); len(got) != 0 {
		t.Fatalf("negated summary must yield no records, got %+v", got)
	}
}

func TestParseTLSInvalidProvenance(t *testing.T) {
	if got := parseTLSInfo(Provenance{}, "  TLSv1.0   enabled\n"); got != nil {
		t.Fatalf("invalid provenance must yield nil, got %+v", got)
	}
}
