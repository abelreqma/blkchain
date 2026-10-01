package main

import "testing"

var assetProv = Provenance{TaskID: "t1", EvidenceID: 7}

func TestParseAssetsTwoHosts(t *testing.T) {
	quote := "Starting Nmap\n" +
		"Nmap scan report for web.example.com (10.0.0.5)\n" +
		"Host is up (0.0010s latency).\n" +
		"Nmap scan report for 10.0.0.6\n" +
		"Host: 10.0.0.7 ()\n"
	got := parseAssets(assetProv, quote)
	want := []string{"10.0.0.5", "10.0.0.6", "10.0.0.7"}
	if len(got) != len(want) {
		t.Fatalf("got %d assets %+v, want %d", len(got), got, len(want))
	}
	for i, h := range want {
		if got[i].Host != h {
			t.Errorf("asset[%d].Host = %q, want %q", i, got[i].Host, h)
		}
		if got[i].Prov != assetProv {
			t.Errorf("asset[%d].Prov = %+v, want %+v", i, got[i].Prov, assetProv)
		}
	}
}

func TestParseAssetsDedup(t *testing.T) {
	quote := "Nmap scan report for 10.0.0.5\nNmap scan report for 10.0.0.5\n"
	if got := parseAssets(assetProv, quote); len(got) != 1 {
		t.Fatalf("duplicate host produced %d assets, want 1: %+v", len(got), got)
	}
}

func TestParseAssetsInvalidProvenance(t *testing.T) {
	quote := "Nmap scan report for 10.0.0.5\n"
	if got := parseAssets(Provenance{}, quote); got != nil {
		t.Fatalf("invalid provenance must yield nil, got %+v", got)
	}
	if got := parseAssets(Provenance{TaskID: "t1"}, quote); got != nil {
		t.Fatalf("zero EvidenceID must yield nil, got %+v", got)
	}
}

func TestParseAssetsJunk(t *testing.T) {
	if got := parseAssets(assetProv, "no hosts here\njust noise\n"); len(got) != 0 {
		t.Fatalf("junk must yield no assets, got %+v", got)
	}
}
