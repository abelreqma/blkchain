package main

import (
	"testing"

	"blkchain/cli/internal/engagement"
)

func TestCorrelateServiceKnownProductIsUnarmedExploit(t *testing.T) {
	svc := Service{Host: "10.0.0.5", Port: 22, Transport: "tcp", Product: "OpenSSH", Version: "8.2p1", Prov: Provenance{TaskID: "t1", EvidenceID: 4}}
	got, ok := correlateService(svc)
	if !ok {
		t.Fatal("a cataloged product must correlate to a candidate")
	}
	if got.Phase != engagement.PhaseExploit {
		t.Errorf("Phase = %q, want exploit (never recon)", got.Phase)
	}
	if got.Armed {
		t.Error("candidate must be created UNARMED")
	}
	if got.Status != engagement.StatusTodo {
		t.Errorf("Status = %q, want todo", got.Status)
	}
	if len(got.BasisIDs) != 1 || got.BasisIDs[0] != "t1" {
		t.Errorf("BasisIDs = %v, want [t1]", got.BasisIDs)
	}
}

func TestCorrelateServiceDeterministicEdge(t *testing.T) {
	svc := Service{Host: "10.0.0.5", Port: 22, Transport: "tcp", Product: "OpenSSH", Version: "8.2p1", Prov: Provenance{TaskID: "t1", EvidenceID: 4}}
	a, _ := correlateService(svc)
	// Same service+version from a different evidence row -> same candidate id/fields.
	svc2 := svc
	svc2.Prov = Provenance{TaskID: "t1", EvidenceID: 99}
	b, _ := correlateService(svc2)
	if a.ID != b.ID {
		t.Fatalf("non-deterministic candidate id: %q vs %q", a.ID, b.ID)
	}
	if a.Objective != b.Objective || a.Target != b.Target || a.Phase != b.Phase {
		t.Fatalf("non-deterministic candidate fields: %+v vs %+v", a, b)
	}
}

func TestCorrelateServiceRealSambaBanner(t *testing.T) {
	// nmap -sV reports Samba as "Samba smbd 3.X - 4.X (workgroup: WORKGROUP)".
	// parseServices yields Product "Samba smbd", Version "3.X"; it must correlate.
	quote := "Nmap scan report for 10.0.0.5\n445/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)\n"
	svcs := parseServices(Provenance{TaskID: "t1", EvidenceID: 1}, quote)
	if len(svcs) != 1 {
		t.Fatalf("parseServices returned %d, want 1: %+v", len(svcs), svcs)
	}
	if svcs[0].Product != "Samba smbd" {
		t.Fatalf("product = %q, want %q (banner-form product)", svcs[0].Product, "Samba smbd")
	}
	if _, ok := correlateService(svcs[0]); !ok {
		t.Fatal("the real Samba banner form must correlate to a candidate")
	}
}

func TestCorrelateServiceUnknownProductNoCandidate(t *testing.T) {
	svc := Service{Host: "10.0.0.5", Port: 9999, Product: "frobnicator", Version: "1.0", Prov: Provenance{TaskID: "t1", EvidenceID: 4}}
	if _, ok := correlateService(svc); ok {
		t.Fatal("an uncataloged product must NOT invent a candidate")
	}
}

func TestCorrelateServiceRequiresProvenance(t *testing.T) {
	svc := Service{Host: "10.0.0.5", Port: 22, Product: "OpenSSH", Version: "8.2p1"} // zero Provenance
	if _, ok := correlateService(svc); ok {
		t.Fatal("a service without a verified evidence-quote id must NOT correlate")
	}
}
