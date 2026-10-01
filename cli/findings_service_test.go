package main

import "testing"

var svcProv = Provenance{TaskID: "t1", EvidenceID: 3}

func TestParseServicesVersionBlock(t *testing.T) {
	quote := "Nmap scan report for 10.0.0.5\n" +
		"PORT    STATE SERVICE VERSION\n" +
		"22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5\n" +
		"80/tcp  open  http    Apache httpd 2.4.49 ((Ubuntu))\n" +
		"443/tcp open  https\n" +
		"53/udp  open  domain  ISC BIND 9.16.1\n" +
		"3306/tcp closed mysql\n"
	got := parseServices(svcProv, quote)
	type want struct {
		host, transport, product, version string
		port                              int
	}
	wants := []want{
		{"10.0.0.5", "tcp", "OpenSSH", "8.2p1", 22},
		{"10.0.0.5", "tcp", "Apache httpd", "2.4.49", 80},
		{"10.0.0.5", "tcp", "", "", 443},
		{"10.0.0.5", "udp", "ISC BIND", "9.16.1", 53},
	}
	if len(got) != len(wants) {
		t.Fatalf("got %d services %+v, want %d (closed port must be skipped)", len(got), got, len(wants))
	}
	for i, w := range wants {
		g := got[i]
		if g.Host != w.host || g.Port != w.port || g.Transport != w.transport || g.Product != w.product || g.Version != w.version {
			t.Errorf("service[%d] = %+v, want host=%q port=%d transport=%q product=%q version=%q",
				i, g, w.host, w.port, w.transport, w.product, w.version)
		}
		if g.Prov != svcProv {
			t.Errorf("service[%d].Prov = %+v, want %+v", i, g.Prov, svcProv)
		}
	}
}

func TestParseServicesInvalidProvenance(t *testing.T) {
	quote := "22/tcp open ssh OpenSSH 8.2p1\n"
	if got := parseServices(Provenance{}, quote); got != nil {
		t.Fatalf("invalid provenance must yield nil, got %+v", got)
	}
}

func TestParseServicesJunk(t *testing.T) {
	if got := parseServices(svcProv, "nothing to see\n"); len(got) != 0 {
		t.Fatalf("junk must yield no services, got %+v", got)
	}
}
