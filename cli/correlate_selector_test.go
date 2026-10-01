package main

import (
	"context"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

func TestParseExploitSelection(t *testing.T) {
	cases := []struct{ name, raw, want string }{
		{"valid", `{"technique": "CVE-2021-41773 path traversal"}`, "CVE-2021-41773 path traversal"},
		{"tolerates chatter", `sure: {"technique": "SambaCry"} done`, "SambaCry"},
		{"no braces", `SambaCry`, ""},
		{"malformed", `{"technique":`, ""},
		{"wrong type", `{"technique": 7}`, ""},
		{"missing field", `{"foo": "bar"}`, ""},
		{"empty", `{"technique": "  "}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseExploitSelection(tc.raw); got != tc.want {
				t.Fatalf("parseExploitSelection(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestAcceptCitation(t *testing.T) {
	term := citationTerm("vsftpd") // "vsftpd"

	// Product-specific hit within top-K is accepted (and found past rank 0, so a
	// drifted top hit does not block grounding).
	topK := []retrieval.Result{
		{Score: 1, Payload: retrieval.Payload{Source: "offensive-network", Path: "ftp.md", Section: "FTP", Text: "generic ftp notes"}},
		{Score: 1, Payload: retrieval.Payload{Source: "offensive-rce", Path: "vsftpd.md", Section: "Backdoor", Text: "vsftpd 2.3.4 backdoor"}},
	}
	if cit, ok := acceptCitation(topK, term); !ok || cit.Source != "offensive-rce" {
		t.Fatalf("a product-specific top-K hit must be accepted (got ok=%v cit=%+v)", ok, cit)
	}

	// Keyword-adjacent set (no hit mentions the product) is REJECTED (no false
	// grounding) - the versionless-query drift case.
	adjacent := []retrieval.Result{
		{Score: 5, Payload: retrieval.Payload{Source: "offensive-lfi", Path: "traversal.md", Section: "LFI", Text: "directory traversal and local file inclusion"}},
	}
	if _, ok := acceptCitation(adjacent, term); ok {
		t.Fatal("a keyword-adjacent hit with no product mention must NOT ground (false grounding)")
	}

	// Empty results reject.
	if _, ok := acceptCitation(nil, term); ok {
		t.Fatal("no results must not ground")
	}

	// Below the score floor rejects even a product-specific hit.
	lowScore := []retrieval.Result{
		{Score: MinCitationScore - 1, Payload: retrieval.Payload{Source: "offensive-rce", Text: "vsftpd backdoor"}},
	}
	if _, ok := acceptCitation(lowScore, term); ok {
		t.Fatal("a hit below MinCitationScore must not ground")
	}

	// An empty term (deterministic logic-gap path) skips the specificity gate: a
	// scored hit is accepted on score alone.
	if _, ok := acceptCitation(adjacent, ""); !ok {
		t.Fatal("empty term must skip the specificity gate (score-only grounding)")
	}
}

func TestAcceptCitationWordBoundaryAndVendor(t *testing.T) {
	// Vendor-led name: "ISC BIND" (term "isc bind") must NOT ground on an ISC-DHCP
	// hit that shares only the vendor token, and MUST ground on a real BIND hit.
	bindTerm := citationTerm("ISC BIND")
	iscDHCP := []retrieval.Result{{Score: 1, Payload: retrieval.Payload{Source: "offensive-network", Path: "isc-dhcp.md", Section: "DHCP", Text: "ISC DHCP server notes"}}}
	if _, ok := acceptCitation(iscDHCP, bindTerm); ok {
		t.Error("ISC BIND must NOT ground on an ISC-DHCP hit (vendor-token-only match)")
	}
	bindHit := []retrieval.Result{{Score: 1, Payload: retrieval.Payload{Source: "offensive-dns", Path: "bind.md", Section: "BIND", Text: "ISC BIND named exploitation"}}}
	if _, ok := acceptCitation(bindHit, bindTerm); !ok {
		t.Error("ISC BIND must ground on a real ISC BIND hit")
	}

	// Multi-token product: "Apache httpd" (term "apache httpd") must NOT ground on
	// an Apache-Tomcat-only hit (apache present, httpd absent), MUST ground on httpd.
	httpdTerm := citationTerm("Apache httpd")
	tomcat := []retrieval.Result{{Score: 1, Payload: retrieval.Payload{Source: "offensive-web", Path: "tomcat.md", Section: "Tomcat", Text: "Apache Tomcat manager exploitation"}}}
	if _, ok := acceptCitation(tomcat, httpdTerm); ok {
		t.Error("Apache httpd must NOT ground on an Apache-Tomcat-only hit")
	}
	httpd := []retrieval.Result{{Score: 1, Payload: retrieval.Payload{Source: "offensive-web", Path: "apache-httpd.md", Section: "httpd", Text: "Apache httpd CVE path traversal"}}}
	if _, ok := acceptCitation(httpd, httpdTerm); !ok {
		t.Error("Apache httpd must ground on an apache-httpd hit")
	}

	// Short single-token class term: "idor" must NOT ground on "corridor"
	// (substring superstring false-ground), MUST ground on a word-boundary IDOR hit.
	corridor := []retrieval.Result{{Score: 1, Payload: retrieval.Payload{Source: "offensive-web", Path: "corridor.md", Section: "layout", Text: "the corridor layout"}}}
	if _, ok := acceptCitation(corridor, "idor"); ok {
		t.Error(`"idor" must NOT ground on "corridor" (superstring false-grounding)`)
	}
	idor := []retrieval.Result{{Score: 1, Payload: retrieval.Payload{Source: "offensive-idor", Path: "idor.md", Section: "IDOR", Text: "insecure direct object reference (idor)"}}}
	if _, ok := acceptCitation(idor, "idor"); !ok {
		t.Error(`"idor" must ground on an IDOR hit`)
	}
}

// TestCitationTermFullPhrase pins that the term is the full lowercased phrase
// (all tokens required by citationMentions), not the vendor first token.
func TestCitationTermFullPhrase(t *testing.T) {
	cases := map[string]string{
		"Apache httpd":        "apache httpd",
		"ISC BIND":            "isc bind",
		"OpenSSH":             "openssh",
		"  Apache   Tomcat  ": "apache tomcat",
	}
	for in, want := range cases {
		if got := citationTerm(in); got != want {
			t.Errorf("citationTerm(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestWordBoundaryContains pins the boundary matcher directly.
func TestWordBoundaryContains(t *testing.T) {
	cases := []struct {
		hay, tok string
		want     bool
	}{
		{"the corridor layout", "idor", false},
		{"an idor finding", "idor", true},
		{"offensive-idor notes", "idor", true}, // hyphen is a boundary
		{"iscsi target", "isc", false},         // superstring, no boundary
		{"isc bind", "isc", true},
		{"httpd", "httpd", true},
	}
	for _, c := range cases {
		if got := wordBoundaryContains(c.hay, c.tok); got != c.want {
			t.Errorf("wordBoundaryContains(%q, %q) = %v, want %v", c.hay, c.tok, got, c.want)
		}
	}
}

func TestKBExploitSelectorParsesAndSetsCitation(t *testing.T) {
	rc := &recSearcher{results: []retrieval.Result{
		chunk("offensive-rce", "ssh.md", "SSH", "OpenSSH known CVEs and exploitation."),
	}}
	m := &fakeModel{queue: []*llms.ContentResponse{textResp(`{"technique": "CVE-2020-15778"}`)}}
	sel := newKBExploitSelector(m, rc, ragconfig.Config{TopK: 5})
	tech, cit := sel(context.Background(), Service{Product: "OpenSSH", Version: "8.2p1", Port: 22})
	if tech != "CVE-2020-15778" {
		t.Fatalf("technique = %q, want CVE-2020-15778", tech)
	}
	// The citation is the top result's structured source pointer; the local
	// corpus is trusted.
	want := engagement.Citation{Source: "offensive-rce", Path: "ssh.md", Section: "SSH", Origin: "trusted"}
	if cit != want {
		t.Fatalf("citation = %+v, want %+v", cit, want)
	}
}

func TestKBExploitSelectorFailsClosed(t *testing.T) {
	cfg := ragconfig.Config{TopK: 5}
	oneResult := []retrieval.Result{chunk("s", "p.md", "x", "note")}

	t.Run("nil model", func(t *testing.T) {
		sel := newKBExploitSelector(nil, &recSearcher{results: oneResult}, cfg)
		if tech, _ := sel(context.Background(), Service{Product: "OpenSSH"}); tech != "" {
			t.Fatalf("nil model must fail closed, got %q", tech)
		}
	})
	t.Run("malformed reply", func(t *testing.T) {
		m := &fakeModel{queue: []*llms.ContentResponse{textResp(`not json at all`)}}
		sel := newKBExploitSelector(m, &recSearcher{results: oneResult}, cfg)
		if tech, _ := sel(context.Background(), Service{Product: "OpenSSH"}); tech != "" {
			t.Fatalf("malformed reply must fail closed, got %q", tech)
		}
	})
	t.Run("empty product", func(t *testing.T) {
		m := &fakeModel{queue: []*llms.ContentResponse{textResp(`{"technique":"x"}`)}}
		sel := newKBExploitSelector(m, &recSearcher{results: oneResult}, cfg)
		if tech, _ := sel(context.Background(), Service{Product: "   "}); tech != "" {
			t.Fatalf("empty product must fail closed, got %q", tech)
		}
	})
}
