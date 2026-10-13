package webanalysis

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

func subdomainNames(in []SubdomainName) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range in {
		if item.Wildcard || seen[item.Name] {
			continue
		}
		seen[item.Name] = true
		out = append(out, item.Name)
	}
	sort.Strings(out)
	return out
}

func TestUnderDomainRespectsTheLabelBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, root string
		want       bool
	}{
		{"example.com", "example.com", true},
		{"api.example.com", "example.com", true},
		{"a.b.c.example.com", "example.com", true},
		{"API.Example.COM", "example.com", true},
		{"api.example.com.", "example.com", true},
		// The boundary is the separator: a name that merely ends with the root's text is a different registration.
		{"notexample.com", "example.com", false},
		{"evil-example.com", "example.com", false},
		{"exampleacom", "example.com", false},
		{"example.com.evil.test", "example.com", false},
		{"example.co", "example.com", false},
		{"com", "example.com", false},
		// An internal root is often a single label, and names sit under it the same way.
		{"api.corp", "corp", true},
		{"corp", "corp", true},
		{"a.b.corp", "corp", true},
		{"notcorp", "corp", false},
		{"corp.example.com", "corp", false},
		{"", "example.com", false},
		{"api.example.com", "", false},
		{"192.0.2.1", "example.com", false},
		{"api.example.com", "192.0.2.1", false},
	} {
		if got := UnderDomain(tc.name, tc.root); got != tc.want {
			t.Errorf("UnderDomain(%q, %q) = %v, want %v", tc.name, tc.root, got, tc.want)
		}
	}
}

func TestNormalizeDNSNameRejectsMalformedNames(t *testing.T) {
	for _, in := range []string{
		"", ".", "..", "a..b", "-api.example.com", "api-.example.com",
		"api_.example.com", "api.example.com:443", "api.example.com/path",
		"api example.com", "api.exa mple.com", "192.0.2.1", "::1",
		strings.Repeat("a", 64) + ".example.com",
		strings.Repeat("a.", 200) + "example.com",
	} {
		if got, _ := normalizeDNSName(in); got != "" {
			t.Errorf("normalizeDNSName(%q) = %q, want it rejected", in, got)
		}
	}
	if got, wild := normalizeDNSName("*.Example.COM."); got != "example.com" || !wild {
		t.Errorf("normalizeDNSName of a wildcard = %q/%v, want example.com/true", got, wild)
	}
	if got, wild := normalizeDNSName("api.example.com"); got != "api.example.com" || wild {
		t.Errorf("normalizeDNSName = %q/%v", got, wild)
	}
}

func TestPassiveSubdomainsFromCertificateNames(t *testing.T) {
	got := PassiveSubdomains("example.com", []SubdomainSource{{
		Kind: "certificate", Origin: "www.example.com", EvidenceID: 7,
		Values: []string{
			"www.example.com", "api.example.com", "*.staging.example.com",
			"example.com", "cdn.other-company.net", "", "*.",
		},
	}})
	names := subdomainNames(got)
	want := []string{"api.example.com", "example.com", "www.example.com"}
	if len(names) != len(want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("names = %v, want %v", names, want)
			break
		}
	}
	// The wildcard is recorded but is not an addressable host.
	var wildcard *SubdomainName
	for i := range got {
		if got[i].Wildcard {
			wildcard = &got[i]
		}
	}
	if wildcard == nil {
		t.Fatal("the wildcard name was not recorded")
	}
	if wildcard.Name != "staging.example.com" {
		t.Errorf("wildcard name = %q, want its base name", wildcard.Name)
	}
	for _, s := range got {
		if s.EvidenceID != 7 {
			t.Errorf("%q does not cite its evidence row: %+v", s.Name, s)
		}
		if s.Source != "certificate" {
			t.Errorf("%q names source %q", s.Name, s.Source)
		}
		if strings.Contains(s.Name, "other-company") {
			t.Errorf("a name outside the root was reported: %q", s.Name)
		}
	}
}

func TestPassiveSubdomainsUnderASingleLabelRoot(t *testing.T) {
	got := PassiveSubdomains("corp", []SubdomainSource{{
		Kind: "certificate", Values: []string{"corp", "api.corp", "*.dev.corp", "notcorp", "corp.example.com"},
	}})
	names := subdomainNames(got)
	if len(names) != 2 || names[0] != "api.corp" || names[1] != "corp" {
		t.Errorf("names = %v, want api.corp and corp", names)
	}
	for _, n := range got {
		if n.Name == "notcorp" || n.Name == "corp.example.com" {
			t.Errorf("a name outside the root was reported: %q", n.Name)
		}
	}
}

func TestPassiveSubdomainsFromHeaders(t *testing.T) {
	got := PassiveSubdomains("example.com", []SubdomainSource{{
		Kind: "header", Origin: "www.example.com", EvidenceID: 3,
		Values: []string{
			"https://login.example.com/oauth/authorize?next=/app",
			"default-src 'self'; script-src 'unsafe-inline' https://cdn.example.com static.example.com:8443; connect-src wss://ws.example.com api.evil.test",
			"https://allowed.example.com",
			"max-age=31536000; includeSubDomains",
		},
	}})
	names := subdomainNames(got)
	for _, want := range []string{
		"allowed.example.com", "cdn.example.com", "login.example.com",
		"static.example.com", "ws.example.com",
	} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was not derived from the headers: %v", want, names)
		}
	}
	for _, n := range names {
		if strings.Contains(n, "evil.test") {
			t.Errorf("a name outside the root was reported: %q", n)
		}
	}
	// An HSTS value names no host, so nothing may be invented from it.
	for _, n := range names {
		if n == "max-age" || strings.Contains(n, "includesubdomains") {
			t.Errorf("a directive was read as a host: %q", n)
		}
	}
}

func TestPassiveSubdomainsFromBodies(t *testing.T) {
	body := `<html><head>
<link rel="preconnect" href="https://fonts.example.com">
<script src="//assets.example.com/app.js"></script>
</head><body>
<a href="https://support.example.com/tickets">support</a>
contact ops@mail.example.com or see internal.example.com
version 1.2.3 and build 10.0.0.1
<img src="https://images.partner.test/logo.png">
</body></html>`
	got := PassiveSubdomains("example.com", []SubdomainSource{{
		Kind: "body", Origin: "www.example.com", EvidenceID: 11, Values: []string{body},
	}})
	names := subdomainNames(got)
	for _, want := range []string{
		"assets.example.com", "fonts.example.com", "internal.example.com",
		"mail.example.com", "support.example.com",
	} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was not derived from the body: %v", want, names)
		}
	}
	for _, n := range names {
		if strings.Contains(n, "partner.test") {
			t.Errorf("a name outside the root was reported: %q", n)
		}
	}
	// A dotted version or an address is not a host name.
	for _, n := range names {
		if n == "1.2.3" || n == "10.0.0.1" {
			t.Errorf("a dotted number was read as a host: %q", n)
		}
	}
}

func TestPassiveSubdomainsDeduplicatesPerSource(t *testing.T) {
	got := PassiveSubdomains("example.com", []SubdomainSource{
		{Kind: "certificate", Values: []string{"api.example.com", "api.example.com", "API.EXAMPLE.COM"}},
		{Kind: "body", Values: []string{"api.example.com api.example.com"}},
	})
	if len(got) != 2 {
		t.Fatalf("got %d records, want one per source: %+v", len(got), got)
	}
	if got[0].Source == got[1].Source {
		t.Errorf("the two records share a source: %+v", got)
	}
	if names := subdomainNames(got); len(names) != 1 || names[0] != "api.example.com" {
		t.Errorf("subdomain names = %v, want the one distinct host", names)
	}
}

func TestPassiveSubdomainsIsOrderedAndStable(t *testing.T) {
	sources := []SubdomainSource{{
		Kind: "certificate",
		Values: []string{
			"zulu.example.com", "alpha.example.com", "mike.example.com",
			"*.alpha.example.com",
		},
	}}
	first := PassiveSubdomains("example.com", sources)
	second := PassiveSubdomains("example.com", sources)
	if len(first) != len(second) {
		t.Fatalf("two runs returned %d and %d records", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("the order is not stable at %d: %+v vs %+v", i, first[i], second[i])
		}
	}
	for i := 1; i < len(first); i++ {
		if first[i-1].Name > first[i].Name {
			t.Errorf("not sorted by name: %q before %q", first[i-1].Name, first[i].Name)
		}
	}
	// A host and a wildcard of the same name both appear, host first.
	var hostIdx, wildIdx = -1, -1
	for i, s := range first {
		if s.Name == "alpha.example.com" {
			if s.Wildcard {
				wildIdx = i
			} else {
				hostIdx = i
			}
		}
	}
	if hostIdx < 0 || wildIdx < 0 || hostIdx > wildIdx {
		t.Errorf("host and wildcard records are not both present in order: %+v", first)
	}
}

// A root that is not a usable name matches nothing, so no name is attributed to it. A single-label root is usable: an internal domain is often one.
func TestPassiveSubdomainsRejectsABadRoot(t *testing.T) {
	for _, root := range []string{"", ".", "192.0.2.1", "-bad.com", "a..b"} {
		if got := PassiveSubdomains(root, []SubdomainSource{
			{Kind: "certificate", Values: []string{"api.example.com"}},
		}); got != nil {
			t.Errorf("root %q returned %+v", root, got)
		}
	}
}

// A body is bounded before it is scanned, so a very large captured body cannot turn the derivation into unbounded work.
func TestPassiveSubdomainsBoundsTheMaterialItScans(t *testing.T) {
	var b strings.Builder
	b.WriteString("early.example.com ")
	b.WriteString(strings.Repeat("x", 2<<20))
	b.WriteString(" late.example.com")
	got := PassiveSubdomains("example.com", []SubdomainSource{
		{Kind: "body", Values: []string{b.String()}},
	})
	if names := subdomainNames(got); len(names) != 1 || names[0] != "early.example.com" {
		t.Fatalf("names = %v, want only the name inside the scan bound", names)
	}
}

// The number of matches read from one body is bounded as well, so a body crafted to hold an unbounded list of names cannot drive unbounded work.
func TestPassiveSubdomainsBoundsTheMatchesItReads(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 2500; i++ {
		b.WriteString("h")
		b.WriteString(strings.Repeat("0", 1))
		b.WriteString(".example.com ")
	}
	got := PassiveSubdomains("example.com", []SubdomainSource{
		{Kind: "body", Values: []string{b.String()}},
	})
	// Every name here is the same, so the cap is observed through the count of matches the pattern is allowed to return rather than the distinct names.
	if len(got) != 1 {
		t.Errorf("got %d records from one repeated name", len(got))
	}
	var many strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&many, "h%04d.example.com ", i)
	}
	distinct := PassiveSubdomains("example.com", []SubdomainSource{
		{Kind: "body", Values: []string{many.String()}},
	})
	if len(distinct) > 2000 {
		t.Errorf("read %d names from one body, want at most the 2000 match cap", len(distinct))
	}
}

// Nothing here resolves or connects: the only inputs are strings already captured, so an empty source set yields nothing rather than a query.
func TestPassiveSubdomainsReturnsNothingWithoutMaterial(t *testing.T) {
	if got := PassiveSubdomains("example.com", nil); got != nil {
		t.Errorf("got %+v from no sources", got)
	}
	if got := PassiveSubdomains("example.com", []SubdomainSource{
		{Kind: "certificate"}, {Kind: "body", Values: []string{""}},
		{Kind: "header", Values: []string{"", "   "}},
	}); got != nil {
		t.Errorf("got %+v from empty sources", got)
	}
}

func TestHostsInHeaderValueReadsEachForm(t *testing.T) {
	for value, want := range map[string]string{
		"https://a.example.com/path?q=1":                         "a.example.com",
		"//b.example.com/app":                                    "b.example.com",
		"c.example.com:8443":                                     "c.example.com",
		"'self' https://d.example.com":                           "d.example.com",
		"wss://e.example.com/socket":                             "e.example.com",
		`{"endpoints":[{"url":"https://f.example.com/report"}]}`: "f.example.com",
		`"g.example.com"`:                                        "g.example.com",
		`'h.example.com'`:                                        "h.example.com",
	} {
		got := hostsInHeaderValue(value)
		found := false
		for _, h := range got {
			if h == want {
				found = true
			}
		}
		if !found {
			t.Errorf("hostsInHeaderValue(%q) = %v, want it to include %q", value, got, want)
		}
	}
}
