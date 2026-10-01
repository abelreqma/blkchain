package secgate

import (
	"strings"
	"testing"
	"time"
)

func TestParseScopeAndMatch(t *testing.T) {
	src := `# engagement scope
10.0.0.0/24
host.example.com
!10.0.0.5
!admin.example.com
`
	s, err := ParseScope(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		target string
		want   bool
	}{
		{"10.0.0.9", true},  // in CIDR
		{"10.0.0.5", false}, // excluded, out wins over the CIDR
		{"host.example.com", true},
		{"admin.example.com", false}, // excluded
		{"host2.example.com", false}, // not listed
		{"8.8.8.8", false},           // not listed
	}
	for _, c := range cases {
		if got := s.InScope(c.target); got != c.want {
			t.Errorf("InScope(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}

func TestEmptyScopeMatchesNothing(t *testing.T) {
	s, err := ParseScope(strings.NewReader("# only comments\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Empty() {
		t.Error("scope with no entries should be Empty")
	}
	if s.InScope("10.0.0.1") {
		t.Error("empty scope must not put anything in scope (fail closed)")
	}
}

func TestParseScopeRejectsMalformedLine(t *testing.T) {
	if _, err := ParseScope(strings.NewReader("not a host or cidr !!!")); err == nil {
		t.Fatal("want error on a malformed scope line")
	}
}

func TestOutOfScopeCIDRWins(t *testing.T) {
	s, err := ParseScope(strings.NewReader("10.0.0.0/8\n!10.1.0.0/16\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.InScope("10.1.2.3") {
		t.Error("10.1.2.3 is in an out-of-scope CIDR; must be denied")
	}
	if !s.InScope("10.2.3.4") {
		t.Error("10.2.3.4 is in-scope and not excluded")
	}
}

func TestParseScopeRejectsNumericLastLabel(t *testing.T) {
	bad := []string{
		"10.0.0.256",
		"!10.0.0.256",
		"10.0.0",
		"2130706433",
		"010.0.0.5",
		"!10.0.0.5-9",
	}
	for _, entry := range bad {
		src := "10.0.0.0/24\n" + entry + "\n"
		if _, err := ParseScope(strings.NewReader(src)); err == nil {
			t.Errorf("ParseScope accepted %q; want error (all-numeric last label)", entry)
		}
	}
}

func TestParseScopeAcceptsLegitimateEntries(t *testing.T) {
	good := []string{"10.0.0.0/24", "host.example.com", "localhost", "10.0.0.5"}
	for _, entry := range good {
		s, err := ParseScope(strings.NewReader(entry + "\n"))
		if err != nil {
			t.Errorf("ParseScope rejected %q: %v", entry, err)
			continue
		}
		if s.Empty() {
			t.Errorf("ParseScope(%q) produced an empty scope", entry)
		}
	}
}

func TestNumericTypoExclusionCannotSilentlyFail(t *testing.T) {
	// A typo'd exclusion must be a parse error, never an ignored exclusion.
	if _, err := ParseScope(strings.NewReader("10.0.0.0/24\n!10.0.0.256\n")); err == nil {
		t.Fatal("typo'd exclusion must fail the whole scope parse")
	}
}

func TestParseScopeRejectsHexLiteralLastLabel(t *testing.T) {
	bad := []string{"0x7f000001", "!0x7f000001", "127.0.0.0x1", "0X7F.0XA"}
	for _, entry := range bad {
		src := "10.0.0.0/24\n" + entry + "\n"
		if _, err := ParseScope(strings.NewReader(src)); err == nil {
			t.Errorf("ParseScope accepted %q; want error (hex-literal last label)", entry)
		}
	}
}

func TestParseScopeAcceptsNonHexLookalikes(t *testing.T) {
	good := []string{"xn--abc.example.com", "host.example.com", "0xz.example.com", "host.0xg", "0x"}
	for _, entry := range good {
		if _, err := ParseScope(strings.NewReader(entry + "\n")); err != nil {
			t.Errorf("ParseScope rejected %q: %v", entry, err)
		}
	}
}

func TestScopeLocalAndAllowDirectives(t *testing.T) {
	src := "local\nallow nmap\nallow /usr/bin/find\n10.0.0.0/24\n"
	s, err := ParseScope(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Local() {
		t.Error("local directive not parsed")
	}
	bins := s.AllowedBins()
	if len(bins) != 2 || bins[0] != "nmap" || bins[1] != "find" {
		t.Errorf("AllowedBins = %v, want [nmap find] (base names)", bins)
	}
	if !s.InScope("10.0.0.9") {
		t.Error("target line still in scope")
	}
}

func TestScopeLocalOnlyIsValidNonEmptyForAuto(t *testing.T) {
	s, err := ParseScope(strings.NewReader("local\nallow id\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Local() {
		t.Fatal("expected local")
	}
	// Empty() is about TARGET entries; a local-only scope has none.
	if !s.Empty() {
		t.Error("a local-only scope has no target entries, so Empty() is true")
	}
}

func TestScopeAllowEmptyBaseNameIsError(t *testing.T) {
	if _, err := ParseScope(strings.NewReader("local\nallow /\n")); err == nil {
		t.Error("allow with an empty base name must be a parse error")
	}
}

func TestBuildScopeInOutTargets(t *testing.T) {
	s, err := BuildScope(ScopeSpec{
		In:      []string{"10.0.0.0/24", "host.example.com"},
		Out:     []string{"10.0.0.5"},
		Targets: []string{"acme corp", "admin@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !s.InScope("10.0.0.9") {
		t.Error("10.0.0.9 should be in scope")
	}
	if s.InScope("10.0.0.5") {
		t.Error("10.0.0.5 is out of scope, must be denied")
	}
	got := s.Targets()
	if len(got) != 2 || got[0] != "acme corp" || got[1] != "admin@example.com" {
		t.Errorf("Targets round-trip wrong: %v", got)
	}
}

func TestBuildScopeOutWinsOverIn(t *testing.T) {

	s, err := BuildScope(ScopeSpec{
		In:  []string{"dup.example.com"},
		Out: []string{"dup.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.InScope("dup.example.com") {
		t.Error("a host in both In and Out must be denied (out wins, fail closed)")
	}
}

func TestBuildScopeMalformedFailsClosed(t *testing.T) {
	if s, err := BuildScope(ScopeSpec{In: []string{"not a host!!"}}); err == nil || s != nil {
		t.Errorf("malformed in-scope entry must error and yield nil scope; got scope=%v err=%v", s, err)
	}
}

func TestParseRate(t *testing.T) {
	ok := []struct {
		in  string
		n   int
		per time.Duration
	}{
		{"10/s", 10, time.Second},
		{"60/m", 60, time.Minute},
		{"100/h", 100, time.Hour},
		{" 5 / s ", 5, time.Second},
	}
	for _, c := range ok {
		r, err := parseRate(c.in)
		if err != nil {
			t.Errorf("parseRate(%q) unexpected error: %v", c.in, err)
			continue
		}
		if r.N != c.n || r.Per != c.per {
			t.Errorf("parseRate(%q) = {%d,%v}, want {%d,%v}", c.in, r.N, r.Per, c.n, c.per)
		}
	}
	bad := []string{"0/s", "-1/s", "10/x", "abc", "10", "", "10/", "/s", "1.5/s"}
	for _, c := range bad {
		if r, err := parseRate(c); err == nil {
			t.Errorf("parseRate(%q) should error, got %v", c, r)
		}
	}
}

func TestScopeRateAccessor(t *testing.T) {
	s, err := BuildScope(ScopeSpec{In: []string{"10.0.0.5"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Rate(); ok {
		t.Error("a scope with no rate must report ok=false")
	}
	s2, err := BuildScope(ScopeSpec{In: []string{"10.0.0.5"}, Rate: "5/s"})
	if err != nil {
		t.Fatal(err)
	}
	r, ok := s2.Rate()
	if !ok || r.N != 5 || r.Per != time.Second {
		t.Errorf("Rate() = {%d,%v},%v; want {5,1s},true", r.N, r.Per, ok)
	}
}
