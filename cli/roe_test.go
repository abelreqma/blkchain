package main

import (
	"strings"
	"testing"
	"time"
)

const sampleRoE = `## Summary
Authorized pentest of ACME staging.

## Targets
- acme-corp
- admin@acme.example.com

## In Scope
- 10.0.0.0/24
- staging.acme.example.com

## Out of Scope
- 10.0.0.5
- prod.acme.example.com

## Rate
- 10/s
`

func TestParseRoEFull(t *testing.T) {
	roe, err := ParseRoE(strings.NewReader(sampleRoE))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(roe.Summary, "Authorized pentest") {
		t.Errorf("summary not captured: %q", roe.Summary)
	}
	if len(roe.Targets) != 2 || roe.Targets[0] != "acme-corp" || roe.Targets[1] != "admin@acme.example.com" {
		t.Errorf("targets wrong: %v", roe.Targets)
	}
	if !roe.Scope.InScope("10.0.0.9") {
		t.Error("10.0.0.9 should be in scope")
	}
	if roe.Scope.InScope("10.0.0.5") {
		t.Error("10.0.0.5 is out of scope")
	}
	if !roe.Scope.InScope("staging.acme.example.com") {
		t.Error("staging host should be in scope")
	}
	if roe.Scope.InScope("prod.acme.example.com") {
		t.Error("prod host is out of scope")
	}
	r, ok := roe.Scope.Rate()
	if !ok || r.N != 10 || r.Per != time.Second {
		t.Errorf("rate wrong: {%d,%v},%v", r.N, r.Per, ok)
	}
}

func TestParseRoEOutWinsClosed(t *testing.T) {
	src := "## In Scope\n- dup.example.com\n## Out of Scope\n- dup.example.com\n"
	roe, err := ParseRoE(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if roe.Scope.InScope("dup.example.com") {
		t.Error("a host in both In and Out must fail closed (A5)")
	}
}

func TestParseRoEWildcardAndMultipleTargets(t *testing.T) {
	roe, err := ParseRoE(strings.NewReader("## In Scope\n10.20.0.5\n192.0.2.0/28\napp.example.test\n*.example.test\n## Out of Scope\nblocked.example.test\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"10.20.0.5", "192.0.2.9", "app.example.test", "api.example.test", "deep.api.example.test"} {
		if !roe.Scope.InScope(target) {
			t.Errorf("authorized target %q was lost", target)
		}
	}
	for _, target := range []string{"blocked.example.test", "example.test", "evil-example.test"} {
		if roe.Scope.InScope(target) {
			t.Errorf("unauthorized target %q was accepted", target)
		}
	}
	if !strings.Contains(roe.Policy.Canonical, "*.example.test") {
		t.Fatal("sealed policy lost the wildcard entry")
	}
}

func TestParseRoEMissingOptionalRate(t *testing.T) {
	src := "## In Scope\n- 10.0.0.5\n"
	roe, err := ParseRoE(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := roe.Scope.Rate(); ok {
		t.Error("absent rate section must yield no rate limit")
	}
}

func TestParseRoEMalformedScopeFailsClosed(t *testing.T) {
	src := "## In Scope\n- not a host!!\n"
	if _, err := ParseRoE(strings.NewReader(src)); err == nil {
		t.Error("a malformed in-scope entry must fail closed (error)")
	}
}

func TestParseRoEMalformedRateFailsClosed(t *testing.T) {
	src := "## In Scope\n- 10.0.0.5\n## Rate\n- banana\n"
	if _, err := ParseRoE(strings.NewReader(src)); err == nil {
		t.Error("a malformed rate must fail closed (error)")
	}
}

func TestParseRoEEmpty(t *testing.T) {
	roe, err := ParseRoE(strings.NewReader(""))
	if err != nil {
		t.Fatalf("empty ROE is not an error: %v", err)
	}
	if roe.Scope.InScope("10.0.0.5") {
		t.Error("empty scope must match nothing")
	}
	if _, ok := roe.Scope.Rate(); ok {
		t.Error("empty scope has no rate")
	}
}

// An unrecognized level-2+ section heading must FAIL CLOSED: silently dropping a
// typo'd or synonym heading (e.g. "Out-of-Scope", "Excluded") would discard an
// operator's exclusions and defeat the gate (review HIGH finding).
func TestParseRoEUnknownHeadingRejected(t *testing.T) {
	src := "## Notes\nsome freeform text\n## In Scope\n- 10.0.0.5\n"
	if _, err := ParseRoE(strings.NewReader(src)); err == nil {
		t.Error("an unrecognized ## heading must be a parse error (fail closed), not silently ignored")
	}
}

// The specific fail-open scenario the review flagged: a hyphenated out-of-scope
// heading must be rejected, not silently dropped (which would leave the host in
// scope via a broader in-scope CIDR).
func TestParseRoEHyphenatedOutOfScopeRejected(t *testing.T) {
	src := "## In Scope\n- 10.0.0.0/24\n## Out-of-Scope\n- 10.0.0.5\n"
	if _, err := ParseRoE(strings.NewReader(src)); err == nil {
		t.Error("a mistyped 'Out-of-Scope' heading must fail closed, not silently drop the exclusion")
	}
}

// A level-1 document title is allowed (ignored), so the template's
// "# Rules of Engagement" and operator titles do not error.
func TestParseRoETitleAllowed(t *testing.T) {
	src := "# Rules of Engagement\n## In Scope\n- 10.0.0.5\n"
	roe, err := ParseRoE(strings.NewReader(src))
	if err != nil {
		t.Fatalf("a level-1 title must be allowed: %v", err)
	}
	if !roe.Scope.InScope("10.0.0.5") {
		t.Error("sections after a level-1 title should still parse")
	}
}

// A multi-line HTML comment is skipped entirely (not fed to the section parser).
func TestParseRoEMultiLineCommentSkipped(t *testing.T) {
	src := "## In Scope\n<!--\n10.0.0.99 is just an example, not in scope\n-->\n- 10.0.0.5\n"
	roe, err := ParseRoE(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if roe.Scope.InScope("10.0.0.99") {
		t.Error("a host inside a multi-line HTML comment must not become a matcher")
	}
	if !roe.Scope.InScope("10.0.0.5") {
		t.Error("the real in-scope entry after the comment should parse")
	}
}

func TestRoEAutonomousActionsRequireExactInScopeHost(t *testing.T) {
	roe, err := ParseRoE(strings.NewReader("## In Scope\n192.0.2.1\n## Autonomous Actions\n- exploit/network 192.0.2.1\n"))
	if err != nil || roe.AutoActions == nil {
		t.Fatalf("auto actions=%+v err=%v", roe, err)
	}
	for _, entry := range []string{
		"## In Scope\n192.0.2.1\n## Autonomous Actions\n- exploit/network 198.51.100.2\n",
		"## In Scope\n192.0.2.1\n## Autonomous Actions\n- exploit/network 192.0.2.1:80\n",
		"## In Scope\n192.0.2.1\n## Autonomous Actions\n- exploit/network 192.0.2.0/24\n",
		"## In Scope\n192.0.2.1\n## Autonomous Actions\n- recon/network 192.0.2.1\n",
	} {
		if _, err := ParseRoE(strings.NewReader(entry)); err == nil {
			t.Fatalf("invalid autonomous action accepted: %q", entry)
		}
	}
}

func TestRoELocalAutoActionNeedsLocalScope(t *testing.T) {
	if _, err := ParseRoE(strings.NewReader("## In Scope\n192.0.2.1\n## Autonomous Actions\nrecon/local local\n")); err == nil {
		t.Fatal("local auto action without a local directive accepted")
	}
	roe, err := ParseRoE(strings.NewReader("## In Scope\nlocal\n## Autonomous Actions\nrecon/local local\n"))
	if err != nil || roe.AutoActions == nil {
		t.Fatalf("local auto policy=%+v err=%v", roe, err)
	}
	if _, err := ParseRoE(strings.NewReader("## In Scope\nlocal\n## Out of Scope\nlocal\n## Autonomous Actions\nrecon/local local\n")); err == nil {
		t.Fatal("out-of-scope local directive was ignored")
	}
}
