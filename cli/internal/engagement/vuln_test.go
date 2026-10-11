package engagement

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func seedVulnEvidence(t *testing.T, s *Store, task string) int64 {
	t.Helper()
	id, err := s.RecordEvidence(task, "osv-scanner reported GHSA-xxxx for pkg 1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func sampleVuln(task string, id int64) Vuln {
	return Vuln{
		ID: "v:1", TaskID: task, Surface: SurfaceContainer, Asset: "image:alpine",
		Scanner: "osv-scanner", ScannerVersion: "2.2.4", Advisory: "CVE-2026-0001",
		Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Severity: "HIGH", CVSS: "8.1",
		Package: "zlib", PackageVersion: "1.3.2-r0", Ecosystem: "Alpine",
		FixedVersion: "1.3.2-r1", Summary: "heap overflow", Location: "/lib/libz.so",
		EvidenceID: id,
	}
}

func TestVulnListHasABoundedDefaultPage(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	ctx := context.Background()
	ev := seedVulnEvidence(t, s, "A")
	for i := 0; i < 101; i++ {
		v := sampleVuln("A", ev)
		v.ID = fmt.Sprintf("v:%03d", i)
		v.Advisory = fmt.Sprintf("CVE-2026-%04d", i)
		if _, err := s.SaveVuln(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.Vulns(ctx, VulnFilter{})
	if err != nil || len(page) != 100 {
		t.Errorf("default page has %d rows, want 100: %v", len(page), err)
	}
	if _, err := s.Vulns(ctx, VulnFilter{Limit: 101}); err == nil {
		t.Error("an oversized page was accepted")
	}
}

func TestVulnRoundTripNormalizesSeverity(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	ctx := context.Background()
	ev := seedVulnEvidence(t, s, "A")

	saved, err := s.SaveVuln(ctx, sampleVuln("A", ev))
	if err != nil {
		t.Fatalf("SaveVuln: %v", err)
	}
	if saved.Severity != "high" {
		t.Errorf("Severity = %q, want high", saved.Severity)
	}
	if len(saved.Aliases) != 1 || saved.Aliases[0] != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("Aliases = %v", saved.Aliases)
	}
	if saved.FixedVersion != "1.3.2-r1" || saved.Ecosystem != "Alpine" {
		t.Errorf("round trip lost fields: %+v", saved)
	}
	if saved.ScannedAt == "" || saved.CreatedAt == "" {
		t.Errorf("timestamps missing: %+v", saved)
	}
}

func TestVulnRequiresEvidenceBelongingToTheTask(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	ctx := context.Background()
	ev := seedVulnEvidence(t, s, "A")

	noEvidence := sampleVuln("A", 0)
	_, err := s.SaveVuln(ctx, noEvidence)
	if err == nil {
		t.Error("accepted a vuln with no evidence row")
	} else if !strings.Contains(err.Error(), "requires an evidence row") {
		t.Errorf("unnamed evidence reported as %v, want the missing-row error", err)
	}
	absent := sampleVuln("A", ev+1000)
	if _, err := s.SaveVuln(ctx, absent); err == nil {
		t.Error("accepted a vuln naming an absent evidence row")
	}
	otherTask := sampleVuln("B", ev)
	if _, err := s.SaveVuln(ctx, otherTask); err == nil {
		t.Error("accepted evidence belonging to another task")
	}
}

func TestVulnRejectsUnboundedAndMalformedFields(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	ctx := context.Background()
	ev := seedVulnEvidence(t, s, "A")

	cases := map[string]func(*Vuln){
		"empty advisory":   func(v *Vuln) { v.Advisory = "" },
		"empty package":    func(v *Vuln) { v.Package = "" },
		"empty asset":      func(v *Vuln) { v.Asset = "" },
		"empty scanner":    func(v *Vuln) { v.Scanner = "" },
		"bad surface":      func(v *Vuln) { v.Surface = Surface("nope") },
		"newline in asset": func(v *Vuln) { v.Asset = "host\nInjected: 1" },
		"null in summary":  func(v *Vuln) { v.Summary = "a\x00b" },
		"oversize cvss":    func(v *Vuln) { v.CVSS = strings.Repeat("x", maxVulnField+1) },
		"oversize summary": func(v *Vuln) { v.Summary = strings.Repeat("x", 4097) },
		"too many aliases": func(v *Vuln) { v.Aliases = make([]string, 65) },
		"empty alias":      func(v *Vuln) { v.Aliases = []string{""} },
		"empty id":         func(v *Vuln) { v.ID = "" },
	}
	for name, mutate := range cases {
		v := sampleVuln("A", ev)
		mutate(&v)
		if _, err := s.SaveVuln(ctx, v); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

func TestSaveVulnUpsertsRatherThanDuplicating(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	ctx := context.Background()
	ev := seedVulnEvidence(t, s, "A")

	first, err := s.SaveVuln(ctx, sampleVuln("A", ev))
	if err != nil {
		t.Fatal(err)
	}
	again := sampleVuln("A", ev)
	again.Severity = "CRITICAL"
	again.FixedVersion = "1.3.2-r2"
	second, err := s.SaveVuln(ctx, again)
	if err != nil {
		t.Fatal(err)
	}
	if second.CreatedAt != first.CreatedAt {
		t.Errorf("rescan replaced created_at: %q then %q", first.CreatedAt, second.CreatedAt)
	}
	if second.Severity != "critical" || second.FixedVersion != "1.3.2-r2" {
		t.Errorf("rescan did not update the row: %+v", second)
	}
	all, err := s.Vulns(ctx, VulnFilter{})
	if err != nil || len(all) != 1 {
		t.Fatalf("rescan duplicated the row: %d rows, %v", len(all), err)
	}
}

func TestSaveVulnRejectsCrossTaskIDCollision(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	ctx := context.Background()
	firstEvidence := seedVulnEvidence(t, s, "A")
	secondEvidence := seedVulnEvidence(t, s, "B")
	first, err := s.SaveVuln(ctx, sampleVuln("A", firstEvidence))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveVuln(ctx, sampleVuln("B", secondEvidence)); err == nil {
		t.Fatal("cross-task ID collision was accepted")
	}
	got, err := s.Vuln(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TaskID != "A" || got.EvidenceID != firstEvidence {
		t.Fatalf("cross-task collision changed provenance: %+v", got)
	}
}

func TestVulnsOrderBySeverityThenAdvisory(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	ctx := context.Background()
	ev := seedVulnEvidence(t, s, "A")

	for i, spec := range []struct {
		id, advisory, severity string
	}{
		{"v:low", "CVE-2026-0009", "low"},
		{"v:crit", "CVE-2026-0002", "critical"},
		{"v:none", "CVE-2026-0003", ""},
		{"v:high-b", "CVE-2026-0005", "high"},
		{"v:high-a", "CVE-2026-0004", "high"},
	} {
		v := sampleVuln("A", ev)
		v.ID, v.Advisory, v.Severity = spec.id, spec.advisory, spec.severity
		v.Package = "pkg" + string(rune('a'+i))
		if _, err := s.SaveVuln(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Vulns(ctx, VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"v:crit", "v:high-a", "v:high-b", "v:low", "v:none"}
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("order = %s, want %s (position %d)", got[i].ID, want[i], i)
		}
	}
}

func TestVulnFilterAndLimit(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	ctx := context.Background()
	ev := seedVulnEvidence(t, s, "A")

	for _, spec := range []struct {
		id, asset, scanner, severity, ecosystem, pkg string
	}{
		{"v:1", "image:a", "osv-scanner", "high", "Alpine", "zlib"},
		{"v:2", "image:b", "trivy", "critical", "Go", "golang.org/x/net"},
		{"v:3", "image:a", "trivy", "low", "Alpine", "musl"},
	} {
		v := sampleVuln("A", ev)
		v.ID, v.Asset, v.Scanner, v.Severity, v.Ecosystem, v.Package = spec.id, spec.asset, spec.scanner, spec.severity, spec.ecosystem, spec.pkg
		if _, err := s.SaveVuln(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	for name, f := range map[string]struct {
		filter VulnFilter
		want   int
	}{
		"asset":            {VulnFilter{Asset: "image:a"}, 2},
		"scanner":          {VulnFilter{Scanner: "trivy"}, 2},
		"severity":         {VulnFilter{Severity: "critical"}, 1},
		"severity synonym": {VulnFilter{Severity: "MODERATE"}, 0},
		"ecosystem":        {VulnFilter{Ecosystem: "Alpine"}, 2},
		"package":          {VulnFilter{Package: "musl"}, 1},
		"combined":         {VulnFilter{Asset: "image:a", Scanner: "trivy"}, 1},
		"limit":            {VulnFilter{Limit: 1}, 1},
		"no match":         {VulnFilter{Asset: "image:zzz"}, 0},
	} {
		got, err := s.Vulns(ctx, f.filter)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != f.want {
			t.Errorf("%s: %d rows, want %d", name, len(got), f.want)
		}
	}
}

func TestVulnsUnknownSeverityIncludesUnratedAndUnknown(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	ctx := context.Background()
	ev := seedVulnEvidence(t, s, "A")
	for _, spec := range []struct{ id, severity string }{
		{"unrated", ""}, {"unrecognized", "other"}, {"high", "high"},
	} {
		v := sampleVuln("A", ev)
		v.ID, v.Severity = spec.id, spec.severity
		if _, err := s.SaveVuln(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Vulns(ctx, VulnFilter{Severity: "unknown"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "unrated" || got[1].ID != "unrecognized" {
		t.Fatalf("unknown severity records = %+v", got)
	}
}

func TestVulnsOffsetAndLimitKeepSeverityOrder(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	ctx := context.Background()
	ev := seedVulnEvidence(t, s, "A")
	for _, spec := range []struct{ id, severity, advisory string }{
		{"low", "low", "CVE-3"},
		{"high-b", "high", "CVE-2"},
		{"critical", "critical", "CVE-1"},
		{"high-a", "high", "CVE-1"},
	} {
		v := sampleVuln("A", ev)
		v.ID, v.Severity, v.Advisory = spec.id, spec.severity, spec.advisory
		if _, err := s.SaveVuln(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Vulns(ctx, VulnFilter{Limit: 2, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "high-a" || got[1].ID != "high-b" {
		t.Fatalf("paged severity records = %+v", got)
	}
}

func TestVulnStatsCountsDistinctAdvisoriesAndAssets(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	ctx := context.Background()
	ev := seedVulnEvidence(t, s, "A")

	// One advisory across two assets plus a second advisory, so distinct counts differ from row counts.
	for _, spec := range []struct{ id, asset, advisory, severity, pkg string }{
		{"v:1", "image:a", "CVE-2026-1", "high", "zlib"},
		{"v:2", "image:b", "CVE-2026-1", "high", "zlib"},
		{"v:3", "image:a", "CVE-2026-2", "", "musl"},
	} {
		v := sampleVuln("A", ev)
		v.ID, v.Asset, v.Advisory, v.Severity, v.Package = spec.id, spec.asset, spec.advisory, spec.severity, spec.pkg
		if _, err := s.SaveVuln(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.VulnStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Rows != 3 || got.Advisories != 2 || got.Assets != 2 {
		t.Errorf("stats = %+v, want rows 3 advisories 2 assets 2", got)
	}
	if got.BySeverity["high"] != 2 || got.BySeverity["unknown"] != 1 {
		t.Errorf("BySeverity = %v", got.BySeverity)
	}
	if got.ByScanner["osv-scanner"] != 3 {
		t.Errorf("ByScanner = %v", got.ByScanner)
	}
}

func TestVulnMethodsOnANilStoreReportUnavailable(t *testing.T) {
	ctx := context.Background()
	var s *Store
	if _, err := s.SaveVuln(ctx, Vuln{}); err == nil {
		t.Error("SaveVuln on a nil store returned no error")
	}
	if _, err := s.Vulns(ctx, VulnFilter{}); err == nil {
		t.Error("Vulns on a nil store returned no error")
	}
	if _, err := s.Vuln(ctx, "v:1"); err == nil {
		t.Error("Vuln on a nil store returned no error")
	}
	if _, err := s.VulnStats(ctx); err == nil {
		t.Error("VulnStats on a nil store returned no error")
	}
}
