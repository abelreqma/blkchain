package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
)

// seedVulnWorkspace creates a workspace holding three advisories across two assets and two scanners, so every filter has both a match and a non-match.
func seedVulnWorkspace(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ws, err := engagement.OpenWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ctx := context.Background()
	if _, err := ws.Store.Apply(engagement.Delta{Kind: "fixture", Upserts: []engagement.Task{
		{ID: "scan", Status: engagement.StatusActive, Surface: engagement.SurfaceContainer},
	}}); err != nil {
		t.Fatal(err)
	}
	ev, err := ws.Store.RecordEvidence("scan", "scanner output")
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct {
		id, advisory, severity, pkg, version, fixed, asset, scanner, eco string
	}{
		{"cve:a", "CVE-2026-0001", "critical", "zlib", "1.3.2-r0", "1.3.2-r1", "image:alpine", "trivy", "alpine"},
		{"cve:b", "CVE-2026-0002", "high", "golang.org/x/net", "v0.58.0", "v0.60.0", "/app", "osv-scanner", "Go"},
		{"cve:c", "CVE-2026-0003", "", "musl", "1.2.5-r0", "", "image:alpine", "trivy", "alpine"},
	} {
		if _, err := ws.Store.SaveVuln(ctx, engagement.Vuln{
			ID: spec.id, TaskID: "scan", Surface: engagement.SurfaceContainer,
			Asset: spec.asset, Scanner: spec.scanner, Advisory: spec.advisory,
			Severity: spec.severity, Package: spec.pkg, PackageVersion: spec.version,
			FixedVersion: spec.fixed, Ecosystem: spec.eco, EvidenceID: ev,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runStoreVulns(t *testing.T, dir string, extra ...string) string {
	t.Helper()
	var out bytes.Buffer
	args := append([]string{"vulns", "--workspace", dir}, extra...)
	if err := runStoreTo(context.Background(), args, &out, nil, ""); err != nil {
		t.Fatalf("store vulns %v: %v", extra, err)
	}
	return out.String()
}

func TestStoreVulnsListsSeverityFirst(t *testing.T) {
	dir := seedVulnWorkspace(t)
	got := runStoreVulns(t, dir)
	for _, want := range []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "zlib", "1.3.2-r1", "image:alpine"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	crit := strings.Index(got, "CVE-2026-0001")
	high := strings.Index(got, "CVE-2026-0002")
	none := strings.Index(got, "CVE-2026-0003")
	if !(crit < high && high < none) {
		t.Errorf("rows are not ordered critical, high, unrated:\n%s", got)
	}
	if !strings.Contains(got, "unknown") {
		t.Errorf("an unrated advisory is not labelled unknown:\n%s", got)
	}
	if !strings.Contains(got, "no fix recorded") {
		t.Errorf("an advisory with no fix is not labelled:\n%s", got)
	}
	// Each scanner records its own finding, so a row names the scanner it came from and two reports of one advisory do not read as a duplicate.
	for _, want := range []string{"image:alpine via trivy", "/app via osv-scanner"} {
		if !strings.Contains(got, want) {
			t.Errorf("a row does not name its scanner (%q):\n%s", want, got)
		}
	}
}

func TestStoreVulnsFilters(t *testing.T) {
	dir := seedVulnWorkspace(t)
	for name, tc := range map[string]struct {
		args    []string
		present []string
		absent  []string
	}{
		"severity":  {[]string{"--severity", "critical"}, []string{"CVE-2026-0001"}, []string{"CVE-2026-0002", "CVE-2026-0003"}},
		"scanner":   {[]string{"--scanner", "osv-scanner"}, []string{"CVE-2026-0002"}, []string{"CVE-2026-0001"}},
		"asset":     {[]string{"--asset", "image:alpine"}, []string{"CVE-2026-0001", "CVE-2026-0003"}, []string{"CVE-2026-0002"}},
		"ecosystem": {[]string{"--ecosystem", "Go"}, []string{"CVE-2026-0002"}, []string{"CVE-2026-0001"}},
		"package":   {[]string{"--package", "musl"}, []string{"CVE-2026-0003"}, []string{"CVE-2026-0001"}},
		"advisory":  {[]string{"--advisory", "CVE-2026-0002"}, []string{"CVE-2026-0002"}, []string{"CVE-2026-0001"}},
	} {
		got := runStoreVulns(t, dir, tc.args...)
		for _, want := range tc.present {
			if !strings.Contains(got, want) {
				t.Errorf("%s: output missing %q:\n%s", name, want, got)
			}
		}
		for _, bad := range tc.absent {
			if strings.Contains(got, bad) {
				t.Errorf("%s: filter leaked %q:\n%s", name, bad, got)
			}
		}
	}
}

func TestStoreVulnsPages(t *testing.T) {
	dir := seedVulnWorkspace(t)
	first := runStoreVulns(t, dir, "--limit", "1")
	if !strings.Contains(first, "CVE-2026-0001") || strings.Contains(first, "CVE-2026-0002") {
		t.Errorf("--limit 1 did not return exactly the first row:\n%s", first)
	}
	second := runStoreVulns(t, dir, "--limit", "1", "--offset", "1")
	if !strings.Contains(second, "CVE-2026-0002") || strings.Contains(second, "CVE-2026-0001") {
		t.Errorf("--offset 1 did not skip the first row:\n%s", second)
	}
	for _, offset := range []string{"3", "5"} {
		past := runStoreVulns(t, dir, "--offset", offset)
		if !strings.Contains(past, "No matching advisories.") {
			t.Errorf("offset %s did not return an empty page:\n%s", offset, past)
		}
	}
}

func TestStoreVulnsUnknownSeverity(t *testing.T) {
	dir := seedVulnWorkspace(t)
	got := runStoreVulns(t, dir, "--severity", "unknown")
	if !strings.Contains(got, "CVE-2026-0003") || strings.Contains(got, "CVE-2026-0001") {
		t.Fatalf("unknown severity filter = %q", got)
	}
	if _, _, _, err := parseStoreArgs([]string{"vulns", "--severity", "info"}); err == nil {
		t.Fatal("vulns accepted info as a severity filter")
	}
	if _, _, _, err := parseStoreArgs([]string{"findings", "--severity", "info"}); err != nil {
		t.Fatalf("findings rejected info severity: %v", err)
	}
}

func TestStoreVulnsJSONCarriesEveryField(t *testing.T) {
	dir := seedVulnWorkspace(t)
	got := runStoreVulns(t, dir, "--json", "--advisory", "CVE-2026-0001")
	var rows []engagement.Vuln
	if err := json.Unmarshal([]byte(got), &rows); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, got)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	r := rows[0]
	if r.Advisory != "CVE-2026-0001" || r.Package != "zlib" || r.PackageVersion != "1.3.2-r0" {
		t.Errorf("identity fields missing: %+v", r)
	}
	if r.FixedVersion != "1.3.2-r1" || r.Severity != "critical" || r.Scanner != "trivy" {
		t.Errorf("detail fields missing: %+v", r)
	}
	if r.EvidenceID <= 0 {
		t.Errorf("EvidenceID = %d, want the exact quote row", r.EvidenceID)
	}
}

func TestStoreVulnsEmptyAndArgumentHandling(t *testing.T) {
	dir := seedVulnWorkspace(t)
	if got := runStoreVulns(t, dir, "--asset", "image:absent"); !strings.Contains(got, "No matching advisories.") {
		t.Errorf("empty result not reported:\n%s", got)
	}
	got := runStoreVulns(t, dir, "--json", "--asset", "image:absent")
	var rows []engagement.Vuln
	if err := json.Unmarshal([]byte(got), &rows); err != nil || len(rows) != 0 {
		t.Errorf("empty JSON result = %q (%v)", got, err)
	}
	var out bytes.Buffer
	if err := runStoreTo(context.Background(), []string{"vulns", "--workspace", dir, "extra"}, &out, nil, ""); err == nil {
		t.Error("store vulns accepted a positional argument")
	}
}

func TestStoreVulnsIsARegisteredAction(t *testing.T) {
	if _, _, _, err := parseStoreArgs([]string{"vulns"}); err != nil {
		t.Errorf("vulns is not an accepted store action: %v", err)
	}
	if _, _, _, err := parseStoreArgs([]string{"nonsense"}); err == nil {
		t.Error("an unknown store action was accepted")
	}
}

func seedSurfaceWorkspace(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ws, err := engagement.OpenWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ctx := context.Background()
	if _, err := ws.Store.Apply(engagement.Delta{Kind: "fixture", Upserts: []engagement.Task{
		{ID: "probe", Status: engagement.StatusActive, Surface: engagement.SurfaceWeb},
	}}); err != nil {
		t.Fatal(err)
	}
	ev, err := ws.Store.RecordEvidence("probe", "probe output")
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct{ id, asset, kind, name, value, gap string }{
		{"s1", "www.example.com", "tls-protocol", "TLSv1.0", "negotiated", "SSLv2 and SSLv3 were not probed"},
		{"s2", "www.example.com", "http-header", "X-Frame-Options", "absent", ""},
		{"s3", "api.example.com", "http-path", "/robots.txt", "status 200 text/plain", ""},
	} {
		if _, err := ws.Store.SaveSurface(ctx, engagement.SurfaceRecord{
			ID: spec.id, TaskID: "probe", Surface: engagement.SurfaceWeb,
			Asset: spec.asset, Kind: spec.kind, Name: spec.name, Value: spec.value,
			Gap: spec.gap, EvidenceID: ev,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runStoreSurface(t *testing.T, dir string, extra ...string) string {
	t.Helper()
	var out bytes.Buffer
	args := append([]string{"surface", "--workspace", dir}, extra...)
	if err := runStoreTo(context.Background(), args, &out, nil, ""); err != nil {
		t.Fatalf("store surface %v: %v", extra, err)
	}
	return out.String()
}

func TestStoreSurfaceListsRecordsWithTheirGaps(t *testing.T) {
	dir := seedSurfaceWorkspace(t)
	got := runStoreSurface(t, dir)
	for _, want := range []string{
		"TLSv1.0", "negotiated", "X-Frame-Options", "absent",
		"/robots.txt", "www.example.com", "api.example.com",
		"gap: SSLv2 and SSLv3 were not probed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	// Records order by asset, so the api host comes before the www host.
	if strings.Index(got, "/robots.txt") > strings.Index(got, "TLSv1.0") {
		t.Errorf("records are not ordered by asset:\n%s", got)
	}
}

func TestStoreSurfaceFilters(t *testing.T) {
	dir := seedSurfaceWorkspace(t)
	for name, tc := range map[string]struct {
		args    []string
		present []string
		absent  []string
	}{
		"kind":  {[]string{"--kind", "http-header"}, []string{"X-Frame-Options"}, []string{"TLSv1.0", "/robots.txt"}},
		"asset": {[]string{"--asset", "api.example.com"}, []string{"/robots.txt"}, []string{"TLSv1.0"}},
		"name":  {[]string{"--name", "TLSv1.0"}, []string{"TLSv1.0"}, []string{"X-Frame-Options"}},
	} {
		got := runStoreSurface(t, dir, tc.args...)
		for _, want := range tc.present {
			if !strings.Contains(got, want) {
				t.Errorf("%s: output missing %q:\n%s", name, want, got)
			}
		}
		for _, bad := range tc.absent {
			if strings.Contains(got, bad) {
				t.Errorf("%s: filter leaked %q:\n%s", name, bad, got)
			}
		}
	}
}

func TestStoreSurfaceJSONCarriesEveryField(t *testing.T) {
	dir := seedSurfaceWorkspace(t)
	got := runStoreSurface(t, dir, "--json", "--name", "TLSv1.0")
	var rows []engagement.SurfaceRecord
	if err := json.Unmarshal([]byte(got), &rows); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, got)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	r := rows[0]
	if r.Kind != "tls-protocol" || r.Name != "TLSv1.0" || r.Value != "negotiated" {
		t.Errorf("fields missing: %+v", r)
	}
	if r.Gap == "" || r.EvidenceID <= 0 {
		t.Errorf("gap and citation missing: %+v", r)
	}
}

func TestStoreSurfaceEmptyPagingAndArguments(t *testing.T) {
	dir := seedSurfaceWorkspace(t)
	if got := runStoreSurface(t, dir, "--asset", "absent.example.com"); !strings.Contains(got, "No matching surface records.") {
		t.Errorf("empty result not reported:\n%s", got)
	}
	first := runStoreSurface(t, dir, "--limit", "1")
	if !strings.Contains(first, "/robots.txt") || strings.Contains(first, "TLSv1.0") {
		t.Errorf("--limit 1 did not return only the first record:\n%s", first)
	}
	second := runStoreSurface(t, dir, "--limit", "1", "--offset", "1")
	if strings.Contains(second, "/robots.txt") {
		t.Errorf("--offset 1 did not skip the first record:\n%s", second)
	}
	for _, offset := range []string{"3", "9"} {
		if got := runStoreSurface(t, dir, "--offset", offset); !strings.Contains(got, "No matching surface records.") {
			t.Errorf("offset %s did not return an empty page:\n%s", offset, got)
		}
	}
	var out bytes.Buffer
	if err := runStoreTo(context.Background(), []string{"surface", "--workspace", dir, "extra"}, &out, nil, ""); err == nil {
		t.Error("store surface accepted a positional argument")
	}
}

func TestStoreSurfaceRejectsAnUnknownKind(t *testing.T) {
	if _, _, _, err := parseStoreArgs([]string{"surface", "--kind", "made-up"}); err == nil {
		t.Error("an unknown surface kind was accepted")
	}
	for _, kind := range engagement.SurfaceKinds() {
		if _, _, _, err := parseStoreArgs([]string{"surface", "--kind", kind}); err != nil {
			t.Errorf("kind %q was rejected: %v", kind, err)
		}
	}
	// The same flag names a record kind for the records verb, which has its own vocabulary, so a surface kind is not accepted there.
	if _, _, _, err := parseStoreArgs([]string{"records", "--kind", "tls-protocol"}); err != nil {
		t.Errorf("parse rejected a records kind it should leave to the verb: %v", err)
	}
	if _, _, _, err := parseStoreArgs([]string{"surface"}); err != nil {
		t.Errorf("surface is not an accepted store action: %v", err)
	}
}
