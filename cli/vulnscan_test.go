package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
)

const osvSample = `{
  "results": [
    {
      "source": {"path": "/app/go.mod", "type": "lockfile"},
      "packages": [
        {
          "package": {"name": "golang.org/x/net", "version": "v0.58.0", "ecosystem": "Go"},
          "vulnerabilities": [
            {
              "id": "GO-2026-6617",
              "aliases": ["CVE-2026-1111", ""],
              "summary": "HTTP/2 flaw\nwith a newline",
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
              "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "v0.60.0"}]}]}]
            },
            {
              "id": "GO-2026-6613",
              "database_specific": {"severity": "MODERATE"},
              "summary": "second advisory"
            }
          ],
          "groups": [
            {"ids": ["GO-2026-6617"], "max_severity": "7.5"},
            {"ids": ["GO-2026-6613"], "max_severity": "5.3"}
          ]
        }
      ]
    }
  ]
}`

const trivySample = `{
  "ArtifactName": "alpine:3.23.6",
  "Trivy": {"Version": "0.75.0"},
  "Results": [
    {
      "Target": "alpine:3.23.6 (alpine 3.23.6)",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2026-2222",
          "PkgName": "zlib",
          "InstalledVersion": "1.3.2-r0",
          "FixedVersion": "1.3.2-r1",
          "Severity": "CRITICAL",
          "Title": "zlib heap overflow",
          "PkgPath": "lib/libz.so.1",
          "CVSS": {
            "redhat": {"V3Vector": "CVSS:3.1/AV:L", "V3Score": 7.8},
            "nvd": {"V3Vector": "CVSS:3.1/AV:N", "V3Score": 9.8}
          }
        },
        {
          "VulnerabilityID": "CVE-2026-3333",
          "PkgName": "musl",
          "InstalledVersion": "1.2.5-r0",
          "Severity": "LOW",
          "Description": "fallback description used when Title is absent"
        }
      ]
    }
  ]
}`

func TestParseOSVScannerReadsEveryField(t *testing.T) {
	got, err := parseOSVScanner([]byte(osvSample), "/app", "2.2.4")
	if err != nil {
		t.Fatalf("parseOSVScanner: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	first := got[0]
	if first.Advisory != "GO-2026-6617" || first.Package != "golang.org/x/net" || first.PackageVersion != "v0.58.0" {
		t.Errorf("identity fields wrong: %+v", first)
	}
	if first.Ecosystem != "Go" || first.Location != "/app/go.mod" {
		t.Errorf("source fields wrong: %+v", first)
	}
	if first.FixedVersion != "v0.60.0" {
		t.Errorf("FixedVersion = %q, want v0.60.0", first.FixedVersion)
	}
	if first.CVSS != "CVSS:3.1/AV:N/AC:L" {
		t.Errorf("CVSS = %q, want the advisory's own vector", first.CVSS)
	}
	if first.Scanner != "osv-scanner" || first.ScannerVersion != "2.2.4" {
		t.Errorf("scanner fields wrong: %+v", first)
	}
	// The group rating is a base score, so it reaches the record as a band.
	if first.Severity != "high" {
		t.Errorf("Severity = %q, want the 7.5 group score banded as high", first.Severity)
	}
	// An advisory with its own rating keeps it rather than the group value.
	if got[1].Severity != "MODERATE" {
		t.Errorf("second Severity = %q, want MODERATE", got[1].Severity)
	}
	if strings.ContainsAny(first.Summary, "\r\n") {
		t.Errorf("Summary kept a newline the store rejects: %q", first.Summary)
	}
	if len(first.Aliases) != 1 || first.Aliases[0] != "CVE-2026-1111" {
		t.Errorf("Aliases = %v, want the empty entry dropped", first.Aliases)
	}
}

func TestParseTrivyReadsEveryField(t *testing.T) {
	got, err := parseTrivy([]byte(trivySample), "ignored-by-artifact-name", "0.68.0")
	if err != nil {
		t.Fatalf("parseTrivy: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	first := got[0]
	if first.Asset != "alpine:3.23.6" {
		t.Errorf("Asset = %q, want the report's own ArtifactName", first.Asset)
	}
	if first.Advisory != "CVE-2026-2222" || first.Package != "zlib" || first.PackageVersion != "1.3.2-r0" {
		t.Errorf("identity fields wrong: %+v", first)
	}
	if first.FixedVersion != "1.3.2-r1" || first.Severity != "CRITICAL" {
		t.Errorf("fix and severity wrong: %+v", first)
	}
	if first.Ecosystem != "alpine" || first.Location != "lib/libz.so.1" {
		t.Errorf("source fields wrong: %+v", first)
	}
	if first.ScannerVersion != "0.75.0" {
		t.Errorf("ScannerVersion = %q, want the report's own Trivy.Version", first.ScannerVersion)
	}
	// The vector is chosen by lowest source key so the value is deterministic.
	if first.CVSS != "CVSS:3.1/AV:N" {
		t.Errorf("CVSS = %q, want the nvd vector chosen deterministically", first.CVSS)
	}
	if got[1].Summary != "fallback description used when Title is absent" {
		t.Errorf("Description fallback not used: %q", got[1].Summary)
	}
	if got[1].Location != "alpine:3.23.6 (alpine 3.23.6)" {
		t.Errorf("Target fallback not used for Location: %q", got[1].Location)
	}
}

func TestVulnIDIsStableAndDistinguishing(t *testing.T) {
	a, err := parseTrivy([]byte(trivySample), "x", "0.68.0")
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseTrivy([]byte(trivySample), "x", "0.68.0")
	if err != nil {
		t.Fatal(err)
	}
	if a[0].ID != b[0].ID {
		t.Errorf("id is not stable across parses: %q then %q", a[0].ID, b[0].ID)
	}
	if a[0].ID == a[1].ID {
		t.Error("two advisories share one id")
	}
	// A different version of the same package must not collide, so a rescan after an upgrade adds a row rather than overwriting the old one.
	shifted := strings.Replace(trivySample, `"InstalledVersion": "1.3.2-r0"`, `"InstalledVersion": "1.3.2-r9"`, 1)
	c, err := parseTrivy([]byte(shifted), "x", "0.68.0")
	if err != nil {
		t.Fatal(err)
	}
	if c[0].ID == a[0].ID {
		t.Error("version is not part of the id")
	}
	for _, v := range append(a, c...) {
		if len(v.ID) > 96 || !strings.HasPrefix(v.ID, "cve:") {
			t.Errorf("id %q is not a bounded cve: id", v.ID)
		}
	}
}

func TestParseVulnScanDropsRecordsWithoutIdentity(t *testing.T) {
	osvNoID := `{"results":[{"source":{"path":"p"},"packages":[{"package":{"name":"pkg","version":"1"},
		"vulnerabilities":[{"id":"","summary":"no id"},{"id":"CVE-1","summary":"kept"}]}]}]}`
	got, err := parseOSVScanner([]byte(osvNoID), "a", "v")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Advisory != "CVE-1" {
		t.Errorf("records = %+v, want only the advisory with an id", got)
	}

	osvNoPkg := `{"results":[{"source":{"path":"p"},"packages":[{"package":{"name":"","version":"1"},
		"vulnerabilities":[{"id":"CVE-2"}]}]}]}`
	got, err = parseOSVScanner([]byte(osvNoPkg), "a", "v")
	if err != nil || len(got) != 0 {
		t.Errorf("records = %+v (%v), want none without a package name", got, err)
	}

	trivyNoPkg := `{"Results":[{"Type":"go","Vulnerabilities":[{"VulnerabilityID":"CVE-3","PkgName":""}]}]}`
	got, err = parseTrivy([]byte(trivyNoPkg), "a", "v")
	if err != nil || len(got) != 0 {
		t.Errorf("records = %+v (%v), want none without a package name", got, err)
	}
}

func TestParseVulnScanRejectsBadInput(t *testing.T) {
	err := func() error {
		_, e := parseVulnScan("unknown-tool", []byte("{}"), "a", "v")
		return e
	}()
	if err == nil {
		t.Error("accepted an unknown scanner")
	} else {
		for _, name := range vulnScanners() {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("the error does not name the accepted scanner %q: %v", name, err)
			}
		}
	}
	for _, name := range vulnScanners() {
		if _, e := parseVulnScan(name, []byte("{}"), "a", "v"); e != nil {
			t.Errorf("scanner %q was rejected: %v", name, e)
		}
	}
	if _, err := parseVulnScan("osv-scanner", []byte("not json"), "a", "v"); err == nil {
		t.Error("accepted malformed JSON")
	}
	if _, err := parseVulnScan("trivy", []byte("["), "a", "v"); err == nil {
		t.Error("accepted truncated JSON")
	}
	// The size check must reject before decoding, so the error names the limit rather than whatever the decoder would have said about the bytes.
	big := append([]byte(`{"Results":[]}`), make([]byte, maxScanBytes)...)
	_, err = parseVulnScan("trivy", big, "a", "v")
	if err == nil {
		t.Error("accepted output past the size limit")
	} else if !strings.Contains(err.Error(), "size limit") {
		t.Errorf("oversize output reported as %v, want the size-limit error", err)
	}
	if _, err := parseVulnScan("osv-scanner", big, "a", "v"); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Errorf("osv-scanner oversize output reported as %v", err)
	}
}

func TestParsedRecordsSurviveStoreValidation(t *testing.T) {
	// Fields the store rejects must already be stripped by the parser, so a hostile scanner summary cannot block the whole scan from persisting. Control characters are planted in a field that goes through sanitizeField as well as in the title, which goes through truncateSummary.
	hostile := strings.NewReplacer(
		`"Title": "zlib heap overflow"`, `"Title": "line one\r\nInjected: yes"`,
		`"FixedVersion": "1.3.2-r1"`, `"FixedVersion": "1.3.2-r1\r\nInjected: yes"`,
		`"PkgPath": "lib/libz.so.1"`, `"PkgPath": "lib/\u0000libz.so.1"`,
	).Replace(trivySample)
	got, err := parseTrivy([]byte(hostile), "a\nInjected: yes", "v\x00")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no records parsed")
	}
	for _, v := range got {
		if strings.ContainsAny(v.ScannerVersion, "\x00\r\n") {
			t.Errorf("scanner version kept a control character: %q", v.ScannerVersion)
		}
	}
	for _, v := range got {
		for name, field := range map[string]string{
			"asset": v.Asset, "advisory": v.Advisory, "package": v.Package,
			"version": v.PackageVersion, "ecosystem": v.Ecosystem,
			"fixed": v.FixedVersion, "cvss": v.CVSS, "location": v.Location,
		} {
			if strings.ContainsAny(field, "\x00\r\n") {
				t.Errorf("%s kept a control character: %q", name, field)
			}
		}
		if strings.ContainsRune(v.Summary, '\x00') {
			t.Errorf("summary kept a NUL: %q", v.Summary)
		}
		if len(v.Summary) > 4096 {
			t.Errorf("summary length %d exceeds the store bound", len(v.Summary))
		}
	}
}

func TestParsedRecordsPersistThroughTheStore(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ctx := context.Background()
	if _, err := ws.Store.Apply(engagement.Delta{Kind: "fixture", Upserts: []engagement.Task{
		{ID: "scan-task", Status: engagement.StatusActive, Surface: engagement.SurfaceContainer},
	}}); err != nil {
		t.Fatal(err)
	}
	ev, err := ws.Store.RecordEvidence("scan-task", "trivy output")
	if err != nil {
		t.Fatal(err)
	}

	hostile := strings.Replace(trivySample, `"Title": "zlib heap overflow"`,
		`"Title": "line one\r\nInjected: yes"`, 1)
	parsed, err := parseTrivy([]byte(hostile), "a", "0.68.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) == 0 {
		t.Fatal("no records parsed")
	}
	for _, v := range parsed {
		v.TaskID, v.Surface, v.EvidenceID = "scan-task", engagement.SurfaceContainer, ev
		if _, err := ws.Store.SaveVuln(ctx, v); err != nil {
			t.Fatalf("store rejected a parsed record %q: %v", v.Advisory, err)
		}
	}
	stored, err := ws.Store.Vulns(ctx, engagement.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != len(parsed) {
		t.Fatalf("stored %d of %d parsed records", len(stored), len(parsed))
	}
	if stored[0].Severity != "critical" {
		t.Errorf("severity = %q, want the store's normalized critical", stored[0].Severity)
	}
}

func TestParseTrivyHandlesAnEmptyReport(t *testing.T) {
	for _, in := range []string{`{}`, `{"Results":[]}`, `{"Results":[{"Type":"go","Vulnerabilities":[]}]}`} {
		got, err := parseTrivy([]byte(in), "a", "v")
		if err != nil || len(got) != 0 {
			t.Errorf("input %q: got %d records, %v", in, len(got), err)
		}
	}
	for _, in := range []string{`{}`, `{"results":[]}`} {
		got, err := parseOSVScanner([]byte(in), "a", "v")
		if err != nil || len(got) != 0 {
			t.Errorf("input %q: got %d records, %v", in, len(got), err)
		}
	}
}

func TestCVSSBandFollowsTheV31Scale(t *testing.T) {
	for in, want := range map[string]string{
		"10.0": "critical", "9.0": "critical", "8.9": "high", "7.0": "high",
		"6.9": "medium", "4.0": "medium", "3.9": "low", "0.1": "low",
		"0.0": "none", "": "", "none": "", "10.1": "", "-1": "", "7": "high",
	} {
		if got := cvssBand(in); got != want {
			t.Errorf("cvssBand(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseGrypeReadsEveryField(t *testing.T) {
	got, err := parseGrype(readFixture(t, "grype-dir.json"), "ignored", "fallback")
	if err != nil {
		t.Fatalf("parseGrype: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	first := got[0]
	if first.Asset != "vulnfix" {
		t.Errorf("Asset = %q, want the report's own string source target", first.Asset)
	}
	if first.Advisory != "GHSA-45x7-px36-x8w8" || first.Package != "golang.org/x/crypto" {
		t.Errorf("identity fields wrong: %+v", first)
	}
	if first.PackageVersion != "v0.10.0" || first.Ecosystem != "go-module" {
		t.Errorf("package fields wrong: %+v", first)
	}
	if first.FixedVersion != "0.17.0" {
		t.Errorf("FixedVersion = %q, want the first fix version", first.FixedVersion)
	}
	if first.Severity != "Medium" {
		t.Errorf("Severity = %q, want grype's own word rating", first.Severity)
	}
	if first.CVSS != "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" {
		t.Errorf("CVSS = %q, want the v3.1 vector", first.CVSS)
	}
	if first.Location != "/go.mod" {
		t.Errorf("Location = %q, want the artifact's first location path", first.Location)
	}
	if len(first.Aliases) == 0 || first.Aliases[0] != "CVE-2023-48795" {
		t.Errorf("Aliases = %v, want the related vulnerability ids", first.Aliases)
	}
	// The descriptor of a locally built grype reports no version, so the caller's value stands rather than the placeholder.
	if first.ScannerVersion != "fallback" {
		t.Errorf("ScannerVersion = %q, want the caller's value", first.ScannerVersion)
	}
}

func TestParseGrypeReadsAnImageSourceTarget(t *testing.T) {
	got, err := parseGrype(readFixture(t, "grype-image.json"), "ignored", "v")
	if err != nil {
		t.Fatalf("parseGrype: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no records parsed")
	}
	if got[0].Asset != "alpine:3.18" {
		t.Errorf("Asset = %q, want the image source userInput", got[0].Asset)
	}
	if got[0].Ecosystem != "apk" {
		t.Errorf("Ecosystem = %q, want the artifact type", got[0].Ecosystem)
	}
	if got[0].Location != "/lib/apk/db/installed" {
		t.Errorf("Location = %q, want the apk database path", got[0].Location)
	}
}

func TestParseGrypeDropsRecordsWithoutIdentity(t *testing.T) {
	in := `{"matches":[{"vulnerability":{"id":""},"artifact":{"name":"p","version":"1"}},
		{"vulnerability":{"id":"CVE-1"},"artifact":{"name":"","version":"1"}},
		{"vulnerability":{"id":"CVE-2"},"artifact":{"name":"p","version":"1"}}],
		"source":{"type":"directory","target":"d"}}`
	got, err := parseGrype([]byte(in), "a", "v")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Advisory != "CVE-2" {
		t.Errorf("records = %+v, want only the complete match", got)
	}
}

func TestParseGrypeRejectsBadInput(t *testing.T) {
	if _, err := parseGrype([]byte("not json"), "a", "v"); err == nil {
		t.Error("accepted malformed JSON")
	}
	big := append([]byte(`{"matches":[]}`), make([]byte, maxScanBytes)...)
	if _, err := parseGrype(big, "a", "v"); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Errorf("oversize output reported as %v, want the size-limit error", err)
	}
	for _, in := range []string{`{}`, `{"matches":[]}`} {
		got, err := parseGrype([]byte(in), "a", "v")
		if err != nil || len(got) != 0 {
			t.Errorf("input %q: got %d records, %v", in, len(got), err)
		}
	}
}

// TestParsersReadRealScannerOutput runs each parser over output captured from the scanner itself, so a schema change in any of them fails here rather than silently yielding records with empty fields.
func TestParsersReadRealScannerOutput(t *testing.T) {
	for _, tc := range []struct {
		scanner, fixture, wantAdvisory, wantEcosystem, wantLocation string
	}{
		{"osv-scanner", "osv-scanner.json", "GO-2023-2402", "Go", "/work/go.mod"},
		{"trivy", "trivy.json", "CVE-2024-45337", "gomod", "go.mod"},
		{"grype", "grype-dir.json", "GHSA-45x7-px36-x8w8", "go-module", "/go.mod"},
	} {
		got, err := parseVulnScan(tc.scanner, readFixture(t, tc.fixture), "fallback-asset", "fallback-version")
		if err != nil {
			t.Errorf("%s: %v", tc.scanner, err)
			continue
		}
		if len(got) == 0 {
			t.Errorf("%s: parsed no records from real output", tc.scanner)
			continue
		}
		found := false
		for _, v := range got {
			if v.Advisory == "" || v.Package == "" || v.PackageVersion == "" {
				t.Errorf("%s: record has an empty identity field: %+v", tc.scanner, v)
			}
			if v.Scanner != tc.scanner {
				t.Errorf("%s: record reports scanner %q", tc.scanner, v.Scanner)
			}
			if v.Ecosystem != tc.wantEcosystem {
				t.Errorf("%s: Ecosystem = %q, want %q", tc.scanner, v.Ecosystem, tc.wantEcosystem)
			}
			if v.Location != tc.wantLocation {
				t.Errorf("%s: Location = %q, want %q", tc.scanner, v.Location, tc.wantLocation)
			}
			// Every real record carries a rating and a fix, which is what makes a stored advisory actionable; a CVSS vector is not always published, so it is asserted on the named advisory only.
			if v.Severity == "" {
				t.Errorf("%s: %s carries no severity", tc.scanner, v.Advisory)
			}
			if v.FixedVersion == "" {
				t.Errorf("%s: %s carries no fixed version", tc.scanner, v.Advisory)
			}
			if v.Advisory == tc.wantAdvisory {
				found = true
				if v.Package != "golang.org/x/crypto" {
					t.Errorf("%s: %s names package %q", tc.scanner, v.Advisory, v.Package)
				}
			}
		}
		if !found {
			t.Errorf("%s: real output did not yield %s", tc.scanner, tc.wantAdvisory)
		}
	}
}

// TestRealScannerOutputNormalizesIntoTheStore proves the severities the real scanners emit survive the store's own vocabulary rather than collapsing to unknown.
func TestRealScannerOutputNormalizesIntoTheStore(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
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
	for _, tc := range []struct{ scanner, fixture string }{
		{"osv-scanner", "osv-scanner.json"},
		{"trivy", "trivy.json"},
		{"grype", "grype-dir.json"},
	} {
		parsed, err := parseVulnScan(tc.scanner, readFixture(t, tc.fixture), "asset", "v")
		if err != nil {
			t.Fatalf("%s: %v", tc.scanner, err)
		}
		for _, v := range parsed {
			v.TaskID, v.Surface, v.EvidenceID = "scan", engagement.SurfaceContainer, ev
			if _, err := ws.Store.SaveVuln(ctx, v); err != nil {
				t.Fatalf("%s: store rejected %q: %v", tc.scanner, v.Advisory, err)
			}
		}
	}
	stored, err := ws.Store.Vulns(ctx, engagement.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) == 0 {
		t.Fatal("nothing stored")
	}
	for _, v := range stored {
		if v.Severity == "unknown" || v.Severity == "" {
			t.Errorf("%s from %s normalized to %q", v.Advisory, v.Scanner, v.Severity)
		}
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A local scanner input names no assessed asset, so the report keeps the task's target.
func TestGrypeKeepsTheTaskTargetForLocalScanInput(t *testing.T) {
	for _, target := range []string{".", "./", "/work", "dir:.", "docker-archive:image.tar", "oci-archive:image.tar", "sbom:sbom.json", "", "  "} {
		report := []byte(`{"matches":[{"artifact":{"name":"golang.org/x/crypto","version":"v0.10.0","type":"go-module"},` +
			`"vulnerability":{"id":"GHSA-test","severity":"Critical"}}],` +
			`"source":{"type":"directory","target":"` + target + `"},"descriptor":{"name":"grype","version":"0.104.1"}}`)
		vulns, err := parseGrype(report, "172.17.0.3", "")
		if err != nil {
			t.Fatalf("target %q: %v", target, err)
		}
		if len(vulns) != 1 {
			t.Fatalf("target %q: parsed %d records", target, len(vulns))
		}
		if vulns[0].Asset != "172.17.0.3" {
			t.Errorf("target %q: asset is %q, want the task target", target, vulns[0].Asset)
		}
	}
	archive := []byte(`{"matches":[{"artifact":{"name":"busybox","version":"1.0","type":"apk"},` +
		`"vulnerability":{"id":"CVE-2026-0002","severity":"High"}}],` +
		`"source":{"type":"image","target":{"userInput":"docker-archive:image.tar"}},"descriptor":{"name":"grype"}}`)
	if vulns, err := parseGrype(archive, "172.17.0.3", ""); err != nil || len(vulns) != 1 || vulns[0].Asset != "172.17.0.3" {
		t.Errorf("archive source replaced the task asset: %+v, %v", vulns, err)
	}
	// A source that names a real asset is still preferred over the task target.
	report := []byte(`{"matches":[{"artifact":{"name":"openssl","version":"1.1.1","type":"apk"},` +
		`"vulnerability":{"id":"CVE-2222-1","severity":"High"}}],` +
		`"source":{"type":"image","target":"registry.test/app:1.0"},"descriptor":{"name":"grype"}}`)
	vulns, err := parseGrype(report, "172.17.0.3", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 || vulns[0].Asset != "registry.test/app:1.0" {
		t.Errorf("a named source was not preferred: %+v", vulns)
	}
}

// Local scanner inputs do not replace the task's asset with a scratch path.
func TestLocalScanSourceDoesNotReplaceTheAsset(t *testing.T) {
	for _, target := range []string{"", " ", ".", "./", "..", "/work", "/work/", "dir:.", "file:go.mod", "sbom:sbom.json", "docker-archive:image.tar", "oci-archive:image.tar"} {
		if !localScanSource(target) {
			t.Errorf("%q is not recognized as local scanner input", target)
		}
	}
	for _, target := range []string{
		"registry.test/app:1.0", "/srv/app", "172.17.0.3", "image.tar",
		"./vendor", "/workspace", "work",
	} {
		if localScanSource(target) {
			t.Errorf("%q was discarded as local scanner input", target)
		}
	}
}
