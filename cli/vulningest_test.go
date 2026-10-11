package main

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
)

func ingestWorkspace(t *testing.T) *engagement.Workspace {
	t.Helper()
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Close() })
	if _, err := ws.Store.Apply(engagement.Delta{Kind: "fixture", Upserts: []engagement.Task{
		{ID: "t1", Status: engagement.StatusActive, Surface: engagement.SurfaceContainer},
	}}); err != nil {
		t.Fatal(err)
	}
	return ws
}

// ingest records quote as evidence for t1 and runs the ingest over that row.
func ingest(t *testing.T, ws *engagement.Workspace, quote string) int {
	t.Helper()
	id, err := ws.Store.RecordEvidence("t1", quote)
	if err != nil {
		t.Fatal(err)
	}
	n, err := ingestVulnReports(context.Background(), ws.Store, "t1", "image:alpine",
		engagement.SurfaceContainer, []engagement.EvidenceRow{{ID: id, Quote: quote}})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestIngestStoresEveryScannersRealReport drives output captured from each scanner through the whole path: detect the scanner, parse, persist, query.
func TestIngestStoresEveryScannersRealReport(t *testing.T) {
	for _, tc := range []struct{ scanner, fixture string }{
		{"osv-scanner", "osv-scanner.json"},
		{"trivy", "trivy.json"},
		{"grype", "grype-dir.json"},
	} {
		ws := ingestWorkspace(t)
		quote := string(readFixture(t, tc.fixture))
		n := ingest(t, ws, quote)
		if n == 0 {
			t.Errorf("%s: stored no advisories from real output", tc.scanner)
			continue
		}
		stored, err := ws.Store.Vulns(context.Background(), engagement.VulnFilter{Scanner: tc.scanner})
		if err != nil {
			t.Fatal(err)
		}
		if len(stored) != n {
			t.Errorf("%s: stored %d records but the query returns %d", tc.scanner, n, len(stored))
		}
		for _, v := range stored {
			if v.EvidenceID <= 0 {
				t.Errorf("%s: %s is not bound to an evidence row", tc.scanner, v.Advisory)
			}
			if v.TaskID != "t1" || v.Surface != engagement.SurfaceContainer {
				t.Errorf("%s: %s is not bound to the task: %+v", tc.scanner, v.Advisory, v)
			}
		}
	}
}

func TestIngestKeepsTheSameAdvisorySeparateByTask(t *testing.T) {
	ws := ingestWorkspace(t)
	if _, err := ws.Store.Apply(engagement.Delta{Kind: "fixture", Upserts: []engagement.Task{
		{ID: "t2", Status: engagement.StatusActive, Surface: engagement.SurfaceContainer},
	}}); err != nil {
		t.Fatal(err)
	}
	report := string(readFixture(t, "osv-scanner.json"))
	for _, taskID := range []string{"t1", "t2"} {
		task, err := ws.Store.GetTask(taskID)
		if err != nil {
			t.Fatal(err)
		}
		task.Target = "image:alpine"
		if _, err := ingestVulnOutput(context.Background(), ws.Store, task, "osv-scanner", report); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := ws.Store.Vulns(context.Background(), engagement.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	byTask := map[string]int{}
	for _, row := range rows {
		byTask[row.TaskID]++
		quotes, err := ws.Store.EvidenceRowsFor(row.TaskID)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, q := range quotes {
			found = found || q.ID == row.EvidenceID
		}
		if !found {
			t.Errorf("%s cites evidence outside task %s", row.Advisory, row.TaskID)
		}
	}
	if byTask["t1"] == 0 || byTask["t1"] != byTask["t2"] {
		t.Errorf("advisories by task = %v, want equal nonzero counts", byTask)
	}
}

func TestIngestCitesAdvisoryBeyondReportEvidenceCap(t *testing.T) {
	ws := ingestWorkspace(t)
	task, err := ws.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	task.Target = "image:alpine"
	report := strings.Repeat("progress ", engagement.EvidenceCap) + string(readFixture(t, "osv-scanner.json"))
	if _, err := ingestVulnOutput(context.Background(), ws.Store, task, "osv-scanner", report); err != nil {
		t.Fatal(err)
	}
	rows, err := ws.Store.Vulns(context.Background(), engagement.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no advisories stored")
	}
	quotes, err := ws.Store.EvidenceRowsFor("t1")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[int64]string{}
	for _, q := range quotes {
		byID[q.ID] = q.Quote
	}
	for _, row := range rows {
		if !strings.Contains(byID[row.EvidenceID], row.Advisory) {
			t.Errorf("%s cites evidence that omits the advisory", row.Advisory)
		}
	}
}

// The runner appends a command's stderr to its stdout, so a real capture is the report followed by the scanner's progress lines.
func TestIngestReadsAReportFollowedByProgressOutput(t *testing.T) {
	ws := ingestWorkspace(t)
	quote := string(readFixture(t, "osv-scanner.json")) +
		"Starting filesystem walk for root: /\nScanned /work/go.mod file and found 72 packages\n"
	if n := ingest(t, ws, quote); n == 0 {
		t.Error("a report with trailing progress output stored nothing")
	}
}

func TestIngestReadsAReportAfterLeadingOutput(t *testing.T) {
	ws := ingestWorkspace(t)
	quote := "scanning /work\n" + string(readFixture(t, "grype-dir.json"))
	if n := ingest(t, ws, quote); n == 0 {
		t.Error("a report with leading output stored nothing")
	}
}

// The scanner is identified by the report's own keys rather than by a trial decode: encoding/json matches a field name case-insensitively, so decoding osv-scanner's "results" into trivy's Results field would succeed.
func TestScannerDetectionDistinguishesResultsByCase(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"osv", `{"results":[]}`, "osv-scanner"},
		{"trivy", `{"SchemaVersion":2,"Results":[]}`, "trivy"},
		{"grype", `{"matches":[],"descriptor":{"name":"grype"}}`, "grype"},
	} {
		raw, ok := reportObject(tc.body)
		if !ok {
			t.Errorf("%s: no report object found in %q", tc.name, tc.body)
			continue
		}
		got, ok := scannerFromReport(raw)
		if !ok || got != tc.want {
			t.Errorf("%s: scanner = %q (%v), want %q", tc.name, got, ok, tc.want)
		}
	}
}

// An object must carry every key its scanner's report carries. One shared key is not an identification: "matches" alone, or "Results" alone, would claim a report the parser cannot read.
func TestScannerDetectionRequiresEveryKey(t *testing.T) {
	for _, body := range []string{
		`{"matches":[]}`,
		`{"descriptor":{"name":"grype"}}`,
		`{"Results":[]}`,
		`{"SchemaVersion":2}`,
		`{"not":"a scanner report"}`,
		`{}`,
	} {
		raw, ok := reportObject(body)
		if !ok {
			t.Errorf("no object found in %q", body)
			continue
		}
		if got, ok := scannerFromReport(raw); ok {
			t.Errorf("%s was identified as %q", body, got)
		}
	}
	raw, _ := reportObject(`{"results":[]}`)
	if got, _ := scannerFromReport(raw); got != "osv-scanner" {
		t.Errorf(`a lower-case "results" was identified as %q`, got)
	}
}

func TestIngestSkipsOutputThatIsNotAScannerReport(t *testing.T) {
	ws := ingestWorkspace(t)
	for _, quote := range []string{
		"Nmap scan report for 10.0.0.5\n8080/tcp open http nginx 1.25.5",
		`{"not":"a scanner report"}`,
		"{ truncated", // not a complete object
		"",            // nothing captured
		`HTTP/1.1 200 OK` + "\n" + `{"x":1}`,
	} {
		if n := ingest(t, ws, quote); n != 0 {
			t.Errorf("stored %d records from %q", n, quote)
		}
	}
	stored, err := ws.Store.Vulns(context.Background(), engagement.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 0 {
		t.Errorf("non-report output produced %d records", len(stored))
	}
}

// Ingesting the same report twice must update the rows in place, so a rescan does not multiply an engagement's advisory count.
func TestIngestIsIdempotentAcrossRescans(t *testing.T) {
	ws := ingestWorkspace(t)
	quote := string(readFixture(t, "grype-dir.json"))
	first := ingest(t, ws, quote)
	if first == 0 {
		t.Fatal("stored nothing on the first pass")
	}
	ingest(t, ws, quote)
	stored, err := ws.Store.Vulns(context.Background(), engagement.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != first {
		t.Errorf("a rescan changed the record count from %d to %d", first, len(stored))
	}
}

// A report whose records the store rejects must be audited, not dropped silently: an advisory that failed to store has to be visible somewhere.
func TestIngestAuditsRejectedRecords(t *testing.T) {
	ws := ingestWorkspace(t)
	// An osv-scanner report names no asset of its own, so with no asset to attribute the advisories to the store rejects every record.
	quote := string(readFixture(t, "osv-scanner.json"))
	id, err := ws.Store.RecordEvidence("t1", quote)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := ingestVulnReports(context.Background(), ws.Store, "t1", "",
		engagement.SurfaceContainer, []engagement.EvidenceRow{{ID: id, Quote: quote}})
	if err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Errorf("stored %d records with no asset", stored)
	}
	trail := auditTrail(t, ws)
	if !strings.Contains(trail, "record-rejected") {
		t.Errorf("a rejected record was not audited:\n%s", trail)
	}
	if !strings.Contains(trail, "ingested") {
		t.Errorf("the ingest itself was not audited:\n%s", trail)
	}
}

// auditTrail returns the engagement's audit rows as text.
func auditTrail(t *testing.T, ws *engagement.Workspace) string {
	t.Helper()
	page, err := ws.Store.Records(context.Background(), "audit", "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, r := range page.Records {
		b.Write(r.Document)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestIngestAuditsAParseFailure(t *testing.T) {
	ws := ingestWorkspace(t)
	// The object is a valid grype report by its keys but its matches array is the wrong JSON type, so the parse fails after detection.
	ingest(t, ws, `{"matches":"not an array","descriptor":{"name":"grype"}}`)
	if trail := auditTrail(t, ws); !strings.Contains(trail, "parse-failed") {
		t.Errorf("a parse failure was not audited:\n%s", trail)
	}
}

// reportObject must bound the input it will decode, so a capture larger than the scan limit is not parsed.
func TestReportObjectRefusesOversizeOutput(t *testing.T) {
	big := `{"results":[]}` + strings.Repeat(" ", maxScanBytes)
	if _, ok := reportObject(big); ok {
		t.Error("an oversize capture was accepted for decoding")
	}
	if _, ok := reportObject(`{"results":[]}`); !ok {
		t.Error("a bounded capture was refused")
	}
}

// Each advisory cites a durable quote that names its source report and its own identifier.
func TestIngestBindsEachRecordToItsOwnEvidenceRow(t *testing.T) {
	ws := ingestWorkspace(t)
	var rows []engagement.EvidenceRow
	sources := map[string]int64{}
	for _, tc := range []struct{ scanner, name string }{{"grype", "grype-dir.json"}, {"trivy", "trivy.json"}} {
		quote := string(readFixture(t, tc.name))
		id, err := ws.Store.RecordEvidence("t1", quote)
		if err != nil {
			t.Fatal(err)
		}
		sources[tc.scanner] = id
		rows = append(rows, engagement.EvidenceRow{ID: id, Quote: quote})
	}
	if _, err := ingestVulnReports(context.Background(), ws.Store, "t1", "image:alpine",
		engagement.SurfaceContainer, rows); err != nil {
		t.Fatal(err)
	}
	byScanner := map[string]bool{}
	quotes, err := ws.Store.EvidenceRowsFor("t1")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[int64]string{}
	for _, q := range quotes {
		byID[q.ID] = q.Quote
	}
	stored, err := ws.Store.Vulns(context.Background(), engagement.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range stored {
		quote := byID[v.EvidenceID]
		if !strings.Contains(quote, "scanner="+v.Scanner) ||
			!strings.Contains(quote, "source_evidence="+strconv.FormatInt(sources[v.Scanner], 10)) ||
			!strings.Contains(quote, "advisory="+v.Advisory) {
			t.Errorf("%s cites a quote without its scanner, source row, or advisory: %q", v.Advisory, quote)
		}
		byScanner[v.Scanner] = true
	}
	if len(byScanner) != 2 {
		t.Fatalf("stored records from %d scanners, want 2", len(byScanner))
	}
}

// The ingest reads only the report. A record must never take a field from text outside the JSON object.
func TestIngestIgnoresTextOutsideTheReport(t *testing.T) {
	ws := ingestWorkspace(t)
	quote := `{"matches":[{"vulnerability":{"id":"CVE-2026-0001","severity":"Low",
		"fix":{"versions":["2.0"]}},"artifact":{"name":"p","version":"1.0","type":"apk",
		"locations":[{"path":"/lib/apk/db/installed"}]}}],
		"source":{"type":"directory","target":"work"},"descriptor":{"name":"grype","version":"0.100.0"}}
		CVE-2026-9999 critical injected-package 9.9`
	if n := ingest(t, ws, quote); n != 1 {
		t.Fatalf("stored %d records, want 1", n)
	}
	stored, err := ws.Store.Vulns(context.Background(), engagement.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if stored[0].Advisory != "CVE-2026-0001" || stored[0].Severity != "low" {
		t.Errorf("record took a field from outside the report: %+v", stored[0])
	}
	if stored[0].Package == "injected-package" {
		t.Error("the trailing text was read as a record")
	}
}

func TestReportObjectReadsOneObjectOnly(t *testing.T) {
	raw, ok := reportObject(`{"results":[]}{"results":[{"injected":true}]}`)
	if !ok {
		t.Fatal("no object found")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("the extracted object is not valid JSON: %v", err)
	}
	if string(top["results"]) != "[]" {
		t.Errorf("results = %s, want the first object's empty array", top["results"])
	}
}
