package main

import (
	"blkchain/cli/internal/webanalysis"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/engreport"
)

func TestReportDenialsAreBoundedAndVisible(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	for i := 0; i < 150; i++ {
		if err := ws.AuditLine("secgate", "deny:scope", fmt.Sprintf("attempt %d :: out of scope", i)); err != nil {
			t.Fatal(err)
		}
	}
	denials, omitted, err := readAuditDenials(filepath.Join(ws.Dir, "audit.jsonl"))
	if err != nil || len(denials) != 100 || omitted != 50 {
		t.Fatalf("denials=%d omitted=%d err=%v", len(denials), omitted, err)
	}
	markdown := engreport.RenderMarkdown(engreport.Model{Denials: denials, DenialsOmitted: omitted})
	if !strings.Contains(markdown, "## Policy denials") || !strings.Contains(markdown, "50 additional denial") {
		t.Fatalf("denials missing from report: %q", markdown)
	}
}

func TestReportPaths(t *testing.T) {
	md, js := reportPaths("/ws")
	if md != filepath.Join("/ws", "report.md") || js != filepath.Join("/ws", "report.json") {
		t.Errorf("paths = %q %q", md, js)
	}
}

func TestAtomicReportWriteDoesNotFollowTempSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.md")
	victim := filepath.Join(t.TempDir(), "operator-file")
	if err := os.WriteFile(victim, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(path, []byte("new report")); err != nil {
		t.Fatal(err)
	}
	gotVictim, err := os.ReadFile(victim)
	if err != nil || string(gotVictim) != "original" {
		t.Fatalf("operator file changed: %q err=%v", gotVictim, err)
	}
	gotReport, err := os.ReadFile(path)
	if err != nil || string(gotReport) != "new report" {
		t.Fatalf("report=%q err=%v", gotReport, err)
	}
}

func TestReportWriterWritesBothFiles(t *testing.T) {
	ws := t.TempDir()
	st := openStore(t)
	if _, err := st.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Status: engagement.StatusTodo}}, Kind: "init"}); err != nil {
		t.Fatal(err)
	}
	w := newReportWriter(st, ws, "goal-x", "in: x", "auto")
	if err := w.Flush("in-progress"); err != nil {
		t.Fatal(err)
	}
	md, js := reportPaths(ws)
	b, err := os.ReadFile(md)
	if err != nil {
		t.Fatalf("report.md missing: %v", err)
	}
	if !strings.Contains(string(b), "goal-x") {
		t.Errorf("report.md missing goal")
	}
	jb, err := os.ReadFile(js)
	if err != nil {
		t.Fatalf("report.json missing: %v", err)
	}
	if !strings.Contains(string(jb), "goal-x") {
		t.Errorf("report.json missing goal")
	}
}

func TestReportWriterPersistsFinalAssessment(t *testing.T) {
	ws := t.TempDir()
	st := openStore(t)
	w := newReportWriter(st, ws, "inspect example", "in: example", "auto")
	final := "Confirmed response\n<script>alert(1)</script>\x1b[31m"
	w.SetFinal(final)
	if err := w.Flush("paused"); err != nil {
		t.Fatal(err)
	}
	jsonData, err := os.ReadFile(filepath.Join(ws, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Final  string `json:"final"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(jsonData, &record); err != nil {
		t.Fatal(err)
	}
	if record.Final != final || record.Status != "paused" {
		t.Fatalf("persisted final=%q status=%q", record.Final, record.Status)
	}
	markdown, err := os.ReadFile(filepath.Join(ws, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(markdown), "Final assessment\n\nConfirmed response\n") || !strings.Contains(string(markdown), "&lt;script&gt;") || strings.Contains(string(markdown), "\x1b") {
		t.Fatalf("unsafe or missing final assessment: %q", markdown)
	}
}

func TestReportWriterBoundsFinalAssessment(t *testing.T) {
	w := newReportWriter(openStore(t), t.TempDir(), "goal", "scope", "auto")
	w.SetFinal(strings.Repeat("x", 65537))
	if len([]rune(w.final)) > 65600 || !strings.HasSuffix(w.final, "[final assessment truncated]") {
		t.Fatalf("final assessment length=%d suffix=%q", len([]rune(w.final)), w.final[len(w.final)-40:])
	}
}

func TestReportWriterRejectsUnsafeSavedReport(t *testing.T) {
	for _, fixture := range []string{"symlink", "oversized", "malformed"} {
		t.Run(fixture, func(t *testing.T) {
			wsDir := t.TempDir()
			path := filepath.Join(wsDir, "report.json")
			switch fixture {
			case "symlink":
				target := filepath.Join(t.TempDir(), "target.json")
				if err := os.WriteFile(target, []byte(`{"final":"untrusted"}`), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				f, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate((16 << 20) + 1); err != nil {
					t.Fatal(err)
				}
				f.Close()
			case "malformed":
				if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			w := newReportWriter(openStore(t), wsDir, "goal", "scope", "auto")
			if err := w.RestoreFinal(); err == nil {
				t.Fatal("unsafe report was accepted")
			}
		})
	}
}

func TestReportWriterRestoresFinalFromLargeGeneratedReport(t *testing.T) {
	dir := t.TempDir()
	w := newReportWriter(openStore(t), dir, "goal", "scope", "auto")
	w.SetFinal("prior assessment")
	quote := strings.Repeat("x", 4000)
	evidence := make([]string, 4300)
	for i := range evidence {
		evidence[i] = quote
	}
	large := engreport.Model{Final: w.final, Evidence: map[string][]string{"t1": evidence}}
	data, err := engreport.RenderJSON(large)
	if err != nil || len(data) <= 16<<20 {
		t.Fatalf("generated report size=%d err=%v", len(data), err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	reopened := newReportWriter(openStore(t), dir, "goal", "scope", "auto")
	if err := reopened.RestoreFinal(); err != nil || reopened.final != "prior assessment" {
		t.Fatalf("restored final=%q err=%v", reopened.final, err)
	}
}

func TestReportWriterRefreshesOnEvidenceWithoutTaskUpdate(t *testing.T) {
	ws := t.TempDir()
	st := openStore(t)
	if _, err := st.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Status: engagement.StatusActive}}, Kind: "init"}); err != nil {
		t.Fatal(err)
	}
	w := newReportWriter(st, ws, "goal", "scope", "auto")
	if err := w.Flush("in-progress"); err != nil {
		t.Fatal(err)
	}
	stop := w.Start()
	defer stop()
	if _, err := st.RecordEvidence("t1", "fresh-evidence-marker"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(filepath.Join(ws, "report.md"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "fresh-evidence-marker") {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("evidence-only write did not refresh the live report")
}

func TestReportWriterResumeRegenerates(t *testing.T) {
	ws := t.TempDir()
	st := openStore(t)
	if _, err := st.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Status: engagement.StatusDone}}, Kind: "init"}); err != nil {
		t.Fatal(err)
	}
	// Simulate resume: a fresh writer over the already-populated store.
	w := newReportWriter(st, ws, "g", "s", "auto")
	if err := w.Flush("complete"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(ws, "report.md"))
	if !strings.Contains(string(b), "t1") {
		t.Errorf("resumed report missing prior task t1")
	}
	if !strings.Contains(string(b), "Status: complete") {
		t.Errorf("resumed report missing complete status")
	}
}

func TestReportWriterStartFlushesOnCommit(t *testing.T) {
	ws := t.TempDir()
	st := openStore(t)
	w := newReportWriter(st, ws, "g", "s", "auto")
	stop := w.Start()
	if _, err := st.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Status: engagement.StatusTodo}}, Kind: "init"}); err != nil {
		t.Fatal(err)
	}
	stop() // unregisters the hook and waits for the debounce goroutine to drain
	// A final explicit flush captures the terminal state deterministically.
	if err := w.Flush("complete"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(ws, "report.md"))
	if !strings.Contains(string(b), "t1") {
		t.Errorf("report after Start+commit missing task t1")
	}
}

func TestReportWriterIncludesExactWebOperationRecords(t *testing.T) {
	st := openStore(t)
	if _, e := st.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Status: engagement.StatusTodo}}, Kind: "init"}); e != nil {
		t.Fatal(e)
	}
	op := webanalysis.Operation{ID: webanalysis.ID("report-op"), Origin: "https://fixture.test", Path: "/api/profile", Method: "GET", Protocol: "http", Validation: "access-response", Parameters: []webanalysis.Parameter{{Name: "token", Field: "header.Authorization", Expression: "operation-credential"}}}
	if e := st.PutWeb(context.Background(), "operation", op.ID, "t1", op); e != nil {
		t.Fatal(e)
	}
	coverage := webanalysis.Coverage{ID: webanalysis.ID("report-coverage"), Role: "reader", Targets: []string{"https://fixture.test"}, Routes: []string{"https://fixture.test/profile"}, Interactions: []string{"click:#profile"}, Downloaded: []string{"fixture-artifact"}, Stages: []string{"fixture-analysis"}}
	if e := st.PutWeb(context.Background(), "coverage", coverage.ID, "t1", coverage); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	w := newReportWriter(st, dir, "goal", "scope", "auto")
	if e := w.Flush("complete"); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"report.json", "report.md"} {
		b, e := os.ReadFile(filepath.Join(dir, name))
		click := "click:#profile"
		if name == "report.md" {
			click = "click:\\#profile"
		}
		if e != nil || !strings.Contains(string(b), "/api/profile") || !strings.Contains(string(b), "operation-credential") || !strings.Contains(string(b), "https://fixture.test/profile") || !strings.Contains(string(b), click) || !strings.Contains(string(b), "fixture-artifact") || !strings.Contains(string(b), "fixture-analysis") {
			t.Fatal(name, string(b), e)
		}
	}
}

func TestReportIncludesPersistedFindingReview(t *testing.T) {
	store := openStore(t)
	if _, err := store.Apply(engagement.Delta{Upserts: []engagement.Task{
		{ID: "fixture", Kind: "web", Target: "fixture.invalid", Status: engagement.StatusTodo},
	}, Kind: "seed"}); err != nil {
		t.Fatal(err)
	}
	evidence, err := store.RecordEvidence("fixture", "fixture observation")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.SaveFinding(context.Background(), engagement.Finding{
		TaskID: "fixture", Surface: engagement.SurfaceWeb, Asset: "fixture.invalid",
		Title: "Reviewed fixture finding", Status: engagement.FindingValidated,
		Severity: "high", Impact: "verified fixture impact", EvidenceIDs: []int64{evidence},
	})
	if err != nil {
		t.Fatal(err)
	}
	writer := newReportWriter(store, t.TempDir(), "fixture", "fixture", "safe")
	model, err := writer.buildModel("complete")
	if err != nil {
		t.Fatal(err)
	}
	data, err := engreport.RenderJSON(model)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Findings []engagement.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if len(record.Findings) != 1 || record.Findings[0].Status != engagement.FindingValidated {
		t.Fatalf("review missing from JSON: %s", data)
	}
	markdown := engreport.RenderMarkdown(model)
	if !strings.Contains(markdown, "Reviewed fixture finding") || !strings.Contains(markdown, "validated") {
		t.Fatalf("review missing from Markdown: %s", markdown)
	}
}
