package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/engreport"
	"blkchain/cli/internal/histstore"
)

// newTestStore opens an isolated histstore.Store on a temp db for package-main
// tests (the store's own tests live in the histstore package).
func newTestStore(t *testing.T) *histstore.Store {
	t.Helper()
	s, err := histstore.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatalf("histstore.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// Slice 2 seam: summarizeEngageReport (pure) and ingestEngageReport (reads a
// report.json and stores the summary as one AI turn). The independent source of
// truth is a hand-built engreport.Model, not the renderer.

func sampleReportModel() engreport.Model {
	return engreport.Model{
		Goal:   "escalate to root on the target host",
		Status: "in-progress",
		Engagement: engagement.Engagement{
			Name: "host-42",
			Tasks: []engagement.Task{
				{ID: "t1", Kind: "local", Status: engagement.StatusDone, Objective: "enumerate SUID binaries"},
				{ID: "t2", Kind: "target-analysis", Status: engagement.StatusTodo, Objective: "assess /usr/bin/foo as a vector"},
			},
		},
	}
}

func TestSummarizeEngageReportCarriesGoalStatusAndTasks(t *testing.T) {
	out := summarizeEngageReport(sampleReportModel())

	for _, want := range []string{
		"escalate to root on the target host", // goal
		"in-progress",                         // status
		"Tasks (2)",                           // count
		"enumerate SUID binaries",             // task 1 objective
		"assess /usr/bin/foo as a vector",     // task 2 objective
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q\n--- summary ---\n%s", want, out)
		}
	}
}

func TestIngestEngageReportStoresSummaryTurn(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Write a report.json the way the reportWriter does (RenderJSON), so the
	// ingest path is exercised against the real on-disk format.
	js, err := engreport.RenderJSON(sampleReportModel())
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, js, 0o600); err != nil {
		t.Fatalf("write report.json: %v", err)
	}

	if err := ingestEngageReport(ctx, s, "sess-eng", path); err != nil {
		t.Fatalf("ingestEngageReport: %v", err)
	}

	msgs, err := s.Messages(ctx, "sess-eng")
	if err != nil {
		t.Fatalf("messages: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("want 1 stored turn, got %d", len(msgs))
	}
	if msgs[0].Role != histstore.RoleAI {
		t.Errorf("stored role = %q, want %q", msgs[0].Role, histstore.RoleAI)
	}
	if !strings.Contains(msgs[0].Content, "escalate to root on the target host") {
		t.Errorf("stored summary missing goal: %q", msgs[0].Content)
	}
}

func TestIngestEngageReportMissingFileErrors(t *testing.T) {
	s := newTestStore(t)
	err := ingestEngageReport(context.Background(), s, "sess", filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("want error for missing report.json, got nil")
	}
}

// Cycle 3f seam: ingestEngageRun folds a finished engagement's report.json into
// the default history store under a stable per-workspace id, so /history lists it.
func TestIngestEngageRunAddsSessionToDefaultStore(t *testing.T) {
	isolateUserDirs(t) // point XDG_DATA_HOME at a temp dir so the default store is isolated

	wsDir := t.TempDir()
	js, err := engreport.RenderJSON(sampleReportModel())
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	_, jsonPath := reportPaths(wsDir)
	if err := os.WriteFile(jsonPath, js, 0o600); err != nil {
		t.Fatalf("write report.json: %v", err)
	}

	if err := ingestEngageRun(wsDir); err != nil {
		t.Fatalf("ingestEngageRun: %v", err)
	}

	store := histstore.OpenDefault()
	if store == nil {
		t.Fatal("default store should open")
	}
	defer store.Close()
	id := engageHistorySessionID(wsDir)
	msgs, err := store.Messages(context.Background(), id)
	if err != nil {
		t.Fatalf("messages: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("want 1 stored turn under %q, got %d", id, len(msgs))
	}
}
