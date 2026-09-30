package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
)

func TestReportPaths(t *testing.T) {
	md, js := reportPaths("/ws")
	if md != filepath.Join("/ws", "report.md") || js != filepath.Join("/ws", "report.json") {
		t.Errorf("paths = %q %q", md, js)
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
