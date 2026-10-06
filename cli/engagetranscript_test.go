package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEngageTerminalRejectsControlSequences(t *testing.T) {
	input := "ok\x1b[31m red\x1b[0m\x1b]52;c;c2VjcmV0\x07\nnext\r\x00"
	got := terminalSafe(input)
	if strings.ContainsAny(got, "\x1b\x07\r\x00") || !strings.Contains(got, "ok red\nnext") {
		t.Fatalf("unsafe or lost text: %q", got)
	}
}

func TestEngageTranscriptKeepsExactEvidenceAndSafeDisplay(t *testing.T) {
	for _, mode := range []string{"off", "important", "full"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			var out bytes.Buffer
			trace := newActionTranscript(dir, mode, "worker", 10, 65536, &out)
			raw := "password=private-value\x1b[31m\n" + strings.Repeat("line\n", 30)
			if err := trace.record(actionRecord{Command: "curl token=private-value", Stdout: raw, Status: "complete"}); err != nil {
				t.Fatal(err)
			}
			saved, err := os.ReadFile(filepath.Join(dir, "actions.jsonl"))
			if err != nil || !strings.Contains(string(saved), "private-value") || !strings.Contains(string(saved), `\u001b[31m`) {
				t.Fatalf("exact evidence missing: %q %v", saved, err)
			}
			if strings.Contains(out.String(), "private-value") || strings.Contains(out.String(), "\x1b") {
				t.Fatalf("unsafe terminal output: %q", out.String())
			}
			switch mode {
			case "off":
				if out.Len() != 0 {
					t.Fatalf("off displayed an action: %q", out.String())
				}
			case "important":
				if !strings.Contains(out.String(), "preview truncated") {
					t.Fatalf("important did not truncate preview: %q", out.String())
				}
			case "full":
				if strings.Contains(out.String(), "preview truncated") || strings.Count(out.String(), "line") != 30 {
					t.Fatalf("full omitted output: %q", out.String())
				}
			}
		})
	}
}

func TestEngageTranscriptCheckpointFailureStopsRecord(t *testing.T) {
	trace := newActionTranscript(t.TempDir(), "full", "worker", 10, 1024, nil)
	trace.onPersist = func() error { return errors.New("checkpoint write failed") }
	if err := trace.record(actionRecord{Status: "denied"}); err == nil || !strings.Contains(err.Error(), "checkpoint write failed") {
		t.Fatalf("checkpoint failure was hidden: %v", err)
	}
}

func TestEngageTranscriptRejectsDuplicateJSONFields(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "actions.jsonl"), []byte(`{"id":"a-000001","id":"a-000002"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	trace := newActionTranscript(dir, "off", "worker", 10, 1024, nil)
	if err := trace.restore(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate transcript key accepted: %v", err)
	}
}
