package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEngageCheckpointKeepsAuthorizedRoE(t *testing.T) {
	project, ws := t.TempDir(), t.TempDir()
	source := filepath.Join(project, "ROE.md")
	if err := os.WriteFile(source, []byte("## In Scope\n192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	want := engageCheckpoint{Goal: "inspect 192.0.2.1", ProjectDir: project, ScopeKind: "roe", Auto: true}
	if err := saveEngageCheckpoint(ws, want, source); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("## In Scope\n198.51.100.2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadEngageCheckpoint(ws)
	if err != nil || got.Goal != want.Goal || got.ProjectDir != want.ProjectDir || got.ScopeKind != want.ScopeKind || got.Auto != want.Auto || len(got.ScopeSHA256) != 64 {
		t.Fatalf("checkpoint=%+v err=%v", got, err)
	}
	data, err := os.ReadFile(filepath.Join(ws, "ROE.md"))
	if err != nil || !strings.Contains(string(data), "192.0.2.1") || strings.Contains(string(data), "198.51.100.2") {
		t.Fatalf("saved RoE=%q err=%v", data, err)
	}
}

func TestEngageCheckpointRejectsChangedScope(t *testing.T) {
	project, ws := t.TempDir(), t.TempDir()
	source := filepath.Join(project, "ROE.md")
	if err := os.WriteFile(source, []byte("## In Scope\n192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveEngageCheckpoint(ws, engageCheckpoint{Goal: "inspect", ProjectDir: project, ScopeKind: "roe"}, source); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "ROE.md"), []byte("## In Scope\n192.0.2.1\n198.51.100.2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadEngageCheckpoint(ws); err == nil || !strings.Contains(err.Error(), "differs from the saved authorization") {
		t.Fatalf("changed RoE accepted: %v", err)
	}
}

func TestEngageCheckpointRejectsInvalidOrDuplicate(t *testing.T) {
	ws := t.TempDir()
	if _, err := loadEngageCheckpoint(ws); err == nil {
		t.Fatal("missing checkpoint accepted")
	}
	if err := saveEngageCheckpoint(ws, engageCheckpoint{Goal: "test", ProjectDir: t.TempDir(), ScopeKind: "none", Auto: true}, ""); err == nil {
		t.Fatal("automatic run without scope accepted")
	}
	c := engageCheckpoint{Goal: "test", ProjectDir: t.TempDir(), ScopeKind: "none"}
	if err := saveEngageCheckpoint(ws, c, ""); err != nil {
		t.Fatal(err)
	}
	if err := saveEngageCheckpoint(ws, c, ""); err == nil {
		t.Fatal("duplicate run overwrote checkpoint")
	}
	if err := os.WriteFile(filepath.Join(ws, "checkpoint.json"), []byte(`{"goal":"test","project_dir":"/tmp","scope_kind":"none"}{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadEngageCheckpoint(ws); err == nil {
		t.Fatal("checkpoint with trailing data accepted")
	}
}

func TestEngageResumeNeedsCheckpointBeforeServices(t *testing.T) {
	err := runEngage([]string{"resume", "--workspace", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("resume error=%v", err)
	}
}

func TestEngageResumeAcceptsWorkspacePathWithSpaces(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "named engagement")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	err := runEngage([]string{"resume", workspace})
	if err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("resume error=%v", err)
	}
}
