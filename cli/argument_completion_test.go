package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestArgumentTabCompletesWithoutSubmitting(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.setDraft("/models lo")
	m = m.refreshPalette()
	if !m.pal.open {
		t.Fatal("argument choices missing")
	}
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = nm.(model)
	if m.ta.Value() != "/models load " || m.working || cmd != nil {
		t.Fatalf("Tab submitted or failed to complete: %q", m.ta.Value())
	}
}

func TestCitationCompletionUsesAvailableSources(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.openTargets = []openTarget{{Path: "notes.md", Section: "Configuration"}}
	m.setDraft("/open ")
	m = m.refreshPalette()
	if !m.pal.open {
		t.Fatal("source choice missing")
	}
	m = m.completeSelected()
	if m.ta.Value() != "/open 1 " {
		t.Fatalf("source completion: %q", m.ta.Value())
	}
}

func TestFileCompletionPreservesSpacesAndNeverReadsContents(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	dir := t.TempDir()
	name := filepath.Join(dir, "Review Notes.txt")
	if err := os.WriteFile(name, []byte("private contents"), 0600); err != nil {
		t.Fatal(err)
	}
	m.setDraft("/attach " + filepath.Join(dir, "Rev"))
	m = m.refreshPalette()
	if !m.pal.open {
		t.Fatal("file choice missing")
	}
	m = m.completeSelected()
	if strings.TrimSpace(m.ta.Value()) != "/attach "+name || len(m.attachments) != 0 {
		t.Fatalf("completion consumed the file or lost spaces: %q", m.ta.Value())
	}
}

func TestFileCompletionShowsBasenameInNarrowPalette(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.width, m.height = 40, 24
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Review Notes.txt"), []byte("notes"), 0600); err != nil {
		t.Fatal(err)
	}
	m.setDraft("/attach " + filepath.Join(dir, "Rev"))
	m = m.refreshPalette()
	if !strings.Contains(stripANSI(m.paletteView(40, 10)), "Review Notes.txt") {
		t.Fatal("completion hides the distinguishing filename")
	}
}

func TestCompletionContinuesIntoModelNamesAfterAction(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.completionModels = []string{"sample-model"}
	m.setDraft("/models lo")
	m = m.refreshPalette()
	m = m.completeSelected()
	if m.ta.Value() != "/models load " || !m.pal.open {
		t.Fatal("completion stopped before model choices")
	}
	found := false
	for _, item := range m.pal.items {
		found = found || item.value == "/models load sample-model "
		if item.value == "/models load load " {
			t.Fatal("completion repeated the action")
		}
	}
	if !found {
		t.Fatal("model name missing after action completion")
	}
}

func TestCompletionPreservesContextPathAndValidatesAction(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	dir := t.TempDir()
	name := filepath.Join(dir, "Review Notes.txt")
	if err := os.WriteFile(name, []byte("notes"), 0600); err != nil {
		t.Fatal(err)
	}
	items := m.argumentSuggestions("/context add " + filepath.Join(dir, "Review N"))
	if len(items) != 1 || strings.TrimSpace(items[0].value) != "/context add "+name {
		t.Fatalf("path completion lost spaces: %+v", items)
	}
	m.completionModels = []string{"sample-model"}
	if got := m.argumentSuggestions("/models typo s"); len(got) != 0 {
		t.Fatalf("invalid action received models: %+v", got)
	}
}

func TestTranscriptCompletionFillsWithoutChangingMode(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.setDraft("/transcript f")
	m = m.refreshPalette()
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = nm.(model)
	if m.ta.Value() != "/transcript full " || m.engageTranscript != "important" || m.working || cmd != nil {
		t.Fatalf("completion submitted or changed transcript mode: draft=%q mode=%q", m.ta.Value(), m.engageTranscript)
	}
}

func TestCompletedSingleArgumentsStopSuggesting(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	for _, draft := range []string{"/help model ", "/logs embed_server ", "/history clear ", "/transcript full ", "/viz off "} {
		if got := m.argumentSuggestions(draft); len(got) != 0 {
			t.Errorf("%q suggests an extra argument: %+v", draft, got)
		}
	}
}
