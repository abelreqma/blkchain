package main

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenPickerPreviewsSourceWithoutExecutingIt(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.width, m.height = 80, 24
	p := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(p, []byte("source evidence excerpt"), 0600); err != nil {
		t.Fatal(err)
	}
	m.openTargets = []openTarget{{Path: p, Section: "Configuration"}}
	nm, _ := m.dispatchInput("/open")
	m = nm.(model)
	if m.overlay == nil {
		t.Fatal("source picker missing")
	}
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("p")})
	m = nm.(model)
	if !strings.Contains(stripANSI(m.View()), "source evidence excerpt") {
		t.Fatal("preview missing")
	}
}

func TestSourcePickerOpensItsDisplayedSnapshot(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.openTargets = []openTarget{{Path: "https://example.org/source-a"}}
	nm, _ := m.dispatchInput("/open")
	m = nm.(model)
	m.openTargets = []openTarget{{Path: "https://example.org/source-b"}}
	nm, selectCmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	_, openCmd := nm.(model).Update(selectCmd())
	if got := fmt.Sprint(openCmd()); !strings.Contains(got, "source-a") || strings.Contains(got, "source-b") {
		t.Fatalf("opened a different source: %s", got)
	}
}
