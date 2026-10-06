package main

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAttachAcceptsURLReferencesWithoutOpeningPicker(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	nm, _ := m.dispatchInput("/attach https://example.test/notes?q=1")
	m = nm.(model)
	if m.overlay != nil || len(m.attachments) != 1 || m.attachments[0].path != "https://example.test/notes?q=1" {
		t.Fatalf("URL attachment was not stored: %+v", m.attachments)
	}
	preface := m.buildContextPreface()
	if !strings.Contains(preface, "URL reference") || strings.Contains(preface, "Attached file https") {
		t.Fatalf("URL reads as file content: %s", preface)
	}
}

func TestContextRemovesOnlySelectedPendingAttachment(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.attachments = []attachment{{path: "one.txt", content: "one"}, {path: "two.txt", content: "two"}}
	nm, _ := m.dispatchInput("/context remove 1")
	m = nm.(model)
	if len(m.attachments) != 1 || m.attachments[0].path != "two.txt" {
		t.Fatalf("remove changed wrong entries: %+v", m.attachments)
	}
}

func TestAttachAcceptsBoundedFileArgument(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	p := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(p, []byte("review notes"), 0600); err != nil {
		t.Fatal(err)
	}
	nm, _ := m.dispatchInput("/attach " + p)
	m = nm.(model)
	if len(m.attachments) != 1 || !strings.Contains(m.buildContextPreface(), "review notes") {
		t.Fatal("file argument did not reach context")
	}
}

func TestContextURLDetectionRejectsUnsafeFormsAndBoundsResults(t *testing.T) {
	text := `See (https://example.test/a(b)). https://example.test/a(b) javascript:alert(1) https://user:pass@example.test/x https://second.test/x?q=1.`
	got := contextURLs(text)
	if len(got) != 2 || got[0] != "https://example.test/a(b)" || got[1] != "https://second.test/x?q=1" {
		t.Fatalf("URL recognition: %v", got)
	}
	got = contextURLs(strings.Repeat("https://example.test/ ", 100) + "https://last.test/")
	if len(got) > maxPendingItems {
		t.Fatal("URL results exceeded cap")
	}
}

func TestContextPickerPreviewsAndRemovesSelectedItem(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.width, m.height = 80, 24
	m.attachments = []attachment{{path: "notes.txt", content: "review excerpt"}}
	nm, _ := m.dispatchInput("/context")
	m = nm.(model)
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = nm.(model)
	if !strings.Contains(stripANSI(m.View()), "review excerpt") {
		t.Fatal("enter did not preview selected attachment")
	}
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = nm.(model)
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	m = nm.(model)
	if cmd == nil {
		t.Fatal("delete did not update pending context")
	}
	nm, _ = m.Update(cmd())
	m = nm.(model)
	if len(m.attachments) != 0 {
		t.Fatal("deleted item remained pending")
	}
}

func TestRejectedURLDoesNotEchoCredentials(t *testing.T) {
	m := model{}
	err := m.addPendingContext("https://user:private-marker@example.test/path")
	if err == nil || strings.Contains(err.Error(), "private-marker") || len(m.attachments) != 0 {
		t.Fatalf("credential URL was accepted or echoed: %v", err)
	}
}

func TestPendingContextLimitRejectsAnEntireURLBatch(t *testing.T) {
	m := model{}
	for i := 0; i < 15; i++ {
		if err := m.addPendingContext(fmt.Sprintf("https://example.test/%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	err := m.addPendingContext("https://example.test/a https://example.test/b")
	if err == nil || len(m.attachments) != 15 {
		t.Fatalf("over-limit batch was partly added: %d, %v", len(m.attachments), err)
	}
}

func TestContextSummaryKeepsCommandAndFilename(t *testing.T) {
	m := model{width: 40, height: 24, attachments: []attachment{{path: "/tmp/notes.txt", content: "notes"}}}
	text := stripANSI(m.contextSummary())
	if !strings.Contains(text, "/context") || !strings.Contains(text, "notes.txt") || !strings.Contains(text, "5") {
		t.Fatalf("pending summary hides the item: %s", text)
	}
}

func TestContextRejectsOversizedURLBatchWithoutClipping(t *testing.T) {
	m := model{}
	var urls []string
	for i := 0; i <= maxPendingItems; i++ {
		urls = append(urls, fmt.Sprintf("https://example.test/%d", i))
	}
	if err := m.addPendingContext(strings.Join(urls, " ")); err == nil || len(m.attachments) != 0 {
		t.Fatal("oversized batch was silently clipped")
	}
}

func TestContextKeepsExplicitURLPunctuationAndFindsLaterLinks(t *testing.T) {
	m := model{}
	link := "https://example.test/resource!"
	if err := m.addPendingContext(link); err != nil || m.attachments[0].path != link {
		t.Fatal("explicit URL punctuation changed")
	}
	links := contextURLs(strings.Repeat("https://example.test/ ", 100) + "https://last.test/")
	if len(links) != 2 || links[1] != "https://last.test/" {
		t.Fatal("duplicate URLs hid later links")
	}
}

func TestContextReviewDoesNotRestoreConsumedAttachmentsOrDraft(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.attachments = []attachment{{path: "one.txt", content: "one"}, {path: "two.txt", content: "two"}}
	m.setDraft("saved draft")
	nm, _ := m.dispatchInput("/context")
	m = nm.(model)
	m.attachments = nil
	m.setDraft("")
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	nm, _ = nm.(model).Update(cmd())
	m = nm.(model)
	if len(m.attachments) != 0 || m.ta.Value() != "" {
		t.Fatal("context review restored context already consumed by a turn")
	}
}
