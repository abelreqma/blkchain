package main

import (
	"strings"
	"testing"
)

func TestCommandDraftFooterUsesRunRatherThanAsk(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.width, m.height = 80, 24
	m.setDraft("/copy ")
	if !strings.Contains(stripANSI(m.footer()), "run command") {
		t.Fatal("command footer says ask")
	}
}

func TestModelSettingScopeIsShownForSelectedRow(t *testing.T) {
	p := newModelsPanel(defaultPrefs(), "sample-model")
	updated, _ := p.Update(modelsDataMsg{data: modelsData{chat: []chatModel{{ID: "sample-model"}}}})
	p = updated.(modelsPanel)
	if !strings.Contains(stripANSI(p.View(80, 24)), "session") {
		t.Fatal("model selection scope not visible")
	}
	p.sel = len(p.rows()) - 1
	if !strings.Contains(stripANSI(p.View(80, 24)), "all blk commands") {
		t.Fatal("saved setting scope not visible")
	}
}

func TestNarrowReviewFootersKeepPrimaryActions(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.width, m.height = 40, 24
	for _, tc := range []struct {
		name    string
		overlay overlayModel
		words   []string
	}{
		{"context", contextPicker{}, []string{"preview", "remove", "close"}},
		{"queue", queuePicker{}, []string{"edit", "resume", "close"}},
		{"sources", sourcePicker{}, []string{"preview", "open", "close"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m.overlay = tc.overlay
			footer := stripANSI(m.footer())
			for _, word := range tc.words {
				if !strings.Contains(footer, word) {
					t.Fatalf("primary action %q hidden: %s", word, footer)
				}
			}
		})
	}
}
