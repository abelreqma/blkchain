package main

import (
	tea "github.com/charmbracelet/bubbletea"
	"strings"
	"testing"
)

func TestAnswerAgentSelectionUsesRegisteredChoices(t *testing.T) {
	for _, input := range []string{"", "auto", "general", "cloud", " API "} {
		choice, err := parseAnswerAgent(input)
		if err != nil {
			t.Fatalf("%q: %v", input, err)
		}
		if input == " API " && choice != "api" {
			t.Fatal("choice not normalized")
		}
	}
	for _, input := range []string{"not-an-agent", "cloud web", strings.Repeat("a", 65), "web\x1b[31m"} {
		if _, err := parseAnswerAgent(input); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
	if len(answerAgentNames()) != len(personas)+2 {
		t.Fatal("registered specialists missing")
	}
}

func TestAnswerAgentAutoAndExplicitDomain(t *testing.T) {
	for _, tc := range []struct{ choice, detected, want string }{{"", "web", "web"}, {"auto", "api", "api"}, {"cloud", "web", "cloud"}, {"general", "web", ""}} {
		got, err := answerAgentDomain(tc.choice, tc.detected)
		if err != nil || got != tc.want {
			t.Fatalf("%+v: %q, %v", tc, got, err)
		}
	}
}

func TestInteractiveAnswerAgentSelectionIsNativeAndValidated(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.mode = "agent"
	nm, _ := m.dispatchInput("/agent cloud")
	m = nm.(model)
	if m.answerAgent != "cloud" || m.mode != "rag" {
		t.Fatal("selection still uses Hermes")
	}
	nm, _ = m.dispatchInput("/agent not-an-agent")
	m = nm.(model)
	if m.answerAgent != "cloud" {
		t.Fatal("invalid choice changed selection")
	}
	m.working = true
	nm, _ = m.dispatchInput("/agent api")
	if nm.(model).answerAgent != "cloud" {
		t.Fatal("choice changed during a turn")
	}
	m.working = false
	nm, _ = m.dispatchInput("/agent auto")
	if nm.(model).answerAgent != "" {
		t.Fatal("auto did not reset the override")
	}
}

func TestAgentTabCompletesWithoutChangingSelection(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.setDraft("/agent cl")
	m = m.refreshPalette()
	nm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = nm.(model)
	if m.ta.Value() != "/agent cloud " || m.answerAgent != "" || m.working || cmd != nil {
		t.Fatalf("completion submitted or changed selection: %q", m.ta.Value())
	}
}

func TestClearPreservesSelectedAnswerAgent(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	if err := m.selectAnswerAgent("cloud"); err != nil {
		t.Fatal(err)
	}
	if err := m.resetConversation(); err != nil {
		t.Fatal(err)
	}
	if m.answerAgent != "cloud" {
		t.Fatal("new conversation lost its specialist setting")
	}
}

func TestAgentCompletionAndStatusUseDomainEmoji(t *testing.T) {
	useDeadServices(t)
	vizForceTier(t, plNerd)
	m := newKeyModel(t)
	items := m.argumentSuggestions("/agent cl")
	if len(items) != 1 || items[0].label != personaSymbols["cloud"]+" cloud" || items[0].value != "/agent cloud " {
		t.Fatalf("emoji missing or leaked into input: %+v", items)
	}
	if err := m.selectAnswerAgent("cloud"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.answerAgentStatus(), personaSymbols["cloud"]+" cloud") {
		t.Fatal("selected agent has no emoji")
	}
	for _, name := range answerAgentNames() {
		if answerAgentLabel(name) == name {
			t.Fatalf("no emoji for %s", name)
		}
	}
}

func TestAgentCompletionASCIIFallbackKeepsPlainNames(t *testing.T) {
	useDeadServices(t)
	vizForceTier(t, plASCII)
	m := newKeyModel(t)
	items := m.argumentSuggestions("/agent cl")
	if len(items) != 1 || items[0].label != "cloud" || items[0].value != "/agent cloud " {
		t.Fatalf("ASCII completion contains an emoji: %+v", items)
	}
}
