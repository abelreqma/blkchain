package main

import (
	"fmt"
	"sort"
	"strings"
)

func answerAgentNames() []string {
	names := make([]string, 0, len(personas))
	for name := range personas {
		names = append(names, name)
	}
	sort.Strings(names)
	return append([]string{"auto", "general"}, names...)
}

func parseAnswerAgent(value string) (string, error) {
	if len(value) > 64 {
		return "", fmt.Errorf("agent: specialist name exceeds the limit")
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "auto" {
		return "", nil
	}
	if value == "general" {
		return value, nil
	}
	if _, ok := personas[value]; ok {
		return value, nil
	}
	return "", fmt.Errorf("agent: choose %s", strings.Join(answerAgentNames(), ", "))
}

func answerAgentDomain(choice, detected string) (string, error) {
	choice, err := parseAnswerAgent(choice)
	if err != nil {
		return "", err
	}
	if choice == "general" {
		return "", nil
	}
	if choice == "" {
		return detected, nil
	}
	return choice, nil
}

func answerAgentName(domain string) string {
	if domain == "" {
		return "general"
	}
	return domain
}

func answerAgentLabel(name string) string {
	if plCurrentTier() == plASCII {
		return name
	}
	icon := "\U0001f500"
	if name != "auto" {
		domain := name
		if name == "general" {
			domain = ""
		}
		icon = personaSymbols[domain]
	}
	return icon + " " + name
}

func (m model) answerAgentStatus() string {
	choice := m.answerAgent
	suffix := ""
	if choice == "" {
		choice, suffix = "auto", " (dynamic)"
	}
	names := answerAgentNames()
	for i, name := range names {
		names[i] = answerAgentLabel(name)
	}
	selected := answerAgentLabel(choice) + suffix
	if m.mode == "agent" {
		selected = "Hermes (default)"
		if plCurrentTier() != plASCII {
			selected = "\U0001f4ac " + selected
		}
	}
	return "agent " + selected + "\nnative specialists: " + strings.Join(names, ", ")
}

func (m *model) selectAnswerAgent(value string) error {
	choice, err := parseAnswerAgent(value)
	if err != nil {
		return err
	}
	if m.working {
		return fmt.Errorf("agent: cancel the current turn before changing specialists")
	}
	m.answerAgent, m.mode, m.persona = choice, "rag", ""
	return nil
}
