package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var agentDisplayNames = map[string]string{
	"auto": "Auto", "general": "General", "ad": "Active Directory",
	"ai": "AI Security", "api": "API", "binexp": "Binary Exploitation",
	"cloud": "Cloud", "cve": "CVE Research", "k8s": "Kubernetes",
	"linux": "Linux", "mobile": "Mobile", "network": "Network",
	"recon": "Reconnaissance", "supply": "Supply Chain", "web": "Web",
	"windows": "Windows", "wireless": "Wireless",
}

func agentDisplayName(name string) string {
	if display := agentDisplayNames[name]; display != "" {
		return display
	}
	return name
}

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
	value = strings.Join(strings.Fields(value), " ")
	for name, display := range agentDisplayNames {
		if value == strings.ToLower(display) {
			value = name
			break
		}
	}
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
	display := agentDisplayName(name)
	if plCurrentTier() == plASCII {
		return display
	}
	icon := "🔀"
	if name != "auto" {
		domain := name
		if name == "general" {
			domain = ""
		}
		icon = personaSymbols[domain]
	}
	const iconColumn = 3
	return icon + strings.Repeat(" ", max(iconColumn-lipgloss.Width(icon), 1)) + display
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
	return "agent " + selected + "\nnative specialists:\n  " + strings.Join(names, "\n  ")
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
