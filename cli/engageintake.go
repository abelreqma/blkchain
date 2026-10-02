package main

import "strings"

// engageintake.go is the guided pre-dispatch intake for `/engage`: instead of
// erroring on a bare goal or blindly dispatching a vague one, the TUI asks a
// short sequence of key-driven clarify overlays (domain, target, interactive)
// and assembles the answers into the engagement goal. This file holds the
// content (the Clarifications) and the pure goal assembler; the overlay
// sequencing lives in the TUI (engage dispatch + clarifyResolvedMsg handler).

// engageIntakeDomains are the selectable domains, aligned to the engage
// executors. An empty Value means "let the agent decide".
var engageIntakeDomains = []ClarifyOption{
	{Label: "recon / enumeration", Value: "recon"},
	{Label: "web application", Value: "web"},
	{Label: "Active Directory", Value: "ad"},
	{Label: "cloud", Value: "cloud"},
	{Label: "kubernetes / containers", Value: "k8s"},
	{Label: "Linux privilege escalation", Value: "local"},
	{Label: "Windows privilege escalation", Value: "windows"},
	{Label: "wireless / RF", Value: "wifi"},
	{Label: "binary exploitation", Value: "exploit-dev"},
	{Label: "let the agent decide", Value: ""},
}

func domainClarification() Clarification {
	return Clarification{
		Question:    "Which domain should this engagement focus on?",
		Detail:      "Picks the specialized executor; choose a custom instruction if none fit.",
		Options:     engageIntakeDomains,
		AllowCustom: true,
	}
}

func targetClarification() Clarification {
	return Clarification{
		Question:    "Is there a specific target or scope?",
		Detail:      "Choose, then type the target (host, URL, CIDR) if yes.",
		Options:     []ClarifyOption{{Label: "yes - I'll type the target", Value: "yes"}, {Label: "no - derive it from the goal", Value: "no"}},
		AllowCustom: true,
	}
}

func interactiveClarification() Clarification {
	return Clarification{
		Question: "Is this an interactive session?",
		Detail:   "Interactive lets me suggest concrete, ready-to-use payloads to run.",
		Options:  []ClarifyOption{{Label: "yes - interactive (suggest payloads)", Value: "yes"}, {Label: "no - plan and enumerate only", Value: "no"}},
	}
}

// engageIntakeAnswers are the collected intake responses. GoalPrefill is any
// text the operator typed after /engage; Domain/Target are option Values or
// custom text; Interactive is the yes/no answer.
type engageIntakeAnswers struct {
	GoalPrefill string
	Domain      string
	Target      string
	Interactive bool
}

// assembleEngageGoal turns the intake answers into one engagement goal string
// for the orchestrator. It is pure and order-stable so it can be unit tested.
func assembleEngageGoal(a engageIntakeAnswers) string {
	var parts []string
	if g := strings.TrimSpace(a.GoalPrefill); g != "" {
		parts = append(parts, g)
	}
	if d := strings.TrimSpace(a.Domain); d != "" {
		parts = append(parts, "Focus on the "+d+" domain.")
	}
	if t := strings.TrimSpace(a.Target); t != "" {
		parts = append(parts, "Target: "+t+".")
	}
	if a.Interactive {
		parts = append(parts, "This is an interactive session: suggest concrete, ready-to-use payloads to run.")
	} else {
		parts = append(parts, "Plan and enumerate only.")
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}
