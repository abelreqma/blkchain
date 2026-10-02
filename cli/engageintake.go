package main

import (
	"regexp"
	"strings"
)

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
		Detail:      "Type a target (host, URL, CIDR) with the custom row, or derive it from the goal.",
		Options:     []ClarifyOption{{Label: "no specific target - derive from the goal", Value: "none"}},
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

// engageIntakeFlow drives the pre-dispatch intake sequence for /engage. step
// indexes the questions (0 domain, 1 target, 2 interactive); reply marks the
// overlays so the TUI distinguishes an intake resolve from an engagement-time
// clarify. The flow is created at /engage and cleared when it dispatches or is
// canceled.
type engageIntakeFlow struct {
	answers engageIntakeAnswers
	step    int
	reply   chan ClarifyResult
}

const engageIntakeSteps = 3

// clarification returns the question for the current step, or ok=false when the
// sequence is complete.
func (f *engageIntakeFlow) clarification() (Clarification, bool) {
	switch f.step {
	case 0:
		return domainClarification(), true
	case 1:
		return targetClarification(), true
	case 2:
		return interactiveClarification(), true
	}
	return Clarification{}, false
}

// record applies one step's answer and advances. A custom instruction wins over
// a selected option value; the target's "none" value leaves the target empty.
func (f *engageIntakeFlow) record(res ClarifyResult) {
	switch f.step {
	case 0:
		if res.Custom != "" {
			f.answers.Domain = res.Custom
		} else {
			f.answers.Domain = res.Value
		}
	case 1:
		if res.Custom != "" {
			f.answers.Target = res.Custom
		}
	case 2:
		f.answers.Interactive = res.Value == "yes"
	}
	f.step++
}

// done reports whether every step has been answered.
func (f *engageIntakeFlow) done() bool { return f.step >= engageIntakeSteps }

// goal assembles the collected answers into the engagement goal.
func (f *engageIntakeFlow) goal() string { return assembleEngageGoal(f.answers) }

// targetTokenRe matches a concrete engagement target in a goal: an IPv4 address
// (optionally with a CIDR suffix), an http(s) URL, or a dotted hostname with an
// alphabetic TLD. It is the clarity signal for /engage: a goal naming a target
// is specific enough to dispatch; a goal without one runs the guided intake.
var targetTokenRe = regexp.MustCompile(`(?i)(?:\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b|https?://[^\s]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b)`)

// goalHasTarget reports whether the goal already names a concrete target.
func goalHasTarget(goal string) bool { return targetTokenRe.MatchString(goal) }
