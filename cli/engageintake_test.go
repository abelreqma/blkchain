package main

import (
	"strings"
	"testing"
)

func TestAssembleEngageGoalCombinesAnswers(t *testing.T) {
	got := assembleEngageGoal(engageIntakeAnswers{
		GoalPrefill: "find a way in",
		Domain:      "web",
		Target:      "https://app.test",
		Interactive: true,
	})
	for _, want := range []string{"find a way in", "web domain", "Target: https://app.test", "interactive", "payloads"} {
		if !strings.Contains(got, want) {
			t.Errorf("goal missing %q:\n%s", want, got)
		}
	}
}

func TestAssembleEngageGoalMinimal(t *testing.T) {
	// No prefill, agent-decides domain, no target, non-interactive.
	got := assembleEngageGoal(engageIntakeAnswers{Interactive: false})
	if got == "" {
		t.Fatal("goal should never be empty")
	}
	if strings.Contains(got, "Focus on the  domain") {
		t.Errorf("empty domain must not produce a blank focus clause: %q", got)
	}
	if !strings.Contains(got, "Plan and enumerate only") {
		t.Errorf("non-interactive should say plan-only: %q", got)
	}
}

func TestEngageIntakeClarificationsAreWellFormed(t *testing.T) {
	for _, c := range []Clarification{domainClarification(), targetClarification(), interactiveClarification()} {
		if strings.TrimSpace(c.Question) == "" {
			t.Errorf("clarification has no question: %+v", c)
		}
		if len(c.Options) == 0 {
			t.Errorf("clarification %q has no options", c.Question)
		}
	}
	if domainClarification().Options[0].Value != "recon" {
		t.Errorf("first domain option should be recon")
	}
}
