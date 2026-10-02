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

func TestEngageIntakeFlowRecordsAndAssembles(t *testing.T) {
	f := &engageIntakeFlow{answers: engageIntakeAnswers{GoalPrefill: "get in"}, reply: make(chan ClarifyResult, 1)}
	if _, ok := f.clarification(); !ok {
		t.Fatal("step 0 should have a clarification")
	}
	f.record(ClarifyResult{Value: "web"})       // domain
	f.record(ClarifyResult{Custom: "10.0.0.5"}) // target typed
	f.record(ClarifyResult{Value: "yes"})       // interactive
	if !f.done() {
		t.Fatal("after 3 records the flow should be done")
	}
	if _, ok := f.clarification(); ok {
		t.Fatal("a done flow has no clarification")
	}
	g := f.goal()
	for _, want := range []string{"get in", "web domain", "Target: 10.0.0.5", "interactive"} {
		if !strings.Contains(g, want) {
			t.Errorf("assembled goal missing %q: %s", want, g)
		}
	}
}

func TestStartEngageIntakeOpensDomainOverlay(t *testing.T) {
	m := newTestModel(t)
	nm, _ := m.startEngageIntake("offsec", "")
	mm := nm.(model)
	if mm.engageIntake == nil || mm.engageIntake.answers.GoalPrefill != "offsec" {
		t.Fatalf("startEngageIntake should set the flow with the prefill, got %+v", mm.engageIntake)
	}
	if _, ok := mm.overlay.(clarifyPicker); !ok {
		t.Fatalf("intake should open a clarify overlay, got %T", mm.overlay)
	}
}

func TestAdvanceEngageIntakeStepsAndCancel(t *testing.T) {
	m := newTestModel(t)
	nm, _ := m.startEngageIntake("", "")
	m = nm.(model)
	nm, _ = m.advanceEngageIntake(ClarifyResult{Value: "ad"})
	m = nm.(model)
	if m.engageIntake == nil || m.engageIntake.step != 1 || m.engageIntake.answers.Domain != "ad" {
		t.Fatalf("after domain answer: %+v", m.engageIntake)
	}
	if _, ok := m.overlay.(clarifyPicker); !ok {
		t.Fatal("the target overlay should be open next")
	}
	nm, _ = m.advanceEngageIntake(ClarifyResult{Canceled: true})
	m = nm.(model)
	if m.engageIntake != nil {
		t.Fatal("cancel should clear the intake flow")
	}
	if m.overlay != nil {
		t.Fatal("cancel should close the overlay")
	}
}

func TestClarifyResolvedRoutesToIntake(t *testing.T) {
	m := newTestModel(t)
	nm, _ := m.startEngageIntake("x", "")
	m = nm.(model)
	f := m.engageIntake
	nm, _ = m.Update(clarifyResolvedMsg{reply: f.reply, res: ClarifyResult{Value: "cloud"}})
	m = nm.(model)
	if m.engageIntake == nil || m.engageIntake.answers.Domain != "cloud" || m.engageIntake.step != 1 {
		t.Fatalf("clarifyResolvedMsg on the intake reply should advance the flow, got %+v", m.engageIntake)
	}
}

func TestGoalHasTarget(t *testing.T) {
	has := []string{"enumerate 10.0.0.5", "scan 10.0.0.0/24", "attack https://app.test/login", "recon example.com", "hit app.internal.test"}
	no := []string{"offsec", "find a way in", "help me escalate", "version 1.2 check", ""}
	for _, g := range has {
		if !goalHasTarget(g) {
			t.Errorf("goalHasTarget(%q) = false, want true", g)
		}
	}
	for _, g := range no {
		if goalHasTarget(g) {
			t.Errorf("goalHasTarget(%q) = true, want false", g)
		}
	}
}
