package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/retrieval"
	"github.com/tmc/langchaingo/llms"
)

func TestAdviseLoopReturnsFinalAndCarriesPromptAndHistory(t *testing.T) {
	fake := &fakeModel{queue: []*llms.ContentResponse{textResp("ADVICE: run id")}}
	hist := []priorTurn{{Role: "human", Content: "earlier-Q-marker"}, {Role: "ai", Content: "earlier-A-marker"}}
	got, _, err := adviseLoop(context.Background(), fake, nil, kbTestCfg(), nil, "help me escalate on this box", AnswerOpts{History: hist})
	if err != nil {
		t.Fatal(err)
	}
	if got != "ADVICE: run id" {
		t.Fatalf("advice = %q, want the model's final text", got)
	}
	var all strings.Builder
	for _, mc := range fake.seen[0] {
		all.WriteString(msgText(mc))
	}
	s := all.String()
	for _, want := range []string{"advisory offensive-security", "never execute", "route_skill", "earlier-Q-marker", "earlier-A-marker", "help me escalate on this box"} {
		if !strings.Contains(s, want) {
			t.Errorf("first request missing %q", want)
		}
	}
}

func TestAdviseLoopStreamsFinalAnswer(t *testing.T) {
	fake := &fakeModel{queue: []*llms.ContentResponse{textResp("streamed advice")}}
	var streamed strings.Builder
	got, _, err := adviseLoop(context.Background(), fake, nil, kbTestCfg(), nil, "help me", AnswerOpts{
		Stream: func(b []byte) { streamed.Write(b) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "streamed advice" {
		t.Fatalf("returned %q", got)
	}
	if streamed.String() != "streamed advice" {
		t.Errorf("streamed %q, want the final answer (plain-text surfaces render only the stream)", streamed.String())
	}
}

func TestAdviseLoopFiresGenericPersonaCue(t *testing.T) {
	fake := &fakeModel{queue: []*llms.ContentResponse{textResp("x")}}
	var fired bool
	var domain string
	adviseLoop(context.Background(), fake, nil, kbTestCfg(), nil, "q", AnswerOpts{Persona: func(d string) { fired = true; domain = d }})
	if !fired {
		t.Error("advise did not fire the persona cue")
	}
	if domain != "" {
		t.Errorf("advise persona domain = %q, want generic (empty)", domain)
	}
}

func TestAdviseLoopAutoUsesQuestionSpecialist(t *testing.T) {
	fake := &fakeModel{queue: []*llms.ContentResponse{textResp("advice")}}
	var domain string
	_, _, err := adviseLoop(context.Background(), fake, nil, kbTestCfg(), nil, "How should I inspect AD CS templates?", AnswerOpts{
		Agent:   "auto",
		Persona: func(selected string) { domain = selected },
	})
	if err != nil || domain != "ad" {
		t.Fatalf("domain=%q err=%v", domain, err)
	}
}

func TestAdviseLoopKeepsTargetDetailsLocal(t *testing.T) {
	authorizeWebTest(t)
	old := webSearch
	calls := 0
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		calls++
		return nil, nil
	}
	t.Cleanup(func() { webSearch = old })
	fake := &fakeModel{queue: []*llms.ContentResponse{textResp("advice")}}
	_, _, err := adviseLoop(context.Background(), fake, nil, kbTestCfg(), nil, "How should I assess my host 10.0.0.7?", AnswerOpts{WebFirst: true})
	if err != nil || calls != 0 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestAdviseLoopRunsToolsThenAnswers(t *testing.T) {
	fake := &fakeModel{queue: []*llms.ContentResponse{
		callResp("c1", "route_skill", `{"domain":"linux"}`),
		textResp("final advice"),
	}}
	got, _, err := adviseLoop(context.Background(), fake, nil, kbTestCfg(), nil, "help me", AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "final advice" {
		t.Fatalf("advice = %q, want final answer after the tool round", got)
	}
	if fake.calls != 2 {
		t.Fatalf("model calls = %d, want 2 (tool round then answer)", fake.calls)
	}
	var last strings.Builder
	for _, mc := range fake.seen[1] {
		last.WriteString(msgText(mc))
	}
	if !strings.Contains(last.String(), "no skill") {
		t.Errorf("second request missing the route_skill tool result: %s", last.String())
	}
}
