package main

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

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
	for _, want := range []string{"offensive-security", "user-named target", "route_skill", "earlier-Q-marker", "earlier-A-marker", "help me escalate on this box"} {
		if !strings.Contains(s, want) {
			t.Errorf("first request missing %q", want)
		}
	}
}

func TestAdviseLoopRunsNamedTargetCommand(t *testing.T) {
	old := execRunner
	calls := 0
	execRunner = func(context.Context, string, []string, string, int, time.Duration) runResult {
		calls++
		return runResult{Output: "fixture response"}
	}
	t.Cleanup(func() { execRunner = old })
	fake := &fakeModel{queue: []*llms.ContentResponse{
		callResp("c1", "run_command", `{"binary":"curl","args":["-I","http://192.0.2.5/"]}`),
		textResp("The request completed."),
	}}
	var stages []string
	got, _, err := adviseLoop(context.Background(), fake, nil, kbTestCfg(), nil, "Check 192.0.2.5 now", AnswerOpts{Stage: func(stage string) { stages = append(stages, stage) }})
	if err != nil || calls != 1 || got != "The request completed." {
		t.Fatalf("answer=%q calls=%d err=%v", got, calls, err)
	}
	if !slices.Contains(stages, "tool run_command") || !slices.Contains(stages, "tool result: run_command") {
		t.Fatalf("tool activity was hidden: %v", stages)
	}
	if !strings.Contains(msgText(fake.seen[1][len(fake.seen[1])-1]), "fixture response") {
		t.Fatal("command result did not reach the next model round")
	}
}

func TestAdviseLoopRetriesAnExplicitActionUntilARealToolRuns(t *testing.T) {
	old := execRunner
	calls := 0
	execRunner = func(context.Context, string, []string, string, int, time.Duration) runResult {
		calls++
		return runResult{Output: "observed response"}
	}
	t.Cleanup(func() { execRunner = old })
	fake := &fakeModel{queue: []*llms.ContentResponse{
		textResp("I checked it."),
		callResp("c1", "run_command", `{"binary":"curl","args":["-I","http://192.0.2.5/"]}`),
		textResp("Observed the response."),
	}}
	answer, _, err := adviseLoop(context.Background(), fake, nil, kbTestCfg(), nil, "Scan 192.0.2.5", AnswerOpts{requiredAction: "target action"})
	if err != nil || calls != 1 || fake.calls != 3 || answer != "Observed the response." {
		t.Fatalf("answer=%q calls=%d modelCalls=%d err=%v", answer, calls, fake.calls, err)
	}
}

func TestAdviseLoopRejectsAnUnperformedExplicitAction(t *testing.T) {
	fake := &fakeModel{queue: []*llms.ContentResponse{textResp("I scanned it."), textResp("I scanned it again.")}}
	answer, _, err := adviseLoop(context.Background(), fake, nil, kbTestCfg(), nil, "Scan 192.0.2.5", AnswerOpts{requiredAction: "target action"})
	if err == nil || !strings.Contains(err.Error(), "no target action tool") || answer != "" {
		t.Fatalf("unperformed action accepted: answer=%q err=%v", answer, err)
	}
}

func TestAdviseLoopReturnsWebEvidenceInsteadOfUnsupportedSummary(t *testing.T) {
	authorizeWebTest(t)
	old := webSearch
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		return []retrieval.Result{chunk(webSource, "https://owasp.org/current", "Current", "fixture source evidence")}, nil
	}
	t.Cleanup(func() { webSearch = old })
	fake := &fakeModel{queue: []*llms.ContentResponse{
		callResp("c1", "web_search", `{"query":"current OWASP guidance"}`),
		textResp("Unsupported stale claim"),
	}}
	answer, _, err := adviseLoop(context.Background(), fake, nil, kbTestCfg(), nil,
		"Search public OWASP guidance", AnswerOpts{requiredAction: "web_search"})
	if err != nil || !strings.Contains(answer, "fixture source evidence") || strings.Contains(answer, "Unsupported stale claim") {
		t.Fatalf("web result was replaced by unsupported model text: answer=%q err=%v", answer, err)
	}
}

func TestClassifyChatActionDistinguishesRequestsFromContext(t *testing.T) {
	for _, tc := range []struct {
		question string
		reply    string
		target   bool
		want     string
	}{
		{"Read go.mod", "FILE", false, "file_read"},
		{"Find files containing my function", "FILE_SEARCH", false, "file_search"},
		{"Create notes.txt in the workspace", "FILE_WRITE", false, "file_write"},
		{"Replace the old line in notes.txt", "FILE_PATCH", false, "file_patch"},
		{"Run a build in the workspace", "TERMINAL", false, "terminal"},
		{"Run a scan of 192.0.2.5", "TERMINAL", true, "target action"},
		{"Would you mind telling me what https://example.com/ serves?", "TARGET", true, "target action"},
		{"I'd like you to inspect 192.0.2.5", "TARGET", true, "target action"},
		{"Use your knowledge base to answer", "KB_SEARCH", false, "kb_search"},
		{"Search the live web for current guidance", "WEB_SEARCH", false, "web_search"},
		{"Find a relevant skill", "ROUTE_SKILL", false, "route_skill"},
		{"Use the configured MCP server to list records", "MCP", false, "mcp"},
		{"Explain the format of go.mod", "ADVICE", false, ""},
		{"Plan an assessment of example.com without contacting it", "ADVICE", true, ""},
	} {
		fake := &fakeModel{queue: []*llms.ContentResponse{textResp(tc.reply)}}
		got, err := classifyChatAction(context.Background(), fake, tc.question, tc.target)
		if err != nil || got != tc.want {
			t.Errorf("classifyChatAction(%q)=%q, err=%v, want %q", tc.question, got, err, tc.want)
		}
	}
}

func TestClassifyChatActionRejectsInvalidVerdict(t *testing.T) {
	fake := &fakeModel{queue: []*llms.ContentResponse{textResp("TARGET")}}
	if _, err := classifyChatAction(context.Background(), fake, "Inspect the target", false); err == nil {
		t.Fatal("classifier accepted a target action without a user-named target")
	}
	fake = &fakeModel{queue: []*llms.ContentResponse{textResp("Maybe")}}
	if _, err := classifyChatAction(context.Background(), fake, "Read go.mod", false); err == nil {
		t.Fatal("classifier accepted an ambiguous verdict")
	}
	fake = &fakeModel{queue: []*llms.ContentResponse{textResp("WEB_SEARCH")}}
	if _, err := classifyChatAction(context.Background(), fake, "Search for my host 10.0.0.7", true); err == nil {
		t.Fatal("classifier allowed target details in a public search")
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
