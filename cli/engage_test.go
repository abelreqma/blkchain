package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

func TestEngageGeneralQuestionSkipsRetrieval(t *testing.T) {
	rs := &recSearcher{}
	m := &fakeModel{queue: []*llms.ContentResponse{textResp("17 * 3 is 51.")}}
	got, err := runEngageTurn(context.Background(), m, rs, kbTestCfg(), modelPrefs{Web: true}, "what is 17 * 3?")
	if err != nil {
		t.Fatal(err)
	}
	if got != "17 * 3 is 51." {
		t.Errorf("got %q", got)
	}
	if rs.query != "" {
		t.Errorf("searcher must not be called, got query %q", rs.query)
	}
}

func TestEngageSendsRoutingPromptAndQuestion(t *testing.T) {
	m := &fakeModel{queue: []*llms.ContentResponse{textResp("ok")}}
	if _, err := runEngageTurn(context.Background(), m, &recSearcher{}, kbTestCfg(), modelPrefs{}, "hello there"); err != nil {
		t.Fatal(err)
	}
	msgs := m.seen[0]
	if len(msgs) != 2 || msgs[0].Role != llms.ChatMessageTypeSystem || msgs[1].Role != llms.ChatMessageTypeHuman {
		t.Fatalf("unexpected message roles: %+v", msgs)
	}
	sys, _ := msgs[0].Parts[0].(llms.TextContent)
	if sys.Text != routingSystemPrompt {
		t.Error("first message is not the routing system prompt")
	}
	q, _ := msgs[1].Parts[0].(llms.TextContent)
	if q.Text != "hello there" {
		t.Errorf("question = %q", q.Text)
	}
	for _, r := range routingSystemPrompt {
		if r > 127 {
			t.Fatalf("routing prompt has non-ASCII rune %q", r)
		}
	}
}

func TestEngageCorpusQuestionUsesKBSearch(t *testing.T) {
	rs := &recSearcher{results: []retrieval.Result{
		chunk("wstg", "ssrf/intro.md", "Overview", "Block 169.254.169.254 at the egress proxy."),
	}}
	m := &fakeModel{queue: []*llms.ContentResponse{
		callResp("c1", "kb_search", `{"query":"ssrf metadata"}`),
		textResp("Block the metadata IP (wstg ssrf/intro.md)."),
	}}
	got, err := runEngageTurn(context.Background(), m, rs, kbTestCfg(), modelPrefs{}, "how do I stop ssrf to metadata?")
	if err != nil {
		t.Fatal(err)
	}
	if rs.query != "ssrf metadata" {
		t.Errorf("searcher query = %q", rs.query)
	}
	if !strings.Contains(got, "metadata IP") {
		t.Errorf("final = %q", got)
	}
	// The retrieved snippet must have been fed back to the model.
	var toolText string
	for _, msg := range m.seen[1] {
		for _, p := range msg.Parts {
			if tr, ok := p.(llms.ToolCallResponse); ok {
				toolText += tr.Content
			}
		}
	}
	if !strings.Contains(toolText, "169.254.169.254") {
		t.Errorf("tool result missing snippet: %q", toolText)
	}
}

func TestEngageAnswerHonorsWebSwitch(t *testing.T) {
	for _, web := range []bool{false, true} {
		old := kbAnswerFn
		var got AnswerOpts
		called := false
		kbAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, o AnswerOpts) (string, []citation, bool, []retrieval.Result, int, error) {
			got, called = o, true
			return "grounded", nil, false, nil, 1, nil
		}
		m := &fakeModel{queue: []*llms.ContentResponse{
			callResp("c1", "kb_answer", `{"question":"what is xss"}`),
			textResp("done"),
		}}
		_, err := runEngageTurn(context.Background(), m, &recSearcher{}, kbTestCfg(), modelPrefs{Web: web}, "what is xss")
		kbAnswerFn = old
		if err != nil {
			t.Fatal(err)
		}
		if !called {
			t.Fatalf("web=%v: kb_answer not called", web)
		}
		if got.NoWeb != !web {
			t.Errorf("web=%v: NoWeb = %v, want %v", web, got.NoWeb, !web)
		}
	}
}

func TestRoutingGuardShared(t *testing.T) {
	// The engage routing prompt and the ask-path guardrail agree that a CVE
	// question is a grounding question.
	if kind, forced := routeGuard("CVE-2024-1234"); !forced || kind != routeGround {
		t.Error("routeGuard must force ground for a CVE question")
	}
	// The engage routing system prompt still instructs adaptive tool use.
	if !strings.Contains(routingSystemPrompt, "kb_search") {
		t.Error("routingSystemPrompt should reference kb_search")
	}
}
