package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"blkchain/cli/internal/tooldef"

	"github.com/tmc/langchaingo/llms"
)

// fakeModel replays a scripted queue of responses. When the queue is empty it
// repeats the last response, so a "always calls a tool" model needs one entry.
type fakeModel struct {
	queue []*llms.ContentResponse
	// errs, when set, is the error for call i. A nil entry and a call past the
	// slice return the scripted response, so a model with no errs answers every
	// call.
	errs  []error
	calls int
	seen  [][]llms.MessageContent
}

func (f *fakeModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	f.seen = append(f.seen, append([]llms.MessageContent(nil), msgs...))
	call := f.calls
	f.calls++
	if call < len(f.errs) && f.errs[call] != nil {
		return nil, f.errs[call]
	}
	i := call
	if i >= len(f.queue) {
		i = len(f.queue) - 1
	}
	return f.queue[i], nil
}

type fakeTool struct {
	name string
	fn   func(args string) (string, error)
	ran  []string
}

func (t *fakeTool) Name() string           { return t.name }
func (t *fakeTool) Description() string    { return "fake " + t.name }
func (t *fakeTool) Schema() map[string]any { return map[string]any{"type": "object"} }
func (t *fakeTool) Call(_ context.Context, args string) (string, error) {
	t.ran = append(t.ran, args)
	return t.fn(args)
}

func textResp(s string) *llms.ContentResponse {
	return &llms.ContentResponse{Choices: []*llms.ContentChoice{{Content: s}}}
}

func callResp(id, name, args string) *llms.ContentResponse {
	return &llms.ContentResponse{Choices: []*llms.ContentChoice{{
		ToolCalls: []llms.ToolCall{{ID: id, Type: "function", FunctionCall: &llms.FunctionCall{Name: name, Arguments: args}}},
	}}}
}

func newLoopReg(t *testing.T, tools ...*fakeTool) *tooldef.Registry {
	t.Helper()
	reg := tooldef.NewRegistry()
	for _, tl := range tools {
		if err := reg.Register(tl); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

func userMsgs() []llms.MessageContent {
	return []llms.MessageContent{llms.TextParts(llms.ChatMessageTypeHuman, "hi")}
}

// toolResults returns the ToolCallResponse parts of the last request the model saw.
func toolResults(f *fakeModel) []llms.ToolCallResponse {
	var out []llms.ToolCallResponse
	last := f.seen[len(f.seen)-1]
	for _, m := range last {
		if m.Role != llms.ChatMessageTypeTool {
			continue
		}
		for _, p := range m.Parts {
			if r, ok := p.(llms.ToolCallResponse); ok {
				out = append(out, r)
			}
		}
	}
	return out
}

func TestToolLoopImmediateReply(t *testing.T) {
	m := &fakeModel{queue: []*llms.ContentResponse{textResp("done")}}
	final, rounds, err := runToolLoop(context.Background(), m, newLoopReg(t), userMsgs(), LoopCaps{MaxRounds: 4, MaxCalls: 8})
	if err != nil {
		t.Fatal(err)
	}
	if final != "done" || rounds != 1 {
		t.Fatalf("final=%q rounds=%d", final, rounds)
	}
}

func TestToolLoopReviewsFinalOnce(t *testing.T) {
	m := &fakeModel{queue: []*llms.ContentResponse{textResp("draft"), textResp("final")}}
	reviews := 0
	final, rounds, err := runToolLoop(context.Background(), m, newLoopReg(t), userMsgs(), LoopCaps{
		MaxRounds: 4,
		ReviewFinal: func(context.Context, string) (string, error) {
			reviews++
			return "review open task evidence", nil
		},
	})
	if err != nil || final != "final" || rounds != 2 || reviews != 1 || m.calls != 2 {
		t.Fatalf("final=%q rounds=%d reviews=%d calls=%d err=%v", final, rounds, reviews, m.calls, err)
	}
	seenReview := false
	for _, message := range m.seen[1] {
		for _, part := range message.Parts {
			if text, ok := part.(llms.TextContent); ok && strings.Contains(text.Text, "review open task evidence") {
				seenReview = true
			}
		}
	}
	if !seenReview {
		t.Fatal("second model call did not receive the final review")
	}
}

func TestToolLoopRunsTool(t *testing.T) {
	echo := &fakeTool{name: "echo", fn: func(a string) (string, error) { return "echoed:" + a, nil }}
	m := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "echo", `{"x":1}`), textResp("final")}}
	final, rounds, err := runToolLoop(context.Background(), m, newLoopReg(t, echo), userMsgs(), LoopCaps{MaxRounds: 4, MaxCalls: 8})
	if err != nil {
		t.Fatal(err)
	}
	if final != "final" || rounds != 2 {
		t.Fatalf("final=%q rounds=%d", final, rounds)
	}
	if len(echo.ran) != 1 || echo.ran[0] != `{"x":1}` {
		t.Fatalf("echo ran = %v", echo.ran)
	}
	res := toolResults(m)
	if len(res) != 1 || res[0].ToolCallID != "c1" || res[0].Name != "echo" || res[0].Content != `echoed:{"x":1}` {
		t.Fatalf("tool results = %+v", res)
	}
}

func TestToolLoopStopsAfterPolicyCapDenial(t *testing.T) {
	denied := false
	tool := &fakeTool{name: "execute", fn: func(string) (string, error) {
		denied = true
		return "engagement command cap reached", nil
	}}
	model := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "execute", "{}")}}
	final, rounds, err := runToolLoop(context.Background(), model, newLoopReg(t, tool), userMsgs(), LoopCaps{
		MaxRounds: 32,
		MaxCalls:  128,
		StopReason: func(context.Context) (string, error) {
			if denied {
				return "engagement command cap reached", nil
			}
			return "", nil
		},
		Finalize: func(_ context.Context, reason string) (string, error) { return "paused: " + reason, nil },
	})
	if err != nil || final != "paused: engagement command cap reached" || rounds != 1 || model.calls != 1 || len(tool.ran) != 1 {
		t.Fatalf("final=%q rounds=%d calls=%d runs=%d err=%v", final, rounds, model.calls, len(tool.ran), err)
	}
}

func TestToolLoopUnknownTool(t *testing.T) {
	echo := &fakeTool{name: "echo", fn: func(string) (string, error) { return "", nil }}
	m := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "nope", "{}"), textResp("final")}}
	final, _, err := runToolLoop(context.Background(), m, newLoopReg(t, echo), userMsgs(), LoopCaps{MaxRounds: 4, MaxCalls: 8})
	if err != nil || final != "final" {
		t.Fatalf("final=%q err=%v", final, err)
	}
	res := toolResults(m)
	if len(res) != 1 || !strings.Contains(res[0].Content, "tool not found: nope") || !strings.Contains(res[0].Content, "echo") {
		t.Fatalf("tool results = %+v", res)
	}
}

func TestToolLoopToolError(t *testing.T) {
	bad := &fakeTool{name: "bad", fn: func(string) (string, error) { return "", errors.New("boom") }}
	m := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "bad", "{}"), textResp("final")}}
	final, _, err := runToolLoop(context.Background(), m, newLoopReg(t, bad), userMsgs(), LoopCaps{MaxRounds: 4, MaxCalls: 8})
	if err != nil || final != "final" {
		t.Fatalf("final=%q err=%v", final, err)
	}
	res := toolResults(m)
	if len(res) != 1 || !strings.Contains(res[0].Content, "boom") {
		t.Fatalf("tool results = %+v", res)
	}
}

// A tool that panics is converted to a tool error and fed back, like runBatch
// recovers an executor panic; it must not crash the whole loop.
func TestToolLoopToolPanicBecomesError(t *testing.T) {
	boom := &fakeTool{name: "boom", fn: func(string) (string, error) { panic("kaboom") }}
	m := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "boom", "{}"), textResp("final")}}
	final, _, err := runToolLoop(context.Background(), m, newLoopReg(t, boom), userMsgs(), LoopCaps{MaxRounds: 4, MaxCalls: 8})
	if err != nil || final != "final" {
		t.Fatalf("final=%q err=%v", final, err)
	}
	res := toolResults(m)
	if len(res) != 1 || !strings.Contains(res[0].Content, "panic") || !strings.Contains(res[0].Content, "kaboom") {
		t.Fatalf("tool results = %+v", res)
	}
}

func TestToolLoopMaxRounds(t *testing.T) {
	echo := &fakeTool{name: "echo", fn: func(string) (string, error) { return "ok", nil }}
	m := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "echo", "{}")}}
	final, rounds, err := runToolLoop(context.Background(), m, newLoopReg(t, echo), userMsgs(), LoopCaps{MaxRounds: 3, MaxCalls: 100})
	if err != nil {
		t.Fatal(err)
	}
	if rounds != 3 || m.calls != 3 {
		t.Fatalf("rounds=%d calls=%d", rounds, m.calls)
	}
	if !strings.Contains(final, "round cap") {
		t.Fatalf("final = %q", final)
	}
}

func TestToolLoopMaxCalls(t *testing.T) {
	echo := &fakeTool{name: "echo", fn: func(string) (string, error) { return "ok", nil }}
	m := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "echo", "{}")}}
	final, _, err := runToolLoop(context.Background(), m, newLoopReg(t, echo), userMsgs(), LoopCaps{MaxRounds: 50, MaxCalls: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(echo.ran) != 2 || !strings.Contains(final, "call cap") {
		t.Fatalf("ran=%d final=%q", len(echo.ran), final)
	}
}

func TestToolLoopCallCapWithinRound(t *testing.T) {
	echo := &fakeTool{name: "echo", fn: func(string) (string, error) { return "ok", nil }}
	response := callResp("c1", "echo", "{}")
	response.Choices[0].ToolCalls = append(response.Choices[0].ToolCalls, llms.ToolCall{ID: "c2", FunctionCall: &llms.FunctionCall{Name: "echo", Arguments: "{}"}})
	m := &fakeModel{queue: []*llms.ContentResponse{response}}
	_, _, err := runToolLoop(context.Background(), m, newLoopReg(t, echo), userMsgs(), LoopCaps{MaxRounds: 3, MaxCalls: 1})
	if err != nil || len(echo.ran) != 1 {
		t.Fatalf("ran=%d err=%v", len(echo.ran), err)
	}
}

func TestToolLoopProgressErrorStops(t *testing.T) {
	want := errors.New("progress unavailable")
	m := &fakeModel{queue: []*llms.ContentResponse{textResp("done")}}
	_, _, err := runToolLoop(context.Background(), m, newLoopReg(t), userMsgs(), LoopCaps{
		NoProgressRounds: 2, Progress: func(context.Context) (string, error) { return "", want },
	})
	if !errors.Is(err, want) || m.calls != 0 {
		t.Fatalf("calls=%d err=%v", m.calls, err)
	}
}

func TestToolLoopNoChoices(t *testing.T) {
	m := &fakeModel{queue: []*llms.ContentResponse{{}}}
	if _, _, err := runToolLoop(context.Background(), m, newLoopReg(t), userMsgs(), LoopCaps{}); err == nil {
		t.Fatal("expected error for empty choices")
	}
}

func TestToolLoopNilFunctionCall(t *testing.T) {
	resp := &llms.ContentResponse{Choices: []*llms.ContentChoice{{
		ToolCalls: []llms.ToolCall{{ID: "c1", Type: "function"}},
	}}}
	m := &fakeModel{queue: []*llms.ContentResponse{resp, textResp("final")}}
	final, _, err := runToolLoop(context.Background(), m, newLoopReg(t), userMsgs(), LoopCaps{MaxRounds: 4, MaxCalls: 8})
	if err != nil || final != "final" {
		t.Fatalf("final=%q err=%v", final, err)
	}
	if res := toolResults(m); len(res) != 1 || res[0].ToolCallID != "c1" {
		t.Fatalf("tool results = %+v", res)
	}
}

func TestToolLoopModelError(t *testing.T) {
	m := errModel{}
	_, _, err := runToolLoop(context.Background(), m, newLoopReg(t), userMsgs(), LoopCaps{})
	if err == nil || !strings.Contains(err.Error(), "llm down") {
		t.Fatalf("err = %v", err)
	}
}

type errModel struct{}

func (errModel) GenerateContent(context.Context, []llms.MessageContent, ...llms.CallOption) (*llms.ContentResponse, error) {
	return nil, fmt.Errorf("llm down")
}

// aiMessages returns the AI-role messages of the last request the model saw.
func aiMessages(f *fakeModel) []llms.MessageContent {
	var out []llms.MessageContent
	for _, m := range f.seen[len(f.seen)-1] {
		if m.Role == llms.ChatMessageTypeAI {
			out = append(out, m)
		}
	}
	return out
}

func TestToolLoopAssistantMessageShape(t *testing.T) {
	echo := &fakeTool{name: "echo", fn: func(string) (string, error) { return "ok", nil }}
	first := callResp("c1", "echo", `{"x":1}`)
	first.Choices[0].Content = "thinking"
	m := &fakeModel{queue: []*llms.ContentResponse{first, textResp("final")}}
	if _, _, err := runToolLoop(context.Background(), m, newLoopReg(t, echo), userMsgs(), LoopCaps{MaxRounds: 4, MaxCalls: 8}); err != nil {
		t.Fatal(err)
	}
	ai := aiMessages(m)
	if len(ai) != 1 || len(ai[0].Parts) != 2 {
		t.Fatalf("ai messages = %+v", ai)
	}
	if tp, ok := ai[0].Parts[0].(llms.TextContent); !ok || tp.Text != "thinking" {
		t.Fatalf("part 0 = %#v", ai[0].Parts[0])
	}
	tc, ok := ai[0].Parts[1].(llms.ToolCall)
	if !ok || tc.ID != "c1" || tc.FunctionCall == nil || tc.FunctionCall.Name != "echo" || tc.FunctionCall.Arguments != `{"x":1}` {
		t.Fatalf("part 1 = %#v", ai[0].Parts[1])
	}
}

func TestToolLoopParallelCallsOneAssistantTurn(t *testing.T) {
	ta := &fakeTool{name: "ta", fn: func(string) (string, error) { return "ra", nil }}
	tb := &fakeTool{name: "tb", fn: func(string) (string, error) { return "rb", nil }}
	resp := &llms.ContentResponse{Choices: []*llms.ContentChoice{{
		ToolCalls: []llms.ToolCall{
			{ID: "a", Type: "function", FunctionCall: &llms.FunctionCall{Name: "ta", Arguments: `{"n":"a"}`}},
			{ID: "b", Type: "function", FunctionCall: &llms.FunctionCall{Name: "tb", Arguments: `{"n":"b"}`}},
		},
	}}}
	m := &fakeModel{queue: []*llms.ContentResponse{resp, textResp("final")}}
	final, _, err := runToolLoop(context.Background(), m, newLoopReg(t, ta, tb), userMsgs(), LoopCaps{MaxRounds: 4, MaxCalls: 8})
	if err != nil || final != "final" {
		t.Fatalf("final=%q err=%v", final, err)
	}
	if len(ta.ran) != 1 || len(tb.ran) != 1 {
		t.Fatalf("ran ta=%v tb=%v", ta.ran, tb.ran)
	}
	hist := m.seen[len(m.seen)-1]
	// human, ONE assistant turn, tool(a), tool(b)
	if len(hist) != 4 {
		t.Fatalf("history len = %d: %+v", len(hist), hist)
	}
	if hist[1].Role != llms.ChatMessageTypeAI || len(hist[1].Parts) != 2 {
		t.Fatalf("assistant turn = %+v", hist[1])
	}
	want := []struct{ id, name, args string }{{"a", "ta", `{"n":"a"}`}, {"b", "tb", `{"n":"b"}`}}
	for i, w := range want {
		tc, ok := hist[1].Parts[i].(llms.ToolCall)
		if !ok || tc.ID != w.id || tc.FunctionCall == nil || tc.FunctionCall.Name != w.name || tc.FunctionCall.Arguments != w.args {
			t.Fatalf("assistant part %d = %#v", i, hist[1].Parts[i])
		}
	}
	res := toolResults(m)
	if len(res) != 2 || res[0].ToolCallID != "a" || res[1].ToolCallID != "b" || hist[2].Role != llms.ChatMessageTypeTool || hist[3].Role != llms.ChatMessageTypeTool {
		t.Fatalf("tool results = %+v", res)
	}
}

func TestToolLoopDoesNotMutateCallerSlice(t *testing.T) {
	echo := &fakeTool{name: "echo", fn: func(string) (string, error) { return "ok", nil }}
	m := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "echo", "{}"), textResp("final")}}
	backing := make([]llms.MessageContent, 1, 8)
	backing[0] = userMsgs()[0]
	if _, _, err := runToolLoop(context.Background(), m, newLoopReg(t, echo), backing, LoopCaps{MaxRounds: 4, MaxCalls: 8}); err != nil {
		t.Fatal(err)
	}
	if extra := backing[:cap(backing)][1]; extra.Role != "" || extra.Parts != nil {
		t.Fatalf("caller backing array was written: %+v", extra)
	}
}

func TestToolLoopAuditFailureSkipsTool(t *testing.T) {
	echo := &fakeTool{name: "echo", fn: func(string) (string, error) { return "ok", nil }}
	m := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "echo", "{}")}}
	auditErr := errors.New("audit unavailable")
	_, _, err := runToolLoop(context.Background(), m, newLoopReg(t, echo), userMsgs(), LoopCaps{
		Observe: func(action, detail string) error {
			if action == "tool-call" {
				return auditErr
			}
			return nil
		},
	})
	if !errors.Is(err, auditErr) || len(echo.ran) != 0 {
		t.Fatalf("err=%v tool calls=%v", err, echo.ran)
	}
}

func TestToolLoopReportsEachCallOutcome(t *testing.T) {
	good := &fakeTool{name: "good", fn: func(string) (string, error) { return "tool error: quoted by a tool", nil }}
	bad := &fakeTool{name: "bad", fn: func(string) (string, error) { return "", errors.New("boom") }}
	late := &fakeTool{name: "late", fn: func(string) (string, error) { return "ok", nil }}
	response := &llms.ContentResponse{Choices: []*llms.ContentChoice{{ToolCalls: []llms.ToolCall{
		{ID: "c1", FunctionCall: &llms.FunctionCall{Name: "good", Arguments: "{}"}},
		{ID: "c2", FunctionCall: &llms.FunctionCall{Name: "bad", Arguments: "{}"}},
		{ID: "c3", FunctionCall: &llms.FunctionCall{Name: "late", Arguments: "{}"}},
	}}}}
	m := &fakeModel{queue: []*llms.ContentResponse{response}}
	var seen []string
	caps := LoopCaps{
		MaxRounds: 3,
		MaxCalls:  2,
		Observe: func(action, detail string) error {
			seen = append(seen, action+":"+detail)
			return nil
		},
		ObserveResult: func(name string, outcome ToolOutcome) {
			seen = append(seen, "outcome:"+name+"="+string(outcome))
		},
	}
	if _, _, err := runToolLoop(context.Background(), m, newLoopReg(t, good, bad, late), userMsgs(), caps); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"model-tools:round=1 calls=3",
		"tool-call:good", "outcome:good=done", "tool-result:good",
		"tool-call:bad", "outcome:bad=failed", "tool-result:bad",
		"tool-call:late", "outcome:late=skipped", "tool-result:late",
	}
	if !slices.Equal(seen, want) {
		t.Fatalf("observed %q, want %q", seen, want)
	}
	if len(late.ran) != 0 {
		t.Fatalf("skipped tool ran: %v", late.ran)
	}
}

func TestToolLoopReportsUnknownToolAsFailed(t *testing.T) {
	m := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "nope", "{}"), textResp("done")}}
	var got []ToolOutcome
	caps := LoopCaps{MaxRounds: 3, ObserveResult: func(_ string, outcome ToolOutcome) { got = append(got, outcome) }}
	if _, _, err := runToolLoop(context.Background(), m, newLoopReg(t), userMsgs(), caps); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []ToolOutcome{ToolFailed}) {
		t.Fatalf("outcomes = %v", got)
	}
}
