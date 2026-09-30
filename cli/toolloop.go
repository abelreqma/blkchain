package main

import (
	"context"
	"fmt"
	"slices"

	"blkchain/cli/internal/tooldef"

	"github.com/tmc/langchaingo/llms"
)

const (
	defaultLoopRounds = 8
	defaultLoopCalls  = 16
)

// toolLoopModel is the slice of the LLM client the tool loop needs. It is
// satisfied by *openai.LLM and by test fakes.
type toolLoopModel interface {
	GenerateContent(ctx context.Context, msgs []llms.MessageContent, opts ...llms.CallOption) (*llms.ContentResponse, error)
}

// LoopCaps bounds one tool loop. A value <= 0 selects the default.
type LoopCaps struct {
	MaxRounds int
	MaxCalls  int
}

// runToolLoop drives the model through tool-calling rounds. Each round it sends
// msgs with the registry's tool specs. A reply with no tool calls ends the loop
// and its text is returned. Otherwise every requested tool is run (unknown tools
// and tool errors are fed back as results, never fatal) and the loop continues.
// It stops at caps.MaxRounds rounds or once caps.MaxCalls calls have run.
func runToolLoop(ctx context.Context, m toolLoopModel, reg *tooldef.Registry, msgs []llms.MessageContent, caps LoopCaps, extra ...llms.CallOption) (final string, rounds int, err error) {
	if caps.MaxRounds <= 0 {
		caps.MaxRounds = defaultLoopRounds
	}
	if caps.MaxCalls <= 0 {
		caps.MaxCalls = defaultLoopCalls
	}
	msgs = slices.Clone(msgs)
	opts := append([]llms.CallOption{llms.WithTools(reg.Specs())}, extra...)
	total := 0
	for rounds < caps.MaxRounds {
		if err := ctx.Err(); err != nil {
			return "", rounds, err
		}
		rounds++
		resp, err := m.GenerateContent(ctx, msgs, opts...)
		if err != nil {
			return "", rounds, err
		}
		if resp == nil || len(resp.Choices) == 0 {
			return "", rounds, fmt.Errorf("model returned no choices")
		}
		choice := resp.Choices[0]
		if len(choice.ToolCalls) == 0 {
			return choice.Content, rounds, nil
		}
		// One assistant turn carries the text and every tool call of the round.
		parts := make([]llms.ContentPart, 0, len(choice.ToolCalls)+1)
		if choice.Content != "" {
			parts = append(parts, llms.TextPart(choice.Content))
		}
		for _, tc := range choice.ToolCalls {
			name, args := "", ""
			if tc.FunctionCall != nil {
				name, args = tc.FunctionCall.Name, tc.FunctionCall.Arguments
			}
			parts = append(parts, llms.ToolCall{
				ID:           tc.ID,
				Type:         "function",
				FunctionCall: &llms.FunctionCall{Name: name, Arguments: args},
			})
		}
		msgs = append(msgs, llms.MessageContent{Role: llms.ChatMessageTypeAI, Parts: parts})
		for _, tc := range choice.ToolCalls {
			name, args := "", ""
			if tc.FunctionCall != nil {
				name, args = tc.FunctionCall.Name, tc.FunctionCall.Arguments
			}
			msgs = append(msgs, llms.MessageContent{
				Role: llms.ChatMessageTypeTool,
				Parts: []llms.ContentPart{llms.ToolCallResponse{
					ToolCallID: tc.ID,
					Name:       name,
					Content:    execToolCall(ctx, reg, tc.FunctionCall != nil, name, args),
				}},
			})
			total++
		}
		if total >= caps.MaxCalls {
			return fmt.Sprintf("Stopped: tool call cap reached (%d calls).", total), rounds, nil
		}
	}
	return fmt.Sprintf("Stopped: round cap reached (%d rounds) without a final answer.", caps.MaxRounds), rounds, nil
}

// execToolCall runs one tool call and returns the text to feed back to the model.
func execToolCall(ctx context.Context, reg *tooldef.Registry, hasCall bool, name, args string) string {
	if !hasCall {
		return "invalid tool call: missing function"
	}
	tool, ok := reg.Get(name)
	if !ok {
		return fmt.Sprintf("tool not found: %s; available tools: %v", name, reg.Names())
	}
	out, err := tool.Call(ctx, args)
	if err != nil {
		return "tool error: " + err.Error()
	}
	return out
}
