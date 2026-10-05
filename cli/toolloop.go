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
	MaxRounds        int
	MaxCalls         int
	NoProgressRounds int
	Progress         func(context.Context) (string, error)
	Finalize         func(context.Context, string) (string, error)
	Observe          func(action, detail string) error
	// SummarizeAtChars, when > 0 and Summarizer is set, enables chain
	// summarization: before each model call the running history is compacted
	// once it grows past this many characters. Zero (the default) disables it,
	// so an unset LoopCaps behaves exactly as before.
	SummarizeAtChars int
	// Summarizer condenses older turns when the budget is exceeded. nil (the
	// default) disables summarization regardless of SummarizeAtChars.
	Summarizer *ChainSummarizer
}

// runToolLoop drives the model through tool-calling rounds. Each round it sends
// msgs with the registry's tool specs. A reply with no tool calls ends the loop
// and its text is returned. Otherwise every requested tool is run (unknown tools
// and tool errors are fed back as results, never fatal) and the loop continues.
// It stops at caps.MaxRounds rounds or once caps.MaxCalls calls have run.
func runToolLoop(ctx context.Context, m toolLoopModel, reg *tooldef.Registry, msgs []llms.MessageContent, caps LoopCaps, extra ...llms.CallOption) (final string, rounds int, err error) {
	if caps.Observe == nil {
		caps.Observe = engageTelemetryFromContext(ctx)
	}
	if caps.MaxRounds <= 0 {
		caps.MaxRounds = defaultLoopRounds
	}
	if caps.MaxCalls <= 0 {
		caps.MaxCalls = defaultLoopCalls
	}
	msgs = slices.Clone(msgs)
	stop := func(reason string) (string, int, error) {
		if err := ctx.Err(); err != nil {
			return "", rounds, err
		}
		if caps.Finalize != nil {
			final, err := caps.Finalize(ctx, reason)
			return final, rounds, err
		}
		return "Stopped: " + reason + ".", rounds, nil
	}
	var progress string
	if caps.Progress != nil && caps.NoProgressRounds > 0 {
		progress, err = caps.Progress(ctx)
		if err != nil {
			return "", rounds, err
		}
	}
	idle := 0
	opts := append([]llms.CallOption{llms.WithTools(reg.Specs())}, extra...)
	total := 0
	for rounds < caps.MaxRounds {
		if err := ctx.Err(); err != nil {
			return "", rounds, err
		}
		rounds++
		if err := consumeEngageWork(ctx); err != nil {
			return "", rounds, err
		}
		// Code-owned context budgeting: when the running history outgrows the
		// budget, condense the middle span before the model call. Best-effort -
		// a summarizer error leaves the full history in place rather than
		// aborting the loop; the model never controls whether this runs.
		if caps.Summarizer != nil && caps.SummarizeAtChars > 0 && historyChars(msgs) > caps.SummarizeAtChars {
			if compacted, serr := caps.Summarizer.Compact(ctx, msgs); serr == nil {
				msgs = compacted
			}
		}
		resp, err := m.GenerateContent(withLLMStage(ctx, "tool_loop"), msgs, opts...)
		if err != nil {
			return "", rounds, err
		}
		if resp == nil || len(resp.Choices) == 0 || resp.Choices[0] == nil {
			return "", rounds, fmt.Errorf("model returned no choices")
		}
		choice := resp.Choices[0]
		if len(choice.ToolCalls) == 0 {
			if caps.Observe != nil {
				if err := caps.Observe("model-final", fmt.Sprintf("round=%d", rounds)); err != nil {
					return "", rounds, err
				}
			}
			return choice.Content, rounds, nil
		}
		if caps.Observe != nil {
			if err := caps.Observe("model-tools", fmt.Sprintf("round=%d calls=%d", rounds, len(choice.ToolCalls))); err != nil {
				return "", rounds, err
			}
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
			if err := consumeEngageWork(ctx); err != nil {
				return "", rounds, err
			}
			if caps.Observe != nil {
				if err := caps.Observe("tool-call", name); err != nil {
					return "", rounds, err
				}
			}
			result := "tool call skipped: call cap reached"
			if total < caps.MaxCalls {
				result = execToolCall(ctx, reg, tc.FunctionCall != nil, name, args)
				total++
			}
			if caps.Observe != nil {
				if err := caps.Observe("tool-result", name); err != nil {
					return "", rounds, err
				}
			}
			msgs = append(msgs, llms.MessageContent{
				Role: llms.ChatMessageTypeTool,
				Parts: []llms.ContentPart{llms.ToolCallResponse{
					ToolCallID: tc.ID,
					Name:       name,
					Content:    result,
				}},
			})
		}
		if total >= caps.MaxCalls {
			return stop(fmt.Sprintf("tool call cap reached (%d calls)", total))
		}
		if caps.Progress != nil && caps.NoProgressRounds > 0 {
			next, err := caps.Progress(ctx)
			if err != nil {
				return "", rounds, err
			}
			if next == progress {
				idle++
			} else {
				idle = 0
			}
			progress = next
			if idle >= caps.NoProgressRounds {
				return stop(fmt.Sprintf("no-progress limit reached (%d rounds)", idle))
			}
		}
	}
	return stop(fmt.Sprintf("round cap reached (%d rounds) without a final answer", caps.MaxRounds))
}

// execToolCall runs one tool call and returns the text to feed back to the model.
// A panicking tool is recovered into a tool error (matching runBatch's executor
// recover) so one bad tool cannot crash the whole loop.
func execToolCall(ctx context.Context, reg *tooldef.Registry, hasCall bool, name, args string) (result string) {
	if !hasCall {
		return "invalid tool call: missing function"
	}
	tool, ok := reg.Get(name)
	if !ok {
		return fmt.Sprintf("tool not found: %s; available tools: %v", name, reg.Names())
	}
	defer func() {
		if r := recover(); r != nil {
			result = fmt.Sprintf("tool error: panic: %v", r)
		}
	}()
	out, err := tool.Call(ctx, args)
	if err != nil {
		return "tool error: " + err.Error()
	}
	return out
}
