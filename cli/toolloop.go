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

// ToolOutcome is what became of one requested tool call.
type ToolOutcome string

const (
	// ToolDone means the tool ran and returned without error. It is the only
	// outcome that means the call ran to completion.
	ToolDone ToolOutcome = "done"
	// ToolFailed means the call was attempted and the tool, its lookup or its
	// arguments produced an error.
	ToolFailed ToolOutcome = "failed"
	// ToolSkipped means the call cap was reached and the tool never ran.
	ToolSkipped ToolOutcome = "skipped"
)

// LoopCaps bounds one tool loop. A value <= 0 selects the default.
type LoopCaps struct {
	MaxRounds        int
	MaxCalls         int
	NoProgressRounds int
	Progress         func(context.Context) (string, error)
	StopReason       func(context.Context) (string, error)
	ReviewFinal      func(context.Context, string) (string, error)
	Finalize         func(context.Context, string) (string, error)
	Observe          func(action, detail string) error
	// ObserveResult, when set, is called once per requested tool call with the
	// call's outcome, just before the "tool-result" Observe action. It does not
	// replace Observe.
	ObserveResult func(name string, outcome ToolOutcome)
	// SummarizeAtChars, when > 0 and Summarizer is set, enables chain
	// summarization: before each model call the running history is compacted
	// once it grows past this many characters. Zero (the default) disables it,
	// so an unset LoopCaps behaves exactly as before.
	SummarizeAtChars int
	// Summarizer condenses older turns when the budget is exceeded. nil (the
	// default) disables summarization regardless of SummarizeAtChars.
	Summarizer *ChainSummarizer
	// ToolMemo, when set, carries the results of tool calls that ran to
	// completion across the attempts of one turn, so a failover that restarts
	// the loop replays them instead of running the tool again. It spans every
	// restart of the turn's loop, the required-action reminder retry included:
	// that retry also restarts from the original messages, with a system
	// reminder appended, and would otherwise run a side-effecting tool a second
	// time. It also carries the turn's tool-call count, so MaxCalls bounds the
	// turn rather than each attempt. nil (the default) runs every requested call
	// and counts per loop, which is what the engagement executors want: each of
	// their loops is its own step.
	ToolMemo *toolMemo
	// BeginAttempt, when set, is called before each attempt of the loop, so a
	// caller that tracks what an attempt did drops that state when a failover
	// restarts from the first message. nil (the default) is what a caller that
	// tracks nothing per attempt passes.
	BeginAttempt func()
}

// runToolLoop drives the model through tool-calling rounds. Each round it sends
// msgs with the registry's tool specs. A reply with no tool calls ends the loop
// and its text is returned. Otherwise every requested tool is run (unknown tools
// and tool errors are fed back as results, never fatal) and the loop continues.
// It stops at caps.MaxRounds rounds or once caps.MaxCalls calls have run. When
// caps.ToolMemo is set, a call whose identical arguments already ran to
// completion in an earlier attempt is answered from that record instead of
// being run again, and the memo's own call count is what caps.MaxCalls bounds,
// so the cap covers the turn rather than this one loop.
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
	// The call count lives in the memo when there is one, because the memo is
	// the object with exactly one turn's lifetime: MaxCalls then bounds the
	// turn's calls across the attempts a failover restarts, rather than each
	// attempt's. Without a memo the count is this loop's own.
	total := 0
	calls, spend := func() int { return total }, func() { total++ }
	if caps.ToolMemo != nil {
		calls, spend = caps.ToolMemo.spent, caps.ToolMemo.spend
	}
	reviewedFinal := false
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
			if !reviewedFinal && rounds+2 <= caps.MaxRounds && caps.ReviewFinal != nil {
				retry, err := caps.ReviewFinal(ctx, choice.Content)
				if err != nil {
					return "", rounds, err
				}
				if retry != "" {
					reviewedFinal = true
					msgs = append(msgs, llms.TextParts(llms.ChatMessageTypeAI, choice.Content), llms.TextParts(llms.ChatMessageTypeHuman, retry))
					continue
				}
			}
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
			result, outcome := "tool call skipped: call cap reached", ToolSkipped
			if calls() < caps.MaxCalls {
				key, replayed := "", false
				if caps.ToolMemo != nil && tc.FunctionCall != nil {
					key = toolCallKey(name, args)
					if stored, hit := caps.ToolMemo.lookup(key); hit {
						result, outcome, replayed = stored, ToolDone, true
					}
				}
				if !replayed {
					ok := false
					result, ok = execToolCall(ctx, reg, tc.FunctionCall != nil, name, args)
					outcome = ToolFailed
					if ok {
						outcome = ToolDone
						if key != "" {
							caps.ToolMemo.record(key, result)
						}
					}
				}
				// A replayed call spends a slot like one that ran, so the cap
				// bounds the calls whether they ran or replayed.
				spend()
			}
			if caps.ObserveResult != nil {
				caps.ObserveResult(name, outcome)
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
			if caps.StopReason != nil {
				reason, err := caps.StopReason(ctx)
				if err != nil {
					return "", rounds, err
				}
				if reason != "" {
					return stop(reason)
				}
			}
		}
		if calls() >= caps.MaxCalls {
			return stop(fmt.Sprintf("tool call cap reached (%d calls)", calls()))
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

// execToolCall runs one tool call and returns the text to feed back to the
// model and whether the tool ran without error. A panicking tool is recovered
// into a tool error (matching runBatch's executor recover) so one bad tool
// cannot crash the whole loop.
func execToolCall(ctx context.Context, reg *tooldef.Registry, hasCall bool, name, args string) (result string, ok bool) {
	if !hasCall {
		return "invalid tool call: missing function", false
	}
	tool, found := reg.Get(name)
	if !found {
		return fmt.Sprintf("tool not found: %s; available tools: %v", name, reg.Names()), false
	}
	defer func() {
		if r := recover(); r != nil {
			result, ok = fmt.Sprintf("tool error: panic: %v", r), false
		}
	}()
	out, err := tool.Call(ctx, args)
	if err != nil {
		return "tool error: " + err.Error(), false
	}
	return out, true
}
