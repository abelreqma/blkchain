package main

import (
	"testing"

	"github.com/tmc/langchaingo/llms"
)

// TestToolCallProbe is a compile-only guard for the langchaingo tool-calling
// API surface the harness loop depends on. It asserts nothing at runtime.
func TestToolCallProbe(t *testing.T) {
	tool := llms.Tool{
		Type: "function",
		Function: &llms.FunctionDefinition{
			Name:        "x",
			Description: "y",
			Parameters:  map[string]any{"type": "object"},
		},
	}
	var _ llms.CallOption = llms.WithTools([]llms.Tool{tool})

	// Reading tool calls off a response choice.
	var choice llms.ContentChoice
	for _, tc := range choice.ToolCalls {
		_ = tc.ID
		_ = tc.Type
		if tc.FunctionCall != nil {
			_ = tc.FunctionCall.Name
			_ = tc.FunctionCall.Arguments
		}
	}

	// Sending the assistant tool call back, then the tool result.
	call := llms.ToolCall{
		ID:   "call_1",
		Type: "function",
		FunctionCall: &llms.FunctionCall{
			Name:      "x",
			Arguments: `{}`,
		},
	}
	_ = []llms.MessageContent{
		{Role: llms.ChatMessageTypeAI, Parts: []llms.ContentPart{call}},
		{Role: llms.ChatMessageTypeTool, Parts: []llms.ContentPart{
			llms.ToolCallResponse{ToolCallID: "call_1", Name: "x", Content: "ok"},
		}},
	}

	t.Skip("compile-only probe")
}
