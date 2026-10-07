package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGatewayStreamRequiresCompletionEvent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: assistant.delta\ndata: {\"delta\":\"partial\"}\n\n")
	}))
	defer server.Close()
	t.Setenv("HERMES_API_URL", server.URL)
	err := StreamAgent(context.Background(), "fixture", "question", "", "", func(agentEvent) {})
	if err == nil {
		t.Fatal("incomplete stream reported success")
	}
}

func TestMapAgentEventGateway(t *testing.T) {
	cases := []struct {
		name     string
		event    string
		data     string
		wantOK   bool
		wantKind agentEventKind
		wantText string
		wantTool string
		wantErr  bool
	}{
		{"delta", "assistant.delta", `{"message_id":"m1","delta":"hello"}`, true, agentText, "hello", "", false},
		{"delta empty skipped", "assistant.delta", `{"delta":""}`, false, 0, "", "", false},
		{"commentary", "assistant.commentary", `{"text":"thinking about it"}`, true, agentCommentary, "thinking about it", "", false},
		{"tool started", "tool.started", `{"tool":"web_search","preview":"query"}`, true, agentToolActivity, "running", "web_search", false},
		{"tool completed ok", "tool.completed", `{"tool":"web_search","duration":1.2}`, true, agentToolActivity, "done", "web_search", false},
		{"tool completed err", "tool.completed", `{"tool":"web_search","error":"boom"}`, true, agentToolActivity, "failed", "web_search", false},
		{"tool failed", "tool.failed", `{"tool":"rag"}`, true, agentToolActivity, "failed", "rag", false},
		{"run completed", "run.completed", `{"usage":{}}`, true, agentTerminal, "", "", false},
		{"run failed", "run.failed", `{"error":"model overloaded"}`, true, agentTerminal, "", "", true},
		{"run cancelled", "run.cancelled", `{}`, true, agentTerminal, "", "", true},
		{"run started ignored", "run.started", `{}`, false, 0, "", "", false},
		{"unknown ignored", "subagent.start", `{}`, false, 0, "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := mapAgentEvent(tc.event, tc.data)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (ev=%+v)", ok, tc.wantOK, ev)
			}
			if !ok {
				return
			}
			if ev.kind != tc.wantKind {
				t.Errorf("kind = %d, want %d", ev.kind, tc.wantKind)
			}
			if ev.text != tc.wantText {
				t.Errorf("text = %q, want %q", ev.text, tc.wantText)
			}
			if ev.tool != tc.wantTool {
				t.Errorf("tool = %q, want %q", ev.tool, tc.wantTool)
			}
			if (ev.err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", ev.err, tc.wantErr)
			}
		})
	}
	// run.cancelled must surface as context.Canceled so the TUI shows "canceled".
	ev, _ := mapAgentEvent("run.cancelled", `{}`)
	if !errors.Is(ev.err, context.Canceled) {
		t.Errorf("run.cancelled err = %v, want context.Canceled", ev.err)
	}
}

func TestParseAgentSSESkipsKeepaliveAndDispatches(t *testing.T) {
	// Two answer deltas, a keepalive comment, a tool event, and a terminal event,
	// separated by blank lines per the SSE framing.
	stream := strings.Join([]string{
		": keepalive",
		"event: assistant.delta",
		`data: {"delta":"Hel"}`,
		"",
		"event: assistant.delta",
		`data: {"delta":"lo"}`,
		"",
		": keepalive",
		"event: tool.started",
		`data: {"tool":"rag"}`,
		"",
		"event: run.completed",
		`data: {}`,
		"",
	}, "\n")

	var got []agentEvent
	err := parseAgentSSE(strings.NewReader(stream), func(ev agentEvent) {
		got = append(got, ev)
	})
	if err != nil {
		t.Fatalf("parseAgentSSE error: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d events, want 4: %+v", len(got), got)
	}
	if got[0].kind != agentText || got[0].text != "Hel" {
		t.Errorf("event 0 = %+v, want text Hel", got[0])
	}
	if got[1].kind != agentText || got[1].text != "lo" {
		t.Errorf("event 1 = %+v, want text lo", got[1])
	}
	if got[2].kind != agentToolActivity || got[2].tool != "rag" || got[2].text != "running" {
		t.Errorf("event 2 = %+v, want running rag", got[2])
	}
	if got[3].kind != agentTerminal {
		t.Errorf("event 3 = %+v, want terminal", got[3])
	}
}

func TestParseAgentSSEMultilineData(t *testing.T) {
	// Multiple data: lines for one event are joined with newlines before parsing.
	stream := "event: assistant.delta\ndata: {\"delta\":\ndata: \"multi\"}\n\n"
	var got []agentEvent
	if err := parseAgentSSE(strings.NewReader(stream), func(ev agentEvent) { got = append(got, ev) }); err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(got) != 1 || got[0].text != "multi" {
		t.Fatalf("multiline data not joined: %+v", got)
	}
}

func TestParseAgentJSONLine(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		wantOK   bool
		wantKind agentEventKind
		wantText string
		wantTool string
		wantErr  bool
	}{
		{"init model", `{"type":"system","subtype":"init","model":"supergemma","session_id":"s1"}`, true, agentModelInfo, "supergemma", "", false},
		{"system non-init", `{"type":"system","subtype":"other"}`, false, 0, "", "", false},
		{"text", `{"type":"text","text":"answer part"}`, true, agentText, "answer part", "", false},
		{"text empty", `{"type":"text","text":""}`, false, 0, "", "", false},
		{"tool_use", `{"type":"tool_use","name":"web_search"}`, true, agentToolActivity, "running", "web_search", false},
		{"tool_result", `{"type":"tool_result","name":"web_search"}`, true, agentToolActivity, "done", "web_search", false},
		{"result ok final_response", `{"type":"result","final_response":"the answer","exit_code":0}`, true, agentTerminal, "the answer", "", false},
		{"result ok text field", `{"type":"result","text":"hi","exit_code":0}`, true, agentTerminal, "hi", "", false},
		{"result err", `{"type":"result","final_response":"partial","exit_code":2}`, true, agentTerminal, "partial", "", true},
		{"blank", "", false, 0, "", "", false},
		{"junk", "not json", false, 0, "", "", false},
		{"unknown type", `{"type":"whatever"}`, false, 0, "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := parseAgentJSONLine(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (ev=%+v)", ok, tc.wantOK, ev)
			}
			if !ok {
				return
			}
			if ev.kind != tc.wantKind {
				t.Errorf("kind = %d, want %d", ev.kind, tc.wantKind)
			}
			if ev.text != tc.wantText {
				t.Errorf("text = %q, want %q", ev.text, tc.wantText)
			}
			if ev.tool != tc.wantTool {
				t.Errorf("tool = %q, want %q", ev.tool, tc.wantTool)
			}
			if (ev.err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", ev.err, tc.wantErr)
			}
		})
	}
}

func TestHermesAPIURLDefaultAndOverride(t *testing.T) {
	t.Setenv("HERMES_API_URL", "")
	if got := hermesAPIURL(); got != defaultHermesAPIURL {
		t.Errorf("default = %q, want %q", got, defaultHermesAPIURL)
	}
	t.Setenv("HERMES_API_URL", "http://example.test:9000/")
	if got := hermesAPIURL(); got != "http://example.test:9000" {
		t.Errorf("override = %q, want trailing slash trimmed", got)
	}
}
