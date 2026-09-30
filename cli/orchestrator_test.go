package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"

	"github.com/tmc/langchaingo/llms"
)

// scriptModel returns the queued responses in order, then a final empty-text
// response so a loop always terminates.
type scriptModel struct {
	resps []*llms.ContentResponse
	i     int
}

func (m *scriptModel) GenerateContent(ctx context.Context, msgs []llms.MessageContent, opts ...llms.CallOption) (*llms.ContentResponse, error) {
	if m.i < len(m.resps) {
		r := m.resps[m.i]
		m.i++
		return r, nil
	}
	return &llms.ContentResponse{Choices: []*llms.ContentChoice{{Content: "done"}}}, nil
}

func toolCallResp(id, name, args string) *llms.ContentResponse {
	return &llms.ContentResponse{Choices: []*llms.ContentChoice{{
		ToolCalls: []llms.ToolCall{{ID: id, Type: "function", FunctionCall: &llms.FunctionCall{Name: name, Arguments: args}}},
	}}}
}

func finalResp(text string) *llms.ContentResponse {
	return &llms.ContentResponse{Choices: []*llms.ContentChoice{{Content: text}}}
}

func testDeps(t *testing.T, model toolLoopModel) engageDeps {
	t.Helper()
	return engageDeps{
		Model: model,
		RC:    nil, // kb tools are registered but the scripted model does not call them here
		Cfg:   ragconfig.Config{TopK: 5},
		Prefs: modelPrefs{Web: false},
		Store: openStore(t),
		Asker: askuser.AutoAsker{},
	}
}

func TestDispatchAgentSetsStageAndRunsExecutor(t *testing.T) {
	d := testDeps(t, nil)
	// Seed a task for the executor to act on.
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Kind: "web", Target: "10.0.0.5", Objective: "login", Status: engagement.StatusTodo}}}); err != nil {
		t.Fatal(err)
	}
	// Executor model: immediately record evidence, then finish.
	exec := &scriptModel{resps: []*llms.ContentResponse{
		toolCallResp("c1", "record_evidence", `{"task_id":"t1","quote":"csrf token missing"}`),
		finalResp("executor summary: csrf token missing"),
	}}
	d.Model = exec
	tool := newDispatchAgentTool(d)
	out, err := tool.Call(context.Background(), `{"task_id":"t1"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "csrf") {
		t.Errorf("dispatch result %q missing executor output", out)
	}
	// Stage and active id were written, revision moved past the seed.
	snap, _ := d.Store.Snapshot(context.Background())
	if snap.ActiveID != "t1" {
		t.Errorf("ActiveID = %q, want t1", snap.ActiveID)
	}
	if snap.Stage.Tool != "web" {
		t.Errorf("Stage.Tool = %q, want web", snap.Stage.Tool)
	}
	ev, _ := d.Store.EvidenceFor("t1")
	if len(ev) != 1 {
		t.Errorf("evidence rows = %d, want 1", len(ev))
	}
}

func TestDispatchAgentUnknownTaskSoft(t *testing.T) {
	d := testDeps(t, &scriptModel{})
	out, err := newDispatchAgentTool(d).Call(context.Background(), `{"task_id":"nope"}`)
	if err != nil {
		t.Fatalf("unknown task must be soft: %v", err)
	}
	if !strings.Contains(strings.ToLower(out), "not found") && !strings.Contains(strings.ToLower(out), "unknown") {
		t.Errorf("result %q should explain the missing task", out)
	}
}

func TestRunOrchestratorPlansThenDispatches(t *testing.T) {
	d := testDeps(t, nil)
	// Orchestrator model: add a task, dispatch it, then finish. After the
	// orchestrator's own turns, the scripted executor turn(s) run inside
	// dispatch_agent using the SAME model instance, so queue executor turns
	// after the dispatch call.
	model := &scriptModel{resps: []*llms.ContentResponse{
		toolCallResp("c1", "plan_add", `{"id":"t1","kind":"recon","target":"10.0.0.5","objective":"enumerate"}`),
		toolCallResp("c2", "dispatch_agent", `{"task_id":"t1"}`),
		// executor turn (runs within dispatch_agent):
		finalResp("executor: found ssh on 22"),
		// back in the orchestrator:
		toolCallResp("c3", "plan_complete", `{"id":"t1"}`),
		finalResp("engagement step done"),
	}}
	d.Model = model
	out, err := runOrchestrator(context.Background(), d, "assess 10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "done") {
		t.Errorf("orchestrator final %q", out)
	}
	got, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != engagement.StatusDone {
		t.Errorf("t1 status = %q, want done", got.Status)
	}
}
