package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"github.com/tmc/langchaingo/llms"
)

type convergenceModel struct {
	fakeModel
	opts []llms.CallOptions
}

func TestEngageConvergenceEnvBounds(t *testing.T) {
	for _, tc := range []struct {
		value               string
		rounds, calls, idle int
	}{
		{"", 32, 128, 3}, {"bad", 32, 128, 3}, {"-1", 1, 1, 1}, {"0", 1, 1, 1},
		{" 12 ", 12, 12, 12}, {"999999", 256, 2048, 32},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("BLKCHAIN_ENGAGE_MAX_ROUNDS", tc.value)
			t.Setenv("BLKCHAIN_ENGAGE_MAX_CALLS", tc.value)
			t.Setenv("BLKCHAIN_ENGAGE_NO_PROGRESS_ROUNDS", tc.value)
			caps := engageLoopCaps()
			if caps.MaxRounds != tc.rounds || caps.MaxCalls != tc.calls || caps.NoProgressRounds != tc.idle {
				t.Fatalf("caps=%+v", caps)
			}
		})
	}
}

func TestEngageConvergenceNoOpRevisionsHalt(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_NO_PROGRESS_ROUNDS", "2")
	m := &fakeModel{queue: []*llms.ContentResponse{
		callResp("c1", "plan_add", `{"id":"t1","kind":"web","target":"10.0.0.5","objective":"inspect"}`),
		callResp("c2", "plan_update", `{"id":"t1","objective":"inspect"}`),
		callResp("c3", "plan_update", `{"id":"t1","objective":"inspect"}`),
		textResp("stored report"),
	}}
	d := testDeps(t, m)
	out, err := runOrchestrator(context.Background(), d, "assess target")
	rev, _ := d.Store.Revision(context.Background())
	if err != nil || m.calls != 4 || rev != 3 || !strings.Contains(out, "no-progress") {
		t.Fatalf("out=%q calls=%d revision=%d err=%v", out, m.calls, rev, err)
	}
}

func TestEngageConvergenceEvidenceAndCompletionResetIdle(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_NO_PROGRESS_ROUNDS", "2")
	m := &fakeModel{queue: []*llms.ContentResponse{
		callResp("c1", "plan_add", `{"id":"t1","kind":"web","target":"10.0.0.5","objective":"inspect"}`),
		callResp("c2", "missing", "{}"),
		callResp("c3", "record_evidence", `{"task_id":"t1","quote":"HTTP 200"}`),
		callResp("c4", "missing", "{}"),
		callResp("c5", "plan_complete", `{"id":"t1"}`),
		callResp("c6", "missing", "{}"),
		textResp("normal final report"),
	}}
	d := testDeps(t, m)
	out, err := runOrchestrator(context.Background(), d, "assess target")
	task, taskErr := d.Store.GetTask("t1")
	if err != nil || taskErr != nil || out != "normal final report" || m.calls != 7 || task.Status != engagement.StatusDone {
		t.Fatalf("out=%q calls=%d task=%+v err=%v/%v", out, m.calls, task, err, taskErr)
	}
}

func TestEngageConvergenceDuplicateEvidenceHalts(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_NO_PROGRESS_ROUNDS", "2")
	m := &fakeModel{queue: []*llms.ContentResponse{
		callResp("c1", "plan_add", `{"id":"t1","kind":"web","target":"10.0.0.5","objective":"inspect"}`),
		callResp("c2", "record_evidence", `{"task_id":"t1","quote":"HTTP 200"}`),
		callResp("c3", "record_evidence", `{"task_id":"t1","quote":"HTTP 200"}`),
		callResp("c4", "record_evidence", `{"task_id":"t1","quote":"HTTP 200"}`),
		textResp("stored report"),
	}}
	out, err := runOrchestrator(context.Background(), testDeps(t, m), "assess target")
	if err != nil || m.calls != 5 || !strings.Contains(out, "no-progress") {
		t.Fatalf("out=%q calls=%d err=%v", out, m.calls, err)
	}
}

func TestEngageConvergencePlanDeltaResetIdle(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_NO_PROGRESS_ROUNDS", "2")
	m := &fakeModel{queue: []*llms.ContentResponse{
		callResp("c1", "plan_add", `{"id":"t1","kind":"web","target":"10.0.0.5","objective":"inspect"}`),
		callResp("c2", "missing", "{}"),
		callResp("c3", "plan_update", `{"id":"t1","objective":"inspect login"}`),
		callResp("c4", "missing", "{}"),
		textResp("normal final report"),
	}}
	out, err := runOrchestrator(context.Background(), testDeps(t, m), "assess target")
	if err != nil || out != "normal final report" || m.calls != 5 {
		t.Fatalf("out=%q calls=%d err=%v", out, m.calls, err)
	}
}

func TestEngageConvergenceCoverageIgnoresBookkeeping(t *testing.T) {
	d := testDeps(t, nil)
	ctx := context.Background()
	coverage := engagement.ReconCoverage{Surface: engagement.SurfaceWeb, Asset: "10.0.0.5", Dimensions: map[string]engagement.ReconDimStatus{"http": engagement.ReconPending}}
	if _, err := d.Store.Apply(engagement.Delta{ReconUpserts: []engagement.ReconCoverage{coverage}}); err != nil {
		t.Fatal(err)
	}
	first, err := engagementProgress(ctx, d.Store)
	if err != nil {
		t.Fatal(err)
	}
	coverage.IterationCount = 2
	coverage.LastNoveltyRev = engagement.ReconNoveltyThisRev
	stage := engagement.Stage{Label: "dispatch", Tool: "web"}
	if _, err := d.Store.Apply(engagement.Delta{ReconUpserts: []engagement.ReconCoverage{coverage}, SetStage: &stage}); err != nil {
		t.Fatal(err)
	}
	next, err := engagementProgress(ctx, d.Store)
	if err != nil || first != next {
		t.Fatalf("bookkeeping changes progress: err=%v", err)
	}
	coverage.Dimensions["http"] = engagement.ReconCovered
	if _, err := d.Store.Apply(engagement.Delta{ReconUpserts: []engagement.ReconCoverage{coverage}}); err != nil {
		t.Fatal(err)
	}
	next, err = engagementProgress(ctx, d.Store)
	if err != nil || first == next {
		t.Fatalf("coverage does not change progress: err=%v", err)
	}
}

func TestEngageConvergenceSynthesisContextBound(t *testing.T) {
	m := &fakeModel{queue: []*llms.ContentResponse{textResp("report")}}
	d := testDeps(t, m)
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Kind: "web", Status: engagement.StatusDone, Objective: strings.Repeat("x", 60000)}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := synthesizeEngagement(context.Background(), d, strings.Repeat("g", 10000), "round cap"); err != nil {
		t.Fatal(err)
	}
	text := m.seen[0][1].Parts[0].(llms.TextContent).Text
	if len(text) > 57000 || !strings.Contains(text, `"Truncated":true`) {
		t.Fatalf("length=%d truncated=%v", len(text), strings.Contains(text, `"Truncated":true`))
	}
}

func TestEngageConvergenceCompletedEvidenceStaysExact(t *testing.T) {
	m := &fakeModel{queue: []*llms.ContentResponse{textResp("report")}}
	d := testDeps(t, m)
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Kind: "web", Status: engagement.StatusDone}}}); err != nil {
		t.Fatal(err)
	}
	quote := "header: `value`\nsecond\tline"
	if _, err := d.Store.RecordEvidence("t1", quote); err != nil {
		t.Fatal(err)
	}
	if _, err := synthesizeEngagement(context.Background(), d, "assess", "round cap"); err != nil {
		t.Fatal(err)
	}
	text := m.seen[0][1].Parts[0].(llms.TextContent).Text
	var payload struct{ Report string }
	if err := json.Unmarshal([]byte(strings.TrimPrefix(text, "Engagement data (JSON):\n")), &payload); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(quote)
	if !strings.Contains(payload.Report, string(encoded)) {
		t.Fatalf("raw completed evidence missing: %q", payload.Report)
	}
}

func TestEngageConvergenceCancellationSkipsSynthesis(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := &fakeModel{queue: []*llms.ContentResponse{textResp("report")}}
	_, err := runOrchestrator(ctx, testDeps(t, m), "assess")
	if !errors.Is(err, context.Canceled) || m.calls != 0 {
		t.Fatalf("calls=%d err=%v", m.calls, err)
	}
}

func TestEngageConvergenceSynthesisFailureKeepsEvidence(t *testing.T) {
	for _, resp := range []*llms.ContentResponse{nil, {}, {Choices: []*llms.ContentChoice{nil}}, textResp(" "), callResp("c1", "plan_add", "{}"), {Choices: []*llms.ContentChoice{{Content: "partial", StopReason: "length"}}}} {
		m := &fakeModel{queue: []*llms.ContentResponse{resp}}
		d := testDeps(t, m)
		if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Kind: "web", Status: engagement.StatusTodo}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Store.RecordEvidence("t1", "HTTP 200"); err != nil {
			t.Fatal(err)
		}
		out, err := synthesizeEngagement(context.Background(), d, "assess", "round cap reached")
		if err != nil || !strings.Contains(out, "HTTP 200") || !strings.Contains(out, "Final synthesis unavailable") || m.calls != 1 {
			t.Fatalf("out=%q calls=%d err=%v", out, m.calls, err)
		}
	}
	d := testDeps(t, errModel{})
	out, err := synthesizeEngagement(context.Background(), d, "assess", "call cap reached")
	if err != nil || !strings.Contains(out, "Final synthesis unavailable") {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestEngageConvergenceCallCapUsesSynthesisModel(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_ORCHESTRATOR_MODEL", "larger-model")
	t.Setenv("BLKCHAIN_ENGAGE_MAX_CALLS", "1")
	m := &convergenceModel{fakeModel: fakeModel{queue: []*llms.ContentResponse{callResp("c1", "missing", "{}"), textResp("final report")}}}
	out, err := runOrchestrator(context.Background(), testDeps(t, m), "assess target")
	if err != nil || !strings.Contains(out, "tool call cap") || m.calls != 2 || len(m.opts[1].Tools) != 0 || m.opts[1].Model != "larger-model" {
		t.Fatalf("out=%q options=%+v err=%v", out, m.opts, err)
	}
}

func (m *convergenceModel) GenerateContent(ctx context.Context, msgs []llms.MessageContent, options ...llms.CallOption) (*llms.ContentResponse, error) {
	var opts llms.CallOptions
	for _, option := range options {
		option(&opts)
	}
	m.opts = append(m.opts, opts)
	return m.fakeModel.GenerateContent(ctx, msgs, options...)
}

func TestEngageConvergenceHigherDefaultCaps(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_MAX_ROUNDS", "")
	t.Setenv("BLKCHAIN_ENGAGE_MAX_CALLS", "")
	queue := []*llms.ContentResponse{}
	for i := 0; i < 10; i++ {
		queue = append(queue, callResp(fmt.Sprint(i), "plan_add", fmt.Sprintf(`{"id":"t%d","kind":"web","target":"10.0.0.5","objective":"inspect %d"}`, i, i)))
	}
	queue = append(queue, textResp("engagement report"))
	m := &fakeModel{queue: queue}
	out, err := runOrchestrator(context.Background(), testDeps(t, m), "assess target")
	if err != nil || out != "engagement report" || m.calls != 11 {
		t.Fatalf("out=%q calls=%d err=%v", out, m.calls, err)
	}
}

func TestEngageConvergenceRoundCapSynthesizes(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_MAX_ROUNDS", "1")
	t.Setenv("BLKCHAIN_ENGAGE_MAX_CALLS", "100")
	m := &convergenceModel{fakeModel: fakeModel{queue: []*llms.ContentResponse{
		callResp("c1", "plan_add", `{"id":"t1","kind":"web","target":"10.0.0.5","objective":"inspect login"}`),
		textResp("report: login remains untested"),
	}}}
	d := testDeps(t, m)
	stopReason := ""
	d.OnStop = func(reason string) { stopReason = reason }
	out, err := runOrchestrator(context.Background(), d, "assess target")
	if err != nil || !strings.Contains(out, "login remains untested") || m.calls != 2 || !strings.Contains(stopReason, "round cap") {
		t.Fatalf("out=%q calls=%d err=%v", out, m.calls, err)
	}
	last := m.opts[len(m.opts)-1]
	if len(last.Tools) != 0 || last.ToolChoice != "none" || last.MaxTokens <= 0 {
		t.Fatalf("synthesis options=%+v", last)
	}
}

func TestEngageConvergenceNoProgressSynthesizes(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_MAX_ROUNDS", "20")
	t.Setenv("BLKCHAIN_ENGAGE_MAX_CALLS", "100")
	t.Setenv("BLKCHAIN_ENGAGE_NO_PROGRESS_ROUNDS", "2")
	m := &fakeModel{queue: []*llms.ContentResponse{
		callResp("c1", "missing_tool", "{}"),
		callResp("c2", "missing_tool", "{}"),
		textResp("report: no work completed"),
	}}
	out, err := runOrchestrator(context.Background(), testDeps(t, m), "assess target")
	if err != nil || !strings.Contains(out, "no-progress") || !strings.Contains(out, "report: no work completed") || m.calls != 3 {
		t.Fatalf("out=%q calls=%d err=%v", out, m.calls, err)
	}
}

func TestEngageConvergenceOrchestratorModelOverride(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_ORCHESTRATOR_MODEL", " larger-model ")
	m := &convergenceModel{fakeModel: fakeModel{queue: []*llms.ContentResponse{
		callResp("c1", "plan_add", `{"id":"t1","kind":"web","target":"10.0.0.5","objective":"inspect login"}`),
		callResp("c2", "dispatch_agent", `{"task_id":"t1"}`),
		textResp("executor done"),
		textResp("orchestrator done"),
	}}}
	out, err := runOrchestrator(context.Background(), testDeps(t, m), "assess target")
	if err != nil || out != "orchestrator done" || len(m.opts) != 4 {
		t.Fatalf("out=%q calls=%d err=%v", out, m.calls, err)
	}
	for i, want := range []string{"larger-model", "larger-model", "", "larger-model"} {
		if m.opts[i].Model != want {
			t.Errorf("call %d model=%q want=%q", i, m.opts[i].Model, want)
		}
	}
}
