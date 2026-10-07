package main

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestOrchestratorPromptMentionsReconFirstBatchAndBasisIDs(t *testing.T) {
	for _, want := range []string{"dispatch_batch", "basis_ids", "recon", "breadth"} {
		if !strings.Contains(orchestratorSystemPrompt, want) {
			t.Errorf("orchestratorSystemPrompt missing %q:\n%s", want, orchestratorSystemPrompt)
		}
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
		toolCallResp("c1", "plan_add", `{"id":"t1","kind":"recon","target":"10.0.0.5","objective":"enumerate","done_when":"an open service is listed"}`),
		toolCallResp("c2", "dispatch_agent", `{"task_id":"t1"}`),
		// executor turn (runs within dispatch_agent): record evidence, then finish.
		toolCallResp("c2e", "record_evidence", `{"task_id":"t1","quote":"22/tcp open ssh"}`),
		finalResp("executor: found ssh on 22"),
		// back in the orchestrator:
		toolCallResp("c3", "plan_complete", `{"id":"t1","basis":"the quote lists 22/tcp open","evidence_ids":[1]}`),
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

// TestRegisterOnApplyListenerFiresInOrchestrator pins the multi-flow listener
// seam: a listener registered via registerOnApply is attached by runOrchestrator
// (the CLI/REPL/MCP funnel) and fires on a committed Apply, with zero shared
// edits beyond the init() registration.
func TestRegisterOnApplyListenerFiresInOrchestrator(t *testing.T) {
	// Isolate the registry so this test neither sees nor leaves registrations.
	saved := onApplyListeners
	t.Cleanup(func() { onApplyListeners = saved })
	onApplyListeners = nil

	var mu sync.Mutex
	fired := 0
	var lastRev int64
	registerOnApply(func(rev int64, e engagement.Engagement) {
		mu.Lock()
		fired++
		lastRev = rev
		mu.Unlock()
	})

	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{
		toolCallResp("c1", "plan_add", `{"id":"t1","kind":"recon","target":"10.0.0.5","objective":"enumerate"}`),
		finalResp("done"),
	}})
	if _, err := runOrchestrator(context.Background(), d, "assess 10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if fired == 0 {
		t.Fatal("listener registered via registerOnApply did not fire during runOrchestrator")
	}
	if lastRev == 0 {
		t.Errorf("listener fired with rev=0, want the committed revision")
	}
}

func TestExecutorRunsCommandAndRecordsEvidence(t *testing.T) {
	d := testDeps(t, nil)
	// seed an active task
	name, active := "eng", "t1"
	stage := engagement.Stage{Label: "dispatch", Tool: "recon"}
	if _, err := d.Store.Apply(engagement.Delta{
		Upserts: []engagement.Task{{ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "scan", Status: engagement.StatusActive}},
		SetName: &name, SetActiveID: &active, SetStage: &stage, Kind: "init",
	}); err != nil {
		t.Fatal(err)
	}
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		return runResult{Output: "22/tcp open ssh"}
	})
	// executor: run_command, then record_evidence a real quote, then finish.
	exec := &scriptModel{resps: []*llms.ContentResponse{
		toolCallResp("c1", "run_command", `{"binary":"nmap","args":["-p","22","10.0.0.5"]}`),
		toolCallResp("c2", "record_evidence", `{"task_id":"t1","quote":"22/tcp open"}`),
		finalResp("found ssh"),
	}}
	d.Model = exec
	out, err := runExecutor(context.Background(), d, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ssh") {
		t.Errorf("executor final: %q", out)
	}
	ev, _ := d.Store.EvidenceFor("t1")
	if len(ev) != 1 {
		t.Errorf("evidence rows = %d, want 1 (verified real quote)", len(ev))
	}
}

func TestNewExecutorScratchDirDistinctPerCall(t *testing.T) {
	root := t.TempDir()
	dir1, cleanup1, err := newExecutorScratchDir(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup1()
	dir2, cleanup2, err := newExecutorScratchDir(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup2()
	if dir1 == dir2 {
		t.Fatalf("scratch dirs collide: %q", dir1)
	}
	if _, err := os.Stat(dir1); err != nil {
		t.Errorf("dir1 missing: %v", err)
	}
	if _, err := os.Stat(dir2); err != nil {
		t.Errorf("dir2 missing: %v", err)
	}
}

func TestNewExecutorScratchDirEmptyRootNoScratch(t *testing.T) {
	dir, cleanup, err := newExecutorScratchDir(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if dir != "" {
		t.Errorf("dir = %q, want empty when root is empty", dir)
	}
}

func TestNewExecutorScratchDirConcurrentDistinct(t *testing.T) {
	root := t.TempDir()
	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	dirs := make(map[string]bool)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dir, cleanup, err := newExecutorScratchDir(context.Background(), root)
			if err != nil {
				errs <- err
				return
			}
			defer cleanup()
			mu.Lock()
			dirs[dir] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if len(dirs) != n {
		t.Errorf("got %d distinct scratch dirs, want %d", len(dirs), n)
	}
}

func TestMarkTaskActiveSetsStatusPreservesFields(t *testing.T) {
	task := engagement.Task{ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "scan", Status: engagement.StatusTodo}
	got := markTaskActive(task)
	if got.Status != engagement.StatusActive {
		t.Errorf("Status = %q, want active", got.Status)
	}
	if got.ID != task.ID || got.Kind != task.Kind || got.Target != task.Target || got.Objective != task.Objective {
		t.Errorf("markTaskActive changed unrelated fields: %+v", got)
	}
}

func TestDispatchAgentSetsTaskStatusActive(t *testing.T) {
	d := testDeps(t, nil)
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Kind: "web", Target: "10.0.0.5", Objective: "login", Status: engagement.StatusTodo}}}); err != nil {
		t.Fatal(err)
	}
	// Executor never completes the task, so its status reflects dispatch alone.
	exec := &scriptModel{resps: []*llms.ContentResponse{
		finalResp("executor summary: nothing to report"),
	}}
	d.Model = exec
	if _, err := newDispatchAgentTool(d).Call(context.Background(), `{"task_id":"t1"}`); err != nil {
		t.Fatal(err)
	}
	got, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != engagement.StatusActive {
		t.Errorf("Status = %q, want active", got.Status)
	}
}

func TestOrchestratorRejectsFabricatedEvidenceWithRuns(t *testing.T) {
	d := testDeps(t, nil)
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	// The orchestrator invents a quote no executor captured, then tries to
	// complete the task. Both must fail.
	d.Model = &scriptModel{resps: []*llms.ContentResponse{
		toolCallResp("c1", "plan_add", `{"id":"t1","kind":"recon","target":"10.0.0.5","objective":"enumerate","done_when":"an open service is listed"}`),
		toolCallResp("c2", "record_evidence", `{"task_id":"t1","quote":"made up ssh banner"}`),
		toolCallResp("c3", "plan_complete", `{"id":"t1","basis":"the banner names ssh","evidence_ids":[1]}`),
		finalResp("stopped"),
	}}
	if _, err := runOrchestrator(context.Background(), d, "assess 10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	if ev, _ := d.Store.EvidenceFor("t1"); len(ev) != 0 {
		t.Errorf("fabricated evidence stored: %v", ev)
	}
	got, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status == engagement.StatusDone {
		t.Error("task must not complete without real evidence")
	}
}

// An executor's scratch cleanup also releases that task's runner workers, so a
// long engagement cannot exhaust the eight-worker pool. The release belongs to
// the one helper every executor already calls rather than to a second deferred
// call each executor has to remember.
func TestExecutorScratchCleanupReleasesRunnerWorkers(t *testing.T) {
	r := &engageRunner{workers: map[string]string{}, rawWorkers: map[string]string{}}
	var removed []string
	r.remove = func(_ context.Context, id string) error {
		removed = append(removed, id)
		return nil
	}
	ctx := context.WithValue(context.Background(), engageRuntimeKey{}, &engageRuntime{runner: r})
	dir, cleanup, err := newExecutorScratchDir(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r.workers[dir] = "worker"
	r.rawWorkers[dir] = "rawworker"

	cleanup()

	if len(r.workers) != 0 || len(r.rawWorkers) != 0 {
		t.Errorf("cleanup left workers in the pool: %v %v", r.workers, r.rawWorkers)
	}
	if !slices.Contains(removed, "worker") || !slices.Contains(removed, "rawworker") {
		t.Errorf("removed = %v, want both workers removed", removed)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("cleanup left the scratch dir behind: %v", err)
	}
}
