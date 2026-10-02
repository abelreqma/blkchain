package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"

	"github.com/tmc/langchaingo/llms"
)

// perTaskModel is a stateless, concurrency-safe executor model. It reads the
// task id from the human message and the turn from the number of tool results
// so far: run_command against that task's own host, then record_evidence with a
// quote from that host's output, then a final answer.
type perTaskModel struct{}

var perTaskHost = map[string]string{"t1": "10.0.0.5", "t2": "10.0.0.6"}

func (perTaskModel) GenerateContent(ctx context.Context, msgs []llms.MessageContent, opts ...llms.CallOption) (*llms.ContentResponse, error) {
	var task string
	toolTurns := 0
	for _, m := range msgs {
		if m.Role == llms.ChatMessageTypeTool {
			toolTurns++
		}
		if m.Role != llms.ChatMessageTypeHuman {
			continue
		}
		for _, p := range m.Parts {
			if tc, ok := p.(llms.TextContent); ok {
				if i := strings.Index(tc.Text, "Your task "); i >= 0 {
					task = strings.Fields(tc.Text[i+len("Your task "):])[0]
				}
			}
		}
	}
	host := perTaskHost[task]
	switch toolTurns {
	case 0:
		return toolCallResp("c1", "run_command", `{"binary":"nmap","args":["-p","22","`+host+`"]}`), nil
	case 1:
		return toolCallResp("c2", "record_evidence", `{"task_id":"`+task+`","quote":"banner-for-`+host+`"}`), nil
	}
	return finalResp("done " + task), nil
}

// Regression: under dispatch_batch no global active_id is set, so the real
// runExecutor must key its command capture on the executor's own task id.
// Otherwise every capture is dropped and verified record_evidence rejects all.
func TestDispatchBatchRealExecutorCapturesPerTaskEvidence(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_PARALLEL", "2")
	d := testDeps(t, perTaskModel{})
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		return runResult{Output: "22/tcp open banner-for-" + args[len(args)-1]}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{
		{ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "scan", Status: engagement.StatusTodo},
		{ID: "t2", Kind: "recon", Target: "10.0.0.6", Objective: "scan", Status: engagement.StatusTodo},
	}}); err != nil {
		t.Fatal(err)
	}

	out, err := newDispatchBatchTool(d).Call(context.Background(), `{"task_ids":["t1","t2"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "done t1") || !strings.Contains(out, "done t2") {
		t.Fatalf("both executors should finish:\n%s", out)
	}

	snap, err := d.Store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.ActiveID != "" {
		t.Fatalf("precondition: global active_id = %q, want unset", snap.ActiveID)
	}
	for id, host := range perTaskHost {
		other := "t1"
		if id == "t1" {
			other = "t2"
		}
		own, foreign := "banner-for-"+host, "banner-for-"+perTaskHost[other]
		if !d.Runs.Contains(id, own) {
			t.Errorf("task %s: own output not captured under its id", id)
		}
		if d.Runs.Contains(id, foreign) {
			t.Errorf("task %s: output of %s cross-attributed", id, other)
		}
		if d.Runs.Contains("", own) {
			t.Errorf("task %s: output captured under empty task id", id)
		}
		ev, err := d.Store.EvidenceFor(id)
		if err != nil {
			t.Fatal(err)
		}
		if len(ev) != 1 {
			t.Errorf("task %s: evidence rows = %d, want 1", id, len(ev))
		}
	}
}

func TestDispatchBatchSkipsNATask(t *testing.T) {
	d := testDeps(t, nil)
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{
		{ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "scan", Status: engagement.StatusNA},
	}}); err != nil {
		t.Fatal(err)
	}
	var ran atomic.Int32
	exec := func(ctx context.Context, d engageDeps, id string) (string, error) {
		ran.Add(1)
		return id, nil
	}
	out, err := newDispatchBatchToolWith(d, exec).Call(context.Background(), `{"task_ids":["t1"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if ran.Load() != 0 || !strings.Contains(out, "not applicable") {
		t.Errorf("na task must be skipped with a note: ran=%d out=%q", ran.Load(), out)
	}
	if got, _ := d.Store.GetTask("t1"); got.Status != engagement.StatusNA {
		t.Errorf("na task status = %q, want unchanged", got.Status)
	}
}

// TestDispatchBatchSkipsBlockedTask enforces the citation-gate: the model
// must NOT auto-dispatch a non-actionable coverage-gap candidate (Status
// blocked). Removing the skip in orchestrator.go makes this test dispatch the
// blocked task and fail (the adversarial direction).
func TestDispatchBatchSkipsBlockedTask(t *testing.T) {
	d := testDeps(t, nil)
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{
		{ID: "t1", Kind: "exploit", Target: "10.0.0.5:22", Objective: "uncited coverage-gap",
			Status: engagement.StatusBlocked, Phase: engagement.PhaseExploit, CoverageGap: true},
	}}); err != nil {
		t.Fatal(err)
	}
	var ran atomic.Int32
	exec := func(ctx context.Context, d engageDeps, id string) (string, error) {
		ran.Add(1)
		return id, nil
	}
	out, err := newDispatchBatchToolWith(d, exec).Call(context.Background(), `{"task_ids":["t1"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if ran.Load() != 0 {
		t.Errorf("a blocked coverage-gap candidate must NOT be dispatched: ran=%d", ran.Load())
	}
	if !strings.Contains(out, "blocked") {
		t.Errorf("blocked task must be skipped with a note: out=%q", out)
	}
	if got, _ := d.Store.GetTask("t1"); got.Status != engagement.StatusBlocked {
		t.Errorf("blocked task status = %q, want unchanged (not marked active)", got.Status)
	}
}

func TestEngageParallelClamp(t *testing.T) {
	cases := []struct {
		env  string
		want int
	}{
		{"", 3},
		{"abc", 3},
		{"0", 1},
		{"-4", 1},
		{"5", 5},
		{"99", 8},
	}
	for _, c := range cases {
		t.Setenv("BLKCHAIN_ENGAGE_PARALLEL", c.env)
		if got := engageParallel(); got != c.want {
			t.Errorf("BLKCHAIN_ENGAGE_PARALLEL=%q: engageParallel() = %d, want %d", c.env, got, c.want)
		}
	}
}

func stubExec(ctx context.Context, d engageDeps, id string) (string, error) {
	return "result-" + id, nil
}

func TestRunBatchRunsAllAndSortsByID(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_PARALLEL", "2")
	var mu sync.Mutex
	ran := map[string]int{}
	exec := func(ctx context.Context, d engageDeps, id string) (string, error) {
		mu.Lock()
		ran[id]++
		mu.Unlock()
		// Finish in reverse id order to prove sorting is not completion order.
		if id == "a" {
			time.Sleep(30 * time.Millisecond)
		}
		return "result-" + id, nil
	}
	got := runBatch(context.Background(), engageDeps{}, []string{"c", "a", "b"}, exec)
	if len(got) != 3 {
		t.Fatalf("got %d results, want 3", len(got))
	}
	for i, id := range []string{"a", "b", "c"} {
		if got[i].TaskID != id || got[i].Result != "result-"+id || got[i].Err != nil {
			t.Errorf("results[%d] = %+v, want task %s", i, got[i], id)
		}
	}
	for _, id := range []string{"a", "b", "c"} {
		if ran[id] != 1 {
			t.Errorf("task %s ran %d times, want 1", id, ran[id])
		}
	}
}

func TestRunBatchNeverExceedsCap(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_PARALLEL", "2")
	var inFlight, maxSeen, total atomic.Int32
	exec := func(ctx context.Context, d engageDeps, id string) (string, error) {
		n := inFlight.Add(1)
		for {
			m := maxSeen.Load()
			if n <= m || maxSeen.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		inFlight.Add(-1)
		total.Add(1)
		return id, nil
	}
	ids := []string{"t1", "t2", "t3", "t4", "t5", "t6", "t7"}
	got := runBatch(context.Background(), engageDeps{}, ids, exec)
	if len(got) != len(ids) || int(total.Load()) != len(ids) {
		t.Fatalf("results=%d total=%d, want %d", len(got), total.Load(), len(ids))
	}
	if maxSeen.Load() > 2 {
		t.Errorf("max in flight = %d, want <= 2", maxSeen.Load())
	}
	if maxSeen.Load() < 2 {
		t.Errorf("max in flight = %d, want 2 (executors did not overlap)", maxSeen.Load())
	}
}

func TestRunBatchCapOfOneIsSerial(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_PARALLEL", "1")
	var inFlight, maxSeen atomic.Int32
	exec := func(ctx context.Context, d engageDeps, id string) (string, error) {
		n := inFlight.Add(1)
		if n > maxSeen.Load() {
			maxSeen.Store(n)
		}
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
		return id, nil
	}
	runBatch(context.Background(), engageDeps{}, []string{"a", "b", "c"}, exec)
	if maxSeen.Load() != 1 {
		t.Errorf("max in flight = %d, want 1", maxSeen.Load())
	}
}

func TestRunBatchRecordsErrorsAndPanics(t *testing.T) {
	exec := func(ctx context.Context, d engageDeps, id string) (string, error) {
		switch id {
		case "bad":
			return "", errors.New("boom")
		case "panic":
			panic("kaboom")
		}
		return "ok", nil
	}
	got := runBatch(context.Background(), engageDeps{}, []string{"panic", "ok", "bad"}, exec)
	if len(got) != 3 {
		t.Fatalf("got %d results, want 3", len(got))
	}
	if got[0].TaskID != "bad" || got[0].Err == nil {
		t.Errorf("results[0] = %+v, want bad with error", got[0])
	}
	if got[1].TaskID != "ok" || got[1].Err != nil || got[1].Result != "ok" {
		t.Errorf("results[1] = %+v, want ok", got[1])
	}
	if got[2].TaskID != "panic" || got[2].Err == nil {
		t.Errorf("results[2] = %+v, want panic converted to error", got[2])
	}
}

func TestRunBatchCanceledContext(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_PARALLEL", "1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var ran atomic.Int32
	exec := func(ctx context.Context, d engageDeps, id string) (string, error) {
		ran.Add(1)
		return id, nil
	}
	got := runBatch(ctx, engageDeps{}, []string{"a", "b"}, exec)
	if len(got) != 2 {
		t.Fatalf("got %d results, want 2", len(got))
	}
	for _, r := range got {
		if r.Err == nil && r.Result == "" {
			t.Errorf("result %+v has neither output nor error", r)
		}
	}
}

// The shared gate budget must hold across concurrent executors: N execs each
// spending one command against a cap of 3 allow exactly 3.
func TestRunBatchSharesGateBudget(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_PARALLEL", "4")
	s, err := secgate.ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Local scope requires per-command confirmation; an approving confirmer lets
	// commands through so the shared episode budget (the subject here) bounds them.
	g := &secgate.Gate{
		Mode:    secgate.Auto,
		Scope:   s,
		Allow:   secgate.NewAllowlist("id"),
		Confirm: &countingConfirmer{ok: true},
		Episode: secgate.NewEpisode(secgate.Caps{MaxCommands: 3}, nil),
	}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	d := engageDeps{Gate: g}
	var allowed atomic.Int32
	exec := func(ctx context.Context, d engageDeps, id string) (string, error) {
		if d.Gate.Authorize(ctx, secgate.Command{Binary: "id"}).Allowed {
			allowed.Add(1)
		}
		return id, nil
	}
	ids := []string{"t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8"}
	got := runBatch(context.Background(), d, ids, exec)
	if len(got) != len(ids) {
		t.Fatalf("got %d results, want %d", len(got), len(ids))
	}
	if allowed.Load() != 3 {
		t.Errorf("allowed = %d, want exactly 3 (shared budget)", allowed.Load())
	}
}

func seedBatchTasks(t *testing.T, d engageDeps) {
	t.Helper()
	tasks := []engagement.Task{
		{ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "enumerate", Status: engagement.StatusTodo},
		{ID: "t2", Kind: "web", Target: "10.0.0.5", Objective: "login", Status: engagement.StatusTodo},
		{ID: "t3", Kind: "recon", Target: "10.0.0.6", Objective: "enumerate", Status: engagement.StatusTodo},
		{ID: "tD", Kind: "recon", Target: "10.0.0.7", Objective: "done already", Status: engagement.StatusDone},
	}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: tasks}); err != nil {
		t.Fatal(err)
	}
}

func TestDispatchBatchToolRejectsBadInput(t *testing.T) {
	d := testDeps(t, nil)
	tool := newDispatchBatchToolWith(d, stubExec)

	out, err := tool.Call(context.Background(), `{"task_ids":[]}`)
	if err != nil || !strings.Contains(out, "task_ids is required") {
		t.Errorf("empty list: out=%q err=%v", out, err)
	}
	out, err = tool.Call(context.Background(), `not json`)
	if err != nil || !strings.Contains(out, "invalid arguments") {
		t.Errorf("bad json: out=%q err=%v", out, err)
	}
	ids := make([]string, 0, maxBatchTasks+1)
	for i := 0; i <= maxBatchTasks; i++ {
		ids = append(ids, fmt.Sprintf("%q", fmt.Sprintf("t%d", i)))
	}
	out, err = tool.Call(context.Background(), `{"task_ids":[`+strings.Join(ids, ",")+`]}`)
	if err != nil || !strings.Contains(out, "too many") {
		t.Errorf("over cap: out=%q err=%v", out, err)
	}
}

func TestDispatchBatchToolMarksActiveAndAggregatesSorted(t *testing.T) {
	d := testDeps(t, nil)
	seedBatchTasks(t, d)
	exec := func(ctx context.Context, d engageDeps, id string) (string, error) {
		// Every dispatched task must already be active when its executor starts.
		task, err := d.Store.GetTask(id)
		if err != nil || task.Status != engagement.StatusActive {
			return "", fmt.Errorf("task %s status = %q err=%v, want active", id, task.Status, err)
		}
		if id == "t2" {
			return "", errors.New("executor failed")
		}
		return "result-" + id, nil
	}
	tool := newDispatchBatchToolWith(d, exec)
	out, err := tool.Call(context.Background(), `{"task_ids":["t3","t1","nope","tD","t2","t1"]}`)
	if err != nil {
		t.Fatal(err)
	}

	// Sorted by task id: nope, t1, t2, t3, tD (byte order).
	order := []string{"== nope ==", "== t1 ==", "== t2 ==", "== t3 ==", "== tD =="}
	last := -1
	for _, h := range order {
		i := strings.Index(out, h)
		if i < 0 {
			t.Fatalf("output missing header %q:\n%s", h, out)
		}
		if i < last {
			t.Errorf("header %q out of order:\n%s", h, out)
		}
		last = i
	}
	if strings.Count(out, "== t1 ==") != 1 {
		t.Errorf("duplicate id ran or reported twice:\n%s", out)
	}
	for _, want := range []string{"result-t1", "result-t3", "executor failed", "not found", "already done"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	snap, err := d.Store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]engagement.Status{}
	for _, tk := range snap.Tasks {
		status[tk.ID] = tk.Status
	}
	for _, id := range []string{"t1", "t2", "t3"} {
		if status[id] != engagement.StatusActive {
			t.Errorf("task %s status = %q, want active", id, status[id])
		}
	}
	if status["tD"] != engagement.StatusDone {
		t.Errorf("done task status = %q, want done (untouched)", status["tD"])
	}
}

func TestDispatchBatchToolNoValidIDsRunsNothing(t *testing.T) {
	d := testDeps(t, nil)
	seedBatchTasks(t, d)
	var ran atomic.Int32
	exec := func(ctx context.Context, d engageDeps, id string) (string, error) {
		ran.Add(1)
		return id, nil
	}
	out, err := newDispatchBatchToolWith(d, exec).Call(context.Background(), `{"task_ids":["nope","tD"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if ran.Load() != 0 {
		t.Errorf("exec ran %d times, want 0", ran.Load())
	}
	if !strings.Contains(out, "not found") || !strings.Contains(out, "already done") {
		t.Errorf("output should note both ids:\n%s", out)
	}
}

func TestDispatchBatchRegisteredInOrchestrator(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: nil})
	tool := newDispatchBatchTool(d)
	if tool.Name() != "dispatch_batch" {
		t.Errorf("tool name = %q, want dispatch_batch", tool.Name())
	}
}
