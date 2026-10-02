package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"

	"github.com/tmc/langchaingo/llms"
)

func TestGenericExecutorPromptIsImperative(t *testing.T) {
	for _, want := range []string{"EXECUTING", "run_command", "plan_add"} {
		if !strings.Contains(executorPreamble, want) {
			t.Errorf("executorPreamble missing %q:\n%s", want, executorPreamble)
		}
	}
	p := genericTaskPrompt("state", engagement.Task{ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "enumerate", DoneWhen: "done"})
	for _, want := range []string{"run_command", "Execute this task now", "attack hypothesis", "basis_ids", "Do not call plan_add"} {
		if !strings.Contains(p, want) {
			t.Errorf("genericTaskPrompt missing %q:\n%s", want, p)
		}
	}
}

func TestExecutorForReturnsRunnableForEverySurface(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	for _, s := range engagement.AllSurfaces() {
		task := engagement.Task{ID: "t", Surface: s, Kind: "recon"}
		if ex := executorFor(d, task); ex == nil {
			t.Errorf("executorFor(surface=%q) = nil, want a surfaceExecutor", s)
		}
	}
}

type stubSurfaceExecutor struct{}

func (stubSurfaceExecutor) Run(ctx context.Context, task engagement.Task) (string, error) {
	return "stub", nil
}

// TestExecutorForUsesRegisteredFactory pins the registration seam: a factory
// registered for a surface is used by executorFor, and an unregistered surface
// still falls back to genericExecutor (today's behavior, since nothing registers).
func TestExecutorForUsesRegisteredFactory(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	const s = engagement.Surface("registry-test-surface")
	registerExecutor(s, func(engageDeps) surfaceExecutor { return stubSurfaceExecutor{} })
	t.Cleanup(func() { delete(surfaceExecutors, s) })

	if ex := executorFor(d, engagement.Task{ID: "t", Surface: s, Kind: "recon"}); ex == nil {
		t.Fatal("executorFor(registered surface) = nil")
	} else if _, ok := ex.(stubSurfaceExecutor); !ok {
		t.Fatalf("executorFor(registered surface) = %T, want stubSurfaceExecutor", ex)
	}

	other := executorFor(d, engagement.Task{ID: "t2", Surface: engagement.Surface("registry-fallback-probe-surface"), Kind: "recon"})
	if _, ok := other.(genericExecutor); !ok {
		t.Fatalf("executorFor(unregistered surface) = %T, want genericExecutor fallback", other)
	}
}

func TestRunBatchSurfaceExecutorsRaceClean(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_PARALLEL", "4")
	d := testDeps(t, perTaskModel{})
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		return runResult{Output: "22/tcp open banner-for-" + args[len(args)-1]}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{
		{ID: "t1", Kind: "recon", Surface: engagement.SurfaceNetwork, Target: "10.0.0.5", Objective: "scan", Status: engagement.StatusTodo},
		{ID: "t2", Kind: "recon", Surface: engagement.SurfaceNetwork, Target: "10.0.0.6", Objective: "scan", Status: engagement.StatusTodo},
	}}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make([]string, 2)
	for i, id := range []string{"t1", "t2"} {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			out, _ := runExecutor(context.Background(), d, id)
			results[i] = out
		}(i, id)
	}
	wg.Wait()
	joined := results[0] + results[1]
	if !strings.Contains(joined, "done t1") || !strings.Contains(joined, "done t2") {
		t.Errorf("both executors should finish via executorFor path: %q", results)
	}
}

func TestVantageGatesInternalSurface(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	ext := engagement.VantageExternalUnauth
	if _, err := d.Store.Apply(engagement.Delta{SetVantage: &ext}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{
		{ID: "t1", Kind: "target-analysis", Surface: engagement.SurfaceLocal, Objective: "assess", Status: engagement.StatusTodo},
	}}); err != nil {
		t.Fatal(err)
	}
	out, _ := runExecutor(context.Background(), d, "t1")
	if !strings.Contains(strings.ToLower(out), "vantage") {
		t.Errorf("local surface at external vantage: out=%q, want a vantage refusal", out)
	}
	foot := engagement.VantageInternalFoothold
	if _, err := d.Store.Apply(engagement.Delta{SetVantage: &foot}); err != nil {
		t.Fatal(err)
	}
	out2, _ := runExecutor(context.Background(), d, "t1")
	if strings.Contains(strings.ToLower(out2), "vantage") {
		t.Errorf("local surface after advance to foothold: out=%q, should no longer refuse on vantage", out2)
	}
}

func TestVantageAllowsExternalSurface(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	ext := engagement.VantageExternalUnauth
	if _, err := d.Store.Apply(engagement.Delta{SetVantage: &ext}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{
		{ID: "t1", Kind: "cloud", Surface: engagement.SurfaceCloud, Objective: "enumerate", Status: engagement.StatusTodo},
	}}); err != nil {
		t.Fatal(err)
	}
	out, _ := runExecutor(context.Background(), d, "t1")
	if strings.Contains(strings.ToLower(out), "vantage") {
		t.Errorf("cloud surface at external-unauth: out=%q, should NOT refuse on vantage", out)
	}
}

func TestVantageUnsetDoesNotGate(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{
		{ID: "t1", Kind: "target-analysis", Surface: engagement.SurfaceLocal, Objective: "assess", Status: engagement.StatusTodo},
	}}); err != nil {
		t.Fatal(err)
	}
	out, _ := runExecutor(context.Background(), d, "t1")
	if strings.Contains(strings.ToLower(out), "vantage") {
		t.Errorf("unset vantage must not gate: out=%q", out)
	}
}

func TestGenericExecutorGroundsBeforeExec(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{
		toolCallResp("c1", "run_command", `{"binary":"nmap","args":["--pwn","10.0.0.5"]}`),
		finalResp("done"),
	}})
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	cache := &stubCache{}
	_ = cache.Store("nmap", resolveBinVersion("nmap"), toolInterface{Flags: []string{"-sV"}})
	d.ToolHelp = cache

	ran := false
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		ran = true
		return runResult{Output: "should not run"}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{
		{ID: "t1", Kind: "recon", Surface: engagement.SurfaceNetwork, Target: "10.0.0.5", Objective: "scan", Status: engagement.StatusTodo},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := runExecutor(context.Background(), d, "t1"); err != nil {
		t.Fatal(err)
	}
	if ran {
		t.Fatal("grounding must reject the hallucinated flag before execRunner runs")
	}
}
