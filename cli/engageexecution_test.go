package main

import (
	"blkchain/cli/internal/secgate"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRoEPipelineChecksEveryStageBeforeIsolatedExecution(t *testing.T) {
	roe, err := ParseRoE(strings.NewReader("## In Scope\n10.20.0.5\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, Policy: roe.Policy}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	trace := newActionTranscript(workspace, "off", "worker", 10, 65536, nil)
	if err := os.WriteFile(filepath.Join(workspace, "actions.jsonl"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	runner := &engageRunner{workers: map[string]string{}, runFn: func(_ context.Context, stages []pipelineStage, _ string, _ int, _ time.Duration) (runResult, []isolatedStageResult) {
		calls++
		if len(stages) != 2 {
			t.Fatalf("runner got %d pipeline stages", len(stages))
		}
		return runResult{Output: "pipeline-ok"}, []isolatedStageResult{{}, {Stdout: "pipeline-ok"}}
	}}
	ctx := context.WithValue(context.Background(), engageRuntimeKey{}, &engageRuntime{runner: runner, trace: trace, policy: roe.Policy, cancel: func() {}})
	tool := newRunCommandTool(g, 65536, time.Second, "worker", func() string { return "t1" }, nil)
	denied, err := tool.Call(ctx, `{"pipeline":[{"binary":"curl","args":["http://10.20.0.5"]},{"binary":"curl","args":["http://8.8.8.8"]}]}`)
	if err != nil || calls != 0 || !strings.Contains(denied, "out of scope") {
		t.Fatalf("denied pipeline ran: calls=%d result=%q err=%v", calls, denied, err)
	}
	allowed, err := tool.Call(ctx, `{"pipeline":[{"binary":"curl","args":["http://10.20.0.5"]},{"binary":"cat"}]}`)
	if err != nil || calls != 1 || !strings.Contains(allowed, "pipeline-ok") {
		t.Fatalf("permitted pipeline failed: calls=%d result=%q err=%v", calls, allowed, err)
	}
}

func TestRoEExecutionCannotFallBackToHost(t *testing.T) {
	p := secgate.DefaultPolicy()
	p.Allowed = []string{"local"}
	scope, _ := secgate.ParseScope(strings.NewReader("local\n"))
	g := &secgate.Gate{Mode: secgate.Auto, Scope: scope, Policy: p}
	calls := 0
	withStubExec(t, func(context.Context, string, []string, string, int, time.Duration) runResult {
		calls++
		return runResult{Output: "host"}
	})
	tool := newRunCommandTool(g, 65536, time.Second, t.TempDir(), func() string { return "t1" }, nil)
	out, err := tool.Call(context.Background(), `{"binary":"id"}`)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 || !strings.Contains(out, "isolated runner") {
		t.Fatalf("host fallback calls=%d result=%s", calls, out)
	}
}

func TestRoETimeoutRetainsCapturedOutput(t *testing.T) {
	withStubExec(t, func(context.Context, string, []string, string, int, time.Duration) runResult {
		return runResult{Output: "partial", TimedOut: true}
	})
	var captured string
	tool := newRunCommandTool(autoGate(t), 65536, time.Second, t.TempDir(), func() string { return "t1" }, func(_, out string) { captured = out })
	out, err := tool.Call(context.Background(), `{"binary":"curl","args":["http://10.0.0.5"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if captured != "partial" || !strings.Contains(out, "partial") {
		t.Fatalf("timeout dropped output capture=%q result=%q", captured, out)
	}
}
