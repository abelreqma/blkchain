package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"github.com/tmc/langchaingo/llms"
)

func TestEngageTelemetryDenialBurstHalts(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	tm := newEngageTelemetry(ws, cancel)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tm.now = func() time.Time { return now }
	for i := 0; i < 7; i++ {
		tm.gate("deny:scope", "out of scope")
	}
	if ctx.Err() != nil {
		t.Fatal("engagement stopped before the denial threshold")
	}
	tm.gate("deny:scope", "out of scope")
	if !errors.Is(context.Cause(ctx), errEngageDenialBurst) {
		t.Fatalf("stop cause=%v", context.Cause(ctx))
	}
	data, err := os.ReadFile(filepath.Join(ws.Dir, "audit.jsonl"))
	if err != nil || !strings.Contains(string(data), `"kind":"anomaly","outcome":"halted","reason_code":"denial-burst"`) {
		t.Fatalf("anomaly audit err=%v data=%q", err, data)
	}
}

func TestEngageTelemetryDenialWindowResets(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	tm := newEngageTelemetry(ws, cancel)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tm.now = func() time.Time { return now }
	for i := 0; i < 7; i++ {
		tm.gate("deny:scope", "out of scope")
	}
	now = now.Add(time.Minute + time.Second)
	tm.gate("deny:scope", "out of scope")
	if ctx.Err() != nil {
		t.Fatalf("old denials counted in new window: %v", context.Cause(ctx))
	}
}

func TestEngageTelemetryIgnoresCanceledGateChecks(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	tm := newEngageTelemetry(ws, cancel)
	for i := 0; i < 8; i++ {
		tm.gate("deny:context", "command canceled")
	}
	if ctx.Err() != nil {
		t.Fatalf("cancellation denials caused anomaly: %v", context.Cause(ctx))
	}
}

func TestEngageTelemetryIgnoresInternalProbeDenials(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	tm := newEngageTelemetry(ws, cancel)
	for i := 0; i < 8; i++ {
		tm.gate("probe-deny:scope", "help probe denied")
	}
	if ctx.Err() != nil {
		t.Fatalf("internal probes caused anomaly: %v", context.Cause(ctx))
	}
}

func TestEngageTelemetryAnomalyAuditFailureStopsWithWriteError(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	tm := newEngageTelemetry(ws, cancel)
	writeErr := errors.New("audit disk unavailable")
	tm.write = func(actor, action, detail string) error {
		if action == "anomaly-denial-burst" {
			return writeErr
		}
		return ws.AuditLine(actor, action, detail)
	}
	for i := 0; i < 8; i++ {
		tm.gate("deny:scope", "out of scope")
	}
	if !errors.Is(context.Cause(ctx), writeErr) || errors.Is(context.Cause(ctx), errEngageDenialBurst) {
		t.Fatalf("stop cause=%v", context.Cause(ctx))
	}
}

func TestEngageTelemetryHaltsGateAfterDenialBurst(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	tm := newEngageTelemetry(ws, cancel)
	scope, err := secgate.ParseScope(strings.NewReader("192.0.2.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	gate := buildEngageGate(ws, scope, secgate.Auto, nil, nil, t.TempDir(), gatePolicy{}, tm.gate)
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if d := gate.Authorize(ctx, secgate.Command{Binary: "nmap", Args: []string{"198.51.100.2"}}); d.Allowed {
			t.Fatal("out-of-scope command was allowed")
		}
	}
	if !errors.Is(context.Cause(ctx), errEngageDenialBurst) {
		t.Fatalf("stop cause=%v", context.Cause(ctx))
	}
}

func TestEngageTelemetryRecordsModelAndToolDecisions(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	tm := newEngageTelemetry(ws, func(error) {})
	m := &fakeModel{queue: []*llms.ContentResponse{
		callResp("c1", "plan_add", `{"id":"t1","kind":"web","target":"192.0.2.1","objective":"inspect"}`),
		textResp("inspection planned"),
	}}
	d := testDeps(t, m)
	if _, err := runOrchestrator(withEngageTelemetry(context.Background(), tm), d, "inspect"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(ws.Dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"model-tools", "tool-call", "tool-result", "model-final"} {
		if !strings.Contains(string(data), `"action":"`+action+`"`) {
			t.Fatalf("missing %s in %q", action, data)
		}
	}
}

func TestEngageTelemetryReachesNestedToolLoop(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	tm := newEngageTelemetry(ws, func(error) {})
	ctx := withEngageTelemetry(context.Background(), tm)
	m := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "echo", `{}`), textResp("done")}}
	echo := &fakeTool{name: "echo", fn: func(string) (string, error) { return "ok", nil }}
	if _, _, err := runToolLoop(ctx, m, newLoopReg(t, echo), userMsgs(), LoopCaps{MaxRounds: 3, MaxCalls: 2}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(ws.Dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"model-tools", "tool-call", "tool-result", "model-final"} {
		if !strings.Contains(string(data), `"action":"`+action+`"`) {
			t.Fatalf("missing %s in nested loop audit: %q", action, data)
		}
	}
}

func TestNestedAuditFailureStopsOuterLoop(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	ctx = withEngageTelemetry(ctx, newEngageTelemetry(ws, cancel))
	inner := &fakeModel{queue: []*llms.ContentResponse{textResp("inner done")}}
	tool := &fakeTool{name: "nested", fn: func(string) (string, error) {
		path := filepath.Join(ws.Dir, "audit.jsonl")
		if err := os.Rename(path, path+".saved"); err != nil {
			return "", err
		}
		if err := os.Mkdir(path, 0700); err != nil {
			return "", err
		}
		_, _, err := runToolLoop(ctx, inner, newLoopReg(t), userMsgs(), LoopCaps{MaxRounds: 1})
		return "", err
	}}
	outer := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "nested", `{}`), textResp("outer continued")}}
	_, _, err = runToolLoop(ctx, outer, newLoopReg(t, tool), userMsgs(), LoopCaps{MaxRounds: 3})
	if err == nil || context.Cause(ctx) == nil || outer.calls != 1 || inner.calls != 1 {
		t.Fatalf("err=%v cause=%v outer=%d inner=%d", err, context.Cause(ctx), outer.calls, inner.calls)
	}
}
