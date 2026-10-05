package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"

	"github.com/tmc/langchaingo/llms"
)

func TestEngageTotalWorkBudgetStopsBeforeAnotherModelCall(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_MAX_ACTIONS", "2")
	t.Setenv("BLKCHAIN_ENGAGE_MAX_ROUNDS", "20")
	m := &fakeModel{queue: []*llms.ContentResponse{
		callResp("c1", "plan_add", `{"id":"t1","kind":"web","target":"192.0.2.1","objective":"inspect"}`),
		callResp("c2", "plan_add", `{"id":"t2","kind":"web","target":"192.0.2.1","objective":"retry"}`),
	}}
	d := testDeps(t, m)
	out, err := runOrchestrator(context.Background(), d, "inspect target")
	if err != nil || m.calls != 1 || !strings.Contains(out, "work budget") || !strings.Contains(out, "t1") {
		t.Fatalf("model_calls=%d output=%q err=%v", m.calls, out, err)
	}
	if _, err := d.Store.GetTask("t2"); err == nil {
		t.Fatal("second task ran after total work budget")
	}
}

type waitingBudgetModel struct{}

func (waitingBudgetModel) GenerateContent(ctx context.Context, _ []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestEngageWallBudgetStopsWaitingModel(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_WALL_SECONDS", "1")
	d := testDeps(t, waitingBudgetModel{})
	start := time.Now()
	out, err := runOrchestrator(context.Background(), d, "inspect target")
	if err != nil || !strings.Contains(out, "wall-clock budget reached") || time.Since(start) > 3*time.Second {
		t.Fatalf("elapsed=%s output=%q err=%v", time.Since(start), out, err)
	}
}

func TestEngageBudgetEnvironmentOverridesProjectDefault(t *testing.T) {
	check := func(want int) {
		t.Helper()
		ctx, stop := engageBudgetContext(context.Background(), 2, 120)
		defer stop()
		for i := 0; i < want; i++ {
			if err := consumeEngageWork(ctx); err != nil {
				t.Fatalf("action %d denied early: %v", i+1, err)
			}
		}
		if err := consumeEngageWork(ctx); err != errEngageWorkBudget {
			t.Fatalf("action %d err=%v", want+1, err)
		}
	}
	check(2)
	t.Setenv("BLKCHAIN_ENGAGE_MAX_ACTIONS", "3")
	check(3)
}

func TestEngageBudgetBoundsReturnedReport(t *testing.T) {
	d := testDeps(t, nil)
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Kind: "web", Objective: strings.Repeat("x", 100000), Status: engagement.StatusTodo}}}); err != nil {
		t.Fatal(err)
	}
	ctx, stop := engageBudgetContext(context.Background(), 1, 60)
	defer stop()
	if err := consumeEngageWork(ctx); err != nil {
		t.Fatal(err)
	}
	if err := consumeEngageWork(ctx); err != errEngageWorkBudget {
		t.Fatal(err)
	}
	final, stopped, err := engageBudgetStop(ctx, d.Store, "inspect target")
	if err != nil || !stopped || len([]rune(final)) > 65650 || !strings.Contains(final, "[report truncated;") {
		t.Fatalf("length=%d stopped=%t err=%v", len([]rune(final)), stopped, err)
	}
}
