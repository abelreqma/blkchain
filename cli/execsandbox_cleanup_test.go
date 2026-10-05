package main

import (
	"context"
	"errors"
	"testing"

	"github.com/tmc/langchaingo/llms"
)

type cleanupAtDeadlineModel struct{ cleanupErr error }

func (m cleanupAtDeadlineModel) GenerateContent(ctx context.Context, _ []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	<-ctx.Done()
	stopExecutorRun(ctx, m.cleanupErr)
	return nil, ctx.Err()
}

func TestExecutorCleanupFailureOverridesWallBudget(t *testing.T) {
	t.Setenv("BLKCHAIN_ENGAGE_WALL_SECONDS", "1")
	cleanupErr := errors.New("executor container removal could not be confirmed")
	d := testDeps(t, cleanupAtDeadlineModel{cleanupErr: cleanupErr})
	out, err := runOrchestrator(context.Background(), d, "inspect")
	if !errors.Is(err, cleanupErr) || out == "" {
		t.Fatalf("report=%q err=%v", out, err)
	}
}
