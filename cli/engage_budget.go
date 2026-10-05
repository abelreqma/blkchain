package main

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"blkchain/cli/internal/engagement"
)

var (
	errEngageWorkBudget = errors.New("engagement work budget reached")
	errEngageWallBudget = errors.New("engagement wall-clock budget reached")
)

type engageWorkBudgetKey struct{}

type engageWorkBudget struct {
	limit  int64
	used   atomic.Int64
	cancel context.CancelCauseFunc
}

func engageBudgetContext(ctx context.Context, configuredActions, configuredSeconds int) (context.Context, func()) {
	if configuredActions <= 0 {
		configuredActions = 512
	}
	if configuredSeconds <= 0 {
		configuredSeconds = 1800
	}
	seconds := clampEnvInt("BLKCHAIN_ENGAGE_WALL_SECONDS", configuredSeconds, 1, 86400)
	maxActions := clampEnvInt("BLKCHAIN_ENGAGE_MAX_ACTIONS", configuredActions, 1, 10000)
	wallCtx, cancelWall := context.WithTimeoutCause(ctx, time.Duration(seconds)*time.Second, errEngageWallBudget)
	workCtx, cancelWork := context.WithCancelCause(wallCtx)
	budget := &engageWorkBudget{limit: int64(maxActions), cancel: cancelWork}
	return context.WithValue(workCtx, engageWorkBudgetKey{}, budget), func() {
		cancelWork(nil)
		cancelWall()
	}
}

func consumeEngageWork(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	budget, ok := ctx.Value(engageWorkBudgetKey{}).(*engageWorkBudget)
	if !ok {
		return nil
	}
	if budget.used.Add(1) <= budget.limit {
		return nil
	}
	budget.cancel(errEngageWorkBudget)
	return errEngageWorkBudget
}

func engageBudgetStop(ctx context.Context, store *engagement.Store, goal string) (string, bool, error) {
	cause := context.Cause(ctx)
	if !errors.Is(cause, errEngageWorkBudget) && !errors.Is(cause, errEngageWallBudget) {
		return "", false, nil
	}
	reason := "work budget reached"
	if errors.Is(cause, errEngageWallBudget) {
		reason = "wall-clock budget reached"
	}
	readCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	report, err := engagementStoreReport(readCtx, store, goal)
	if err != nil {
		return "", true, fmt.Errorf("engagement stopped: %s: %w", reason, err)
	}
	const maxReturnedReportRunes = 65536
	if len([]rune(report)) > maxReturnedReportRunes {
		report = capRunes(report, maxReturnedReportRunes) + "\n[report truncated; inspect the saved workspace report]"
	}
	return "Engagement paused: " + reason + ".\n\n" + report, true, nil
}
