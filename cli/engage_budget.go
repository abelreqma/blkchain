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
	store  *engagement.Store
	cancel context.CancelCauseFunc
}

func engageBudgetContext(ctx context.Context, store *engagement.Store, configuredActions, configuredSeconds int) (context.Context, func(), error) {
	if configuredActions <= 0 {
		configuredActions = 512
	}
	if configuredSeconds <= 0 {
		configuredSeconds = 1800
	}
	seconds := clampEnvInt("BLKCHAIN_ENGAGE_WALL_SECONDS", configuredSeconds, 1, 86400)
	maxActions := clampEnvInt("BLKCHAIN_ENGAGE_MAX_ACTIONS", configuredActions, 1, 10000)
	now := time.Now()
	start := now
	if store != nil {
		var err error
		start, err = store.EnsureEngagementStart(now)
		if err != nil {
			return nil, nil, err
		}
		if start.After(now.Add(time.Minute)) {
			return nil, nil, errors.New("engagement start time is in the future")
		}
	}
	wallCtx, cancelWall := context.WithDeadlineCause(ctx, start.Add(time.Duration(seconds)*time.Second), errEngageWallBudget)
	workCtx, cancelWork := context.WithCancelCause(wallCtx)
	budget := &engageWorkBudget{limit: int64(maxActions), store: store, cancel: cancelWork}
	return context.WithValue(workCtx, engageWorkBudgetKey{}, budget), func() {
		cancelWork(nil)
		cancelWall()
	}, nil
}

func consumeEngageWork(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	budget, ok := ctx.Value(engageWorkBudgetKey{}).(*engageWorkBudget)
	if !ok {
		return nil
	}
	if budget.store != nil {
		allowed, err := budget.store.ReserveEngagementAction(budget.limit)
		if err != nil {
			budget.cancel(err)
			return err
		}
		if !allowed {
			budget.cancel(errEngageWorkBudget)
			return errEngageWorkBudget
		}
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
	return "Engagement paused: " + reason + ".\n\n" + boundedEngageReport(report), true, nil
}

func boundedEngageReport(report string) string {
	const maxReturnedReportRunes = 65536
	if len([]rune(report)) > maxReturnedReportRunes {
		return capRunes(report, maxReturnedReportRunes) + "\n[report truncated; inspect the saved workspace report]"
	}
	return report
}
