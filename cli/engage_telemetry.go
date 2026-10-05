package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"blkchain/cli/internal/engagement"
)

var errEngageDenialBurst = errors.New("engagement halted: eight gate denials within one minute")

type engageTelemetry struct {
	mu      sync.Mutex
	write   func(actor, action, detail string) error
	cancel  context.CancelCauseFunc
	now     func() time.Time
	denials []time.Time
	tripped bool
}

type engageTelemetryKey struct{}

func withEngageTelemetry(ctx context.Context, telemetry *engageTelemetry) context.Context {
	return context.WithValue(ctx, engageTelemetryKey{}, telemetry.observe)
}

func engageTelemetryFromContext(ctx context.Context) func(action, detail string) error {
	observe, _ := ctx.Value(engageTelemetryKey{}).(func(string, string) error)
	return observe
}

func newEngageTelemetry(ws *engagement.Workspace, cancel context.CancelCauseFunc) *engageTelemetry {
	return &engageTelemetry{write: ws.AuditLine, cancel: cancel, now: time.Now}
}

func (t *engageTelemetry) gate(action, detail string) {
	if err := t.write("secgate", action, detail); err != nil {
		t.cancel(fmt.Errorf("engagement audit failed: %w", err))
		return
	}
	if !strings.HasPrefix(action, "deny:") || action == "deny:context" {
		return
	}
	t.mu.Lock()
	if t.tripped {
		t.mu.Unlock()
		return
	}
	now := t.now()
	cutoff := now.Add(-time.Minute)
	kept := t.denials[:0]
	for _, at := range t.denials {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	t.denials = append(kept, now)
	trip := len(t.denials) >= 8 && !t.tripped
	if trip {
		t.tripped = true
	}
	t.mu.Unlock()
	if trip {
		if err := t.write("orchestrator", "anomaly-denial-burst", "eight gate denials within one minute"); err != nil {
			t.cancel(fmt.Errorf("engagement audit failed: %w", err))
			return
		}
		t.cancel(errEngageDenialBurst)
	}
}

func (t *engageTelemetry) observe(action, detail string) error {
	if err := t.write("orchestrator", action, detail); err != nil {
		wrapped := fmt.Errorf("engagement audit failed: %w", err)
		t.cancel(wrapped)
		return wrapped
	}
	return nil
}
