package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	eng "blkchain/cli/internal/engagement"
)

// vizengage.go adapts the real engagement store to the progress view's
// EngagementView and builds the engage Progress callback that prints one DAG
// block per revision advance.

// makeEngageProgress returns the engage Progress hook, or nil when the view is
// off or there is no renderer. The hook fires once per revision advance, so it
// renders without caching.
func makeEngageProgress(w io.Writer, r *vizRenderer, viz bool) func(rev int64, snap eng.Engagement) {
	if !viz || r == nil {
		return nil
	}
	return func(rev int64, snap eng.Engagement) {
		// Runs inside Store.Apply: a panic must not escape, and the render
		// is time-bounded so it cannot stall the orchestrator.
		defer func() { _ = recover() }()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		block := r.blockFor(ctx, snap)
		if strings.TrimSpace(block) != "" {
			fmt.Fprintln(w, block)
		}
	}
}
