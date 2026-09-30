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

// storeView implements EngagementView over the real store. It only reads.
type storeView struct{ s *eng.Store }

func newStoreView(s *eng.Store) storeView { return storeView{s: s} }

func (v storeView) Revision(ctx context.Context) (int64, error) { return v.s.Revision(ctx) }

func (v storeView) Snapshot(ctx context.Context) (Engagement, error) {
	e, err := v.s.Snapshot(ctx)
	if err != nil {
		return Engagement{}, err
	}
	return convertEngagement(e), nil
}

// convertEngagement projects a store snapshot into the view types.
func convertEngagement(e eng.Engagement) Engagement {
	tasks := make([]Task, 0, len(e.Tasks))
	for _, t := range e.Tasks {
		tasks = append(tasks, Task{
			ID:        t.ID,
			Kind:      t.Kind,
			Target:    t.Target,
			Objective: t.Objective,
			DependsOn: t.DependsOn,
			BasisIDs:  t.BasisIDs,
			Status:    taskStatusFromStore(string(t.Status)),
		})
	}
	return Engagement{
		Revision: e.Revision,
		Name:     e.Name,
		Tasks:    tasks,
		ActiveID: e.ActiveID,
		Stage:    Stage{Label: e.Stage.Label, Step: e.Stage.Step, Total: e.Stage.Total, Tool: e.Stage.Tool},
	}
}

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
		block := r.blockFor(ctx, convertEngagement(snap))
		if strings.TrimSpace(block) != "" {
			fmt.Fprintln(w, block)
		}
	}
}
