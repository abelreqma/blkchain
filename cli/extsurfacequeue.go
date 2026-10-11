package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	eng "blkchain/cli/internal/engagement"
)

// extsurfacequeue.go sweeps every recon task that names a web origin, whoever created it: the store's apply listener records what is due and the orchestrator's per-round hook performs it.

// surfaceSweepQueue holds the origins a recon task named and not yet swept.
type surfaceSweepQueue struct {
	mu      sync.Mutex
	pending []surfaceSweepRequest
	queued  map[string]bool
	done    map[string]bool
}

func newSurfaceSweepQueue() *surfaceSweepQueue {
	return &surfaceSweepQueue{queued: map[string]bool{}, done: map[string]bool{}}
}

// sweepableTask reports the origin a recon task names: a web-surface task's bare host, or an explicit http or https URL on any other surface.
func sweepableTask(task eng.Task) string {
	if task.Phase != eng.PhaseRecon {
		return ""
	}
	if task.Surface != eng.SurfaceWeb && !strings.Contains(task.Target, "://") {
		return ""
	}
	return surfaceOriginFor(task.Target)
}

// observe records the sweeps an applied engagement state has made due.
func (q *surfaceSweepQueue) observe(_ int64, e eng.Engagement) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, task := range e.Tasks {
		origin := sweepableTask(task)
		if origin == "" {
			continue
		}
		key := task.ID + "\x00" + origin
		if q.queued[key] || q.done[key] {
			continue
		}
		q.queued[key] = true
		q.pending = append(q.pending, surfaceSweepRequest{
			Origin: origin, TaskID: task.ID, Surface: task.Surface,
			SchemeAssumed: !strings.Contains(task.Target, "://"),
		})
	}
}

// drain returns the due sweeps and marks them done, so each is performed once.
func (q *surfaceSweepQueue) drain() []surfaceSweepRequest {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.pending
	q.pending = nil
	for _, r := range out {
		key := r.TaskID + "\x00" + r.Origin
		delete(q.queued, key)
		q.done[key] = true
	}
	return out
}

// runPendingSurfaceSweeps performs the due sweeps, audits each one, and returns how many it performed.
func runPendingSurfaceSweeps(ctx context.Context, d surfaceSweepDeps, q *surfaceSweepQueue) int {
	if q == nil || d.Broker == nil || d.Store == nil {
		return 0
	}
	swept := 0
	for _, req := range q.drain() {
		if err := ctx.Err(); err != nil {
			return swept
		}
		result, err := sweepExternalSurface(ctx, d, req)
		if err != nil {
			_ = d.Store.Audit("surface", "sweep-failed",
				req.TaskID+" "+req.Origin+": "+capRunes(err.Error(), 400))
			continue
		}
		swept++
		detail := fmt.Sprintf("%s %s: %d observations", req.TaskID, req.Origin, result.Stored)
		if len(result.Gaps) > 0 {
			detail += "; gaps: " + capRunes(strings.Join(result.Gaps, " | "), 800)
		}
		_ = d.Store.Audit("surface", "swept", detail)
	}
	return swept
}
