package main

import (
	"context"
	"fmt"
	"sync"

	"blkchain/cli/internal/engagement"
)

// engagegraph.go is the REPL's bounded, session-scoped, on-demand knowledge-graph
// accessor, the analog of engageevidence.go. The REPL/TUI model holds only the
// read-only Snapshot, not the engagement Store (ws.Store lives inside
// runReplEngage's goroutine), so a /kg view cannot query the graph directly.
// runReplEngage registers a source bound to the live ws.Store while it runs; the
// TUI calls EngageGraphQuery(q) on demand. The source runs populate+query on the
// ALREADY-OPEN store (never a second OpenWorkspace), so its one writer
// (PopulateGraph -> UpsertGraph) serializes with the engagement loop's Apply
// through the store's write lock and never contends for a second SQLite
// connection (no SQLITE_BUSY, no deadlock).

var (
	engageGraphMu     sync.Mutex
	engageGraphSource func(q engagement.GraphQuery) (kgView, error)
)

// SetEngageGraphSource registers the current engagement's graph source so the
// REPL /kg view can query it on demand, paralleling SetEngageEvidenceSource.
// runReplEngage registers a closure bound to the live ws.Store while it runs and
// clears it (nil) on exit.
func SetEngageGraphSource(fn func(q engagement.GraphQuery) (kgView, error)) {
	engageGraphMu.Lock()
	engageGraphSource = fn
	engageGraphMu.Unlock()
}

// EngageGraphQuery runs q against the current engagement's knowledge graph. The
// second return is false (with a nil error) when no engagement is active;
// otherwise it is true and the error is any query failure.
func EngageGraphQuery(q engagement.GraphQuery) (kgView, bool, error) {
	engageGraphMu.Lock()
	fn := engageGraphSource
	engageGraphMu.Unlock()
	if fn == nil {
		return kgView{}, false, nil
	}
	v, err := fn(q)
	return v, true, err
}

// engageGraphOnStore refreshes the knowledge graph from st's current state and
// runs q against it on the given already-open store (no OpenWorkspace). It is the
// shared body of the CLI accessor (engageGraph, which opens a workspace first)
// and the REPL source closure (bound to the live ws.Store).
func engageGraphOnStore(st *engagement.Store, q engagement.GraphQuery) (kgView, error) {
	ctx := context.Background()
	snap, err := st.Snapshot(ctx)
	if err != nil {
		return kgView{}, fmt.Errorf("kg: snapshot: %w", err)
	}
	if err := st.PopulateGraph(ctx, snap); err != nil {
		return kgView{}, fmt.Errorf("kg: populate: %w", err)
	}
	res, err := st.QueryGraph(q)
	if err != nil {
		return kgView{}, fmt.Errorf("kg: query: %w", err)
	}
	return kgView{
		Name:     snap.Name,
		Revision: snap.Revision,
		Nodes:    res.Nodes,
		Edges:    res.Edges,
		Result:   res,
	}, nil
}
