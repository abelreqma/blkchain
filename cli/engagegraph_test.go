package main

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"blkchain/cli/internal/askuser"
	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"

	"github.com/tmc/langchaingo/llms"
)

// With no source registered (no active engagement), EngageGraphQuery reports
// not-active and no error, mirroring EngageEvidence's (nil, false) contract.
func TestEngageGraphQueryNoSource(t *testing.T) {
	SetEngageGraphSource(nil)
	v, active, err := EngageGraphQuery(eng.GraphQuery{})
	if active {
		t.Fatalf("no source should report not-active, got active=true")
	}
	if err != nil {
		t.Fatalf("no source should not error, got %v", err)
	}
	if len(v.Nodes) != 0 || len(v.Edges) != 0 {
		t.Fatalf("no source should return an empty view, got %+v", v)
	}
}

// A registered source bound to an open store returns the live graph.
func TestEngageGraphSourceRoundTrip(t *testing.T) {
	ws, err := eng.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	defer ws.Close()
	if _, err := ws.Store.Apply(eng.Delta{
		Upserts: []eng.Task{{ID: "a", Kind: "recon", Target: "10.0.0.1", Status: eng.StatusTodo}},
		Kind:    "seed",
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	SetEngageGraphSource(func(q eng.GraphQuery) (kgView, error) { return engageGraphOnStore(ws.Store, q) })
	defer SetEngageGraphSource(nil)

	v, active, err := EngageGraphQuery(eng.GraphQuery{})
	if !active || err != nil {
		t.Fatalf("active=%v err=%v, want active=true nil", active, err)
	}
	ids := map[string]bool{}
	for _, n := range v.Nodes {
		ids[n.ID] = true
	}
	if !ids["task:a"] || !ids["asset:10.0.0.1"] {
		t.Fatalf("live graph missing nodes; got %v", ids)
	}
	if v.Revision == 0 {
		t.Fatalf("view revision should be non-zero")
	}
}

// graphProbeModel records, on its first generate call (which runs inside the live
// runOrchestrator while runReplEngage has the graph source registered), whether
// EngageGraphQuery reports an active engagement, then ends the loop.
type graphProbeModel struct {
	checked   bool
	sawActive bool
}

func (m *graphProbeModel) GenerateContent(_ context.Context, _ []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	if !m.checked {
		m.checked = true
		_, active, _ := EngageGraphQuery(eng.GraphQuery{})
		m.sawActive = active
	}
	return finalResp("engagement complete"), nil
}

// TestRunReplEngageRegistersGraphSource proves the /kg source is reachable through
// the PRODUCTION runReplEngage path: live during the run and cleared after.
// Dropping the SetEngageGraphSource registration in replengage.go fails this.
func TestRunReplEngageRegistersGraphSource(t *testing.T) {
	SetEngageGraphSource(nil)
	t.Cleanup(func() { SetEngageGraphSource(nil) })
	m := &graphProbeModel{}
	if _, err := runReplEngage(
		context.Background(),
		t.TempDir(),
		t.TempDir(),
		secgate.Safe, false,
		m, nil, ragconfig.Config{TopK: 5}, modelPrefs{}, nil,
		&countingConfirmer{ok: true}, askuser.AutoAsker{}, nil, "enumerate the lab", nil,
	); err != nil {
		t.Fatalf("runReplEngage: %v", err)
	}
	if !m.sawActive {
		t.Fatal("graph source was not registered during the live REPL run; /kg would be inert")
	}
	if _, active, _ := EngageGraphQuery(eng.GraphQuery{}); active {
		t.Fatal("graph source not cleared after the run (defer SetEngageGraphSource(nil) missing)")
	}
}

// The bound source runs on the ALREADY-OPEN store, so a per-query populate does
// not contend for a second SQLite connection: concurrent Apply (the engagement
// loop) and EngageGraphQuery (the UI) never error with SQLITE_BUSY or deadlock.
func TestEngageGraphSourceConcurrentWithApply(t *testing.T) {
	ws, err := eng.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	defer ws.Close()
	SetEngageGraphSource(func(q eng.GraphQuery) (kgView, error) { return engageGraphOnStore(ws.Store, q) })
	defer SetEngageGraphSource(nil)

	const n = 30
	var wg sync.WaitGroup
	errs := make(chan error, n+16)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			if _, err := ws.Store.Apply(eng.Delta{
				Upserts: []eng.Task{{ID: fmt.Sprintf("t%d", i), Kind: "recon", Target: fmt.Sprintf("h%d", i), Status: eng.StatusTodo}},
				Kind:    "add",
			}); err != nil {
				errs <- err
				return
			}
		}
	}()
	for p := 0; p < 3; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, _, err := EngageGraphQuery(eng.GraphQuery{}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent EngageGraphQuery/Apply error (SQLITE_BUSY/deadlock?): %v", err)
	}

	v, active, err := EngageGraphQuery(eng.GraphQuery{Type: eng.NodeTask})
	if !active || err != nil {
		t.Fatalf("final query active=%v err=%v", active, err)
	}
	if len(v.Nodes) != n {
		t.Fatalf("got %d task nodes, want %d", len(v.Nodes), n)
	}
}
