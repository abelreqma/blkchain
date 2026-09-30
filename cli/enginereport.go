package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/engreport"
)

// reportDebounce coalesces a burst of commits into a single report render.
const reportDebounce = 250 * time.Millisecond

// reportWriter regenerates <wsDir>/report.md and report.json from the engagement
// store. The report is a pure projection of the store, so it rebuilds correctly
// on resume. Live updates are driven by the store's post-commit hook, debounced
// and rendered on a background goroutine so the commit path stays cheap.
type reportWriter struct {
	st     *engagement.Store
	wsDir  string
	goal   string
	scope  string
	mode   string
	dirty  chan struct{}
	remove func()
}

// newReportWriter builds a writer for one engagement workspace.
func newReportWriter(st *engagement.Store, wsDir, goal, scope, mode string) *reportWriter {
	return &reportWriter{
		st:    st,
		wsDir: wsDir,
		goal:  goal,
		scope: scope,
		mode:  mode,
		dirty: make(chan struct{}, 1),
	}
}

// reportPaths returns the Markdown and JSON report paths for a workspace dir.
func reportPaths(wsDir string) (mdPath, jsonPath string) {
	return filepath.Join(wsDir, "report.md"), filepath.Join(wsDir, "report.json")
}

// buildModel assembles the render-ready model from the store at the given status.
func (w *reportWriter) buildModel(status string) (engreport.Model, error) {
	snap, err := w.st.Snapshot(context.Background())
	if err != nil {
		return engreport.Model{}, err
	}
	trans, err := w.st.Transitions()
	if err != nil {
		return engreport.Model{}, err
	}
	ev, err := w.st.AllEvidence()
	if err != nil {
		return engreport.Model{}, err
	}
	receipts := map[string][]engagement.Receipt{}
	for _, t := range snap.Tasks {
		rc, err := w.st.ReceiptsFor(t.ID)
		if err != nil {
			return engreport.Model{}, err
		}
		if len(rc) > 0 {
			receipts[t.ID] = rc
		}
	}
	return engreport.Model{
		Goal:        w.goal,
		Scope:       w.scope,
		Mode:        w.mode,
		Workspace:   w.wsDir,
		Status:      status,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Engagement:  snap,
		Evidence:    ev,
		Receipts:    receipts,
		Transitions: trans,
	}, nil
}

// Flush synchronously regenerates and atomically writes both report files with
// an explicit status.
func (w *reportWriter) Flush(status string) error {
	m, err := w.buildModel(status)
	if err != nil {
		return err
	}
	md := engreport.RenderMarkdown(m)
	js, err := engreport.RenderJSON(m)
	if err != nil {
		return err
	}
	mdPath, jsonPath := reportPaths(w.wsDir)
	if err := atomicWrite(mdPath, []byte(md)); err != nil {
		return err
	}
	return atomicWrite(jsonPath, js)
}

// Start registers the post-commit hook and launches a debounced render loop. The
// returned stop function unregisters the hook, waits for the loop to drain any
// in-flight render, and is safe to call more than once.
func (w *reportWriter) Start() (stop func()) {
	w.remove = w.st.AddOnApply(func(rev int64, e engagement.Engagement) {
		select {
		case w.dirty <- struct{}{}:
		default:
		}
	})
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var timer <-chan time.Time
		for {
			select {
			case <-w.dirty:
				timer = time.After(reportDebounce)
			case <-timer:
				timer = nil
				if err := w.Flush("in-progress"); err != nil {
					fmt.Fprintf(os.Stderr, "report: write failed: %v\n", err)
				}
			case <-quit:
				return
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			w.remove()
			close(quit)
			<-done
		})
	}
}

// atomicWrite writes data to a temp file then renames it into place, so a reader
// never sees a partially written report.
func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
