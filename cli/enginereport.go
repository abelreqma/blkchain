package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
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
	final  string
	dirty  chan struct{}
	remove func()
}

func (w *reportWriter) SetFinal(final string) {
	const maxFinalRunes = 65536
	if len([]rune(final)) > maxFinalRunes {
		w.final = capRunes(final, maxFinalRunes) + "\n[final assessment truncated]"
		return
	}
	w.final = final
}

func (w *reportWriter) RestoreFinal() error {
	const maxHeaderBytes = 1 << 20
	_, jsonPath := reportPaths(w.wsDir)
	fd, err := syscall.Open(jsonPath, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), jsonPath)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("report: saved JSON is not a regular file")
	}
	decoder := json.NewDecoder(io.LimitReader(f, maxHeaderBytes))
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	if first != json.Delim('{') {
		return fmt.Errorf("report: saved JSON has no object")
	}
	key, err := decoder.Token()
	if err != nil {
		return err
	}
	name, ok := key.(string)
	if !ok || (name != "final" && name != "web" && name != "goal") {
		return fmt.Errorf("report: saved JSON has an unexpected header")
	}
	if name != "final" {
		return nil
	}
	var final string
	if err := decoder.Decode(&final); err != nil {
		return err
	}
	w.SetFinal(final)
	return nil
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
	web, err := w.st.WebSnapshot(context.Background())
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
		Web:         &web,
		Goal:        w.goal,
		Scope:       w.scope,
		Mode:        w.mode,
		Workspace:   w.wsDir,
		Status:      status,
		Final:       w.final,
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
	signalDirty := func() {
		select {
		case w.dirty <- struct{}{}:
		default:
		}
	}
	removeApply := w.st.AddOnApply(func(int64, engagement.Engagement) { signalDirty() })
	removeEvidence := w.st.AddOnEvidence(signalDirty)
	w.remove = func() {
		removeApply()
		removeEvidence()
	}
	removeFindings := w.st.AddOnWebFinding(func([]byte) error {
		signalDirty()
		return nil
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
			removeFindings()
			close(quit)
			<-done
		})
	}
}

// atomicWrite writes data to a temp file then renames it into place, so a reader
// never sees a partially written report.
func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
