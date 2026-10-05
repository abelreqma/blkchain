package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/webanalysis"
)

type webCapture struct {
	Store    *engagement.Store
	Runs     *RunOutputs
	OnResult func(string)
	OnSafety func(webSafety)
}
type webSafety struct {
	Access bool
	Stop   exploitStop
}

type capturedWebDriver struct {
	inner   webDriver
	task    engagement.Task
	capture webCapture
	mu      sync.Mutex
}

func (d *capturedWebDriver) save(ctx context.Context, kind, rawURL, out string) (string, error) {
	if d.capture.Store == nil {
		return "", fmt.Errorf("web evidence store missing")
	}
	a, err := d.capture.Store.SaveWebArtifact(ctx, webanalysis.Artifact{TaskID: d.task.ID, Kind: kind, URL: rawURL, Role: d.task.ID, Complete: !strings.Contains(out, "...[truncated]")}, []byte(out))
	if err != nil {
		return "", err
	}
	snapshot, err := d.capture.Store.WebSnapshot(ctx)
	if err != nil {
		return "", err
	}
	snapshot = webFilter(snapshot, []string{rawURL})
	safe := webModelPreview(kind, out, snapshot.Findings)
	quote := fmt.Sprintf("web %s artifact=%s sha256=%s\n%s", kind, a.ID, a.Hash, safe)
	d.mu.Lock()
	defer d.mu.Unlock()
	id, err := d.capture.Store.RecordEvidence(d.task.ID, quote)
	if err != nil {
		return "", err
	}
	if d.capture.Runs != nil {
		d.capture.Runs.Add(d.task.ID, quote)
	}
	if d.capture.OnSafety != nil {
		d.capture.OnSafety(webSafety{Access: exploitYieldedAccess(out), Stop: newExploitBackstop(d.task.DoneWhen).check(out)})
	}
	if d.capture.OnResult != nil {
		d.capture.OnResult(safe)
	}
	return fmt.Sprintf("evidence_id=%d artifact=%s\n%s", id, a.ID, safe), nil
}
func (d *capturedWebDriver) DoBrowser(ctx context.Context, a webBrowserAction, r webRedirectAuthorizer) (string, error) {
	out, err := d.inner.DoBrowser(ctx, a, r)
	if err != nil {
		return "", err
	}
	return d.save(ctx, "browser-dom", a.URL, out)
}
func (d *capturedWebDriver) DoAPIRequest(ctx context.Context, a webAPIRequest, r webRedirectAuthorizer) (string, error) {
	out, err := d.inner.DoAPIRequest(ctx, a, r)
	if err != nil {
		return "", err
	}
	return d.save(ctx, "api-observation", a.URL, out)
}
