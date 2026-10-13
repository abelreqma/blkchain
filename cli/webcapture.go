package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/webanalysis"
)

type webCapture struct {
	Store    *engagement.Store
	Session  *webSessionRole
	Runs     *RunOutputs
	OnResult func(string)
	OnSafety func(webSafety)
}
type webSafety struct {
	Access bool
	Stop   exploitStop
}

func webCapturedRole(session *webSessionRole, rawURL, fallback string) string {
	if session == nil {
		return fallback
	}
	if webSameOrigin(rawURL, session.Origin) {
		return session.Name
	}
	return "anonymous"
}

type capturedWebDriver struct {
	inner   webDriver
	task    engagement.Task
	capture webCapture
	gate    *secgate.Gate
	mu      sync.Mutex
}

func (d *capturedWebDriver) save(ctx context.Context, kind, rawURL, out string) (string, error) {
	if d.capture.Store == nil {
		return "", fmt.Errorf("web evidence store missing")
	}
	if d.gate != nil && d.gate.Policy != nil && len(out) > d.gate.Policy.OutputBytes {
		return "", fmt.Errorf("web evidence exceeds the RoE output cap")
	}
	role := webCapturedRole(d.capture.Session, rawURL, d.task.ID)
	a, err := d.capture.Store.SaveWebArtifact(ctx, webanalysis.Artifact{TaskID: d.task.ID, Kind: kind, URL: rawURL, Role: role, Complete: !strings.Contains(out, "...[truncated]")}, []byte(out))
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
	finalURL := a.URL
	if live, ok := d.inner.(*webPlaywrightDriver); ok {
		live.mu.Lock()
		if live.page != nil {
			finalURL = live.page.URL()
		}
		live.mu.Unlock()
	}
	return d.save(ctx, "browser-dom", finalURL, out)
}
func (d *capturedWebDriver) DoAPIRequest(ctx context.Context, a webAPIRequest, r webRedirectAuthorizer) (string, error) {
	out, err := d.inner.DoAPIRequest(ctx, a, r)
	if err != nil {
		return "", err
	}
	finalURL := a.URL
	if live, ok := d.inner.(*webPlaywrightDriver); ok {
		live.mu.Lock()
		if live.lastAPIURL != "" {
			finalURL = live.lastAPIURL
		}
		live.mu.Unlock()
	}
	return d.save(ctx, "api-observation", finalURL, out)
}
