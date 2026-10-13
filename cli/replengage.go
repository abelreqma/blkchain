package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"

	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/histstore"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/skillcat"
)

// scopeDetected reports whether a scope source autodetects for cwd: an ROE.md in
// cwd, or one remembered for cwd in the recall table. Best-effort and nil-safe (a
// missing memory store degrades to the on-disk check only).
func scopeDetected(cwd string) bool {
	if fi, err := os.Stat(filepath.Join(cwd, "ROE.md")); err == nil && !fi.IsDir() {
		return true
	}
	if store := histstore.OpenDefault(); store != nil {
		defer store.Close()
		if _, ok := recallRoE(store.DB(), cwd); ok {
			return true
		}
	}
	return false
}

// runReplEngage passes the TUI approval and transcript settings to the shared
// RoE session. An existing run.json in wsDir selects resume.
func runReplEngage(ctx context.Context, wsDir, cwd string, mode secgate.Mode, override bool,
	model toolLoopModel, rc searcher, cfg ragconfig.Config, prefs modelPrefs, cat *skillcat.Catalog,
	confirm secgate.Confirmer, asker askuser.Asker, roeDB *sql.DB, goal string,
	progress func(rev int64, snap engagement.Engagement)) (string, error) {
	transcript, _ := ctx.Value(replTranscriptKey{}).(string)
	onAction, _ := ctx.Value(replActionKey{}).(func(actionRecord))
	armReq, _ := ctx.Value(replArmReqKey{}).(ArmRequester)
	o := engageOpts{workspace: wsDir, safe: mode == secgate.Safe, autoOverride: override, transcript: transcript}
	if selected, ok := ctx.Value(replCDPKey{}).(engageOpts); ok {
		o.roe = selected.roe
		o.session = selected.session
		o.role = selected.role
		o.sessionCDP = selected.sessionCDP
	}
	if wsDir != "" {
		if _, err := os.Stat(filepath.Join(wsDir, "run.json")); err == nil {
			o.resume = wsDir
		} else if !os.IsNotExist(err) {
			return "", err
		}
	}
	return runEngageSession(ctx, engageRunInput{Opts: o, Cwd: cwd, Goal: goal, Model: model, RC: rc, Cfg: cfg, Prefs: prefs, Catalog: cat, Confirm: confirm, Asker: asker, ArmReq: armReq, DB: roeDB, Progress: progress, OnAction: onAction, Views: true})
}
