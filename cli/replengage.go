package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"

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
	o := engageOpts{workspace: wsDir, safe: mode == secgate.Safe, autoOverride: override, transcript: transcript}
	if wsDir != "" {
		if _, err := os.Stat(filepath.Join(wsDir, "run.json")); err == nil {
			o.resume = wsDir
		} else if !os.IsNotExist(err) {
			return "", err
		}
	}
	return runEngageSession(ctx, engageRunInput{Opts: o, Cwd: cwd, Goal: goal, Model: model, RC: rc, Cfg: cfg, Prefs: prefs, Catalog: cat, Confirm: confirm, Asker: asker, DB: roeDB, Progress: progress, OnAction: onAction, Views: true})
}

// applyArmReq sets the optional operator arm requester on deps: the REPL
// passes its widget ArmRequester here so the at-exploit arm gate fires in a REPL
// engagement. With no requester, deps.ArmReq stays nil, the arm gate is a no-op,
// and an unarmed exploit's commands are gate-denied (fail-safe).
func applyArmReq(deps engageDeps, armReq ...ArmRequester) engageDeps {
	if len(armReq) > 0 && armReq[0] != nil {
		deps.ArmReq = armReq[0]
	}
	return deps
}

// replArmReqMu guards the process-wide REPL arm requester: the TUI sets it from
// the UI goroutine before dispatching /engage; runReplEngage reads it from the
// engage command goroutine.
var (
	replArmReqMu  sync.Mutex
	replArmReqVal ArmRequester
)

// SetReplArmRequester wires the REPL's operator arm gate so the at-exploit arm
// gate fires in REPL engagements (Safe and Auto). The TUI calls it once with its
// widget ArmRequester, paralleling the widget confirmer. A nil value disables the
// push (fail-safe: an unarmed exploit's commands are gate-denied). This is the
// REPL injection seam for deps.ArmReq; runReplEngage reads it via replArmReq.
func SetReplArmRequester(r ArmRequester) {
	replArmReqMu.Lock()
	replArmReqVal = r
	replArmReqMu.Unlock()
}

// replArmReq returns the wired REPL arm requester (nil when unset).
func replArmReq() ArmRequester {
	replArmReqMu.Lock()
	defer replArmReqMu.Unlock()
	return replArmReqVal
}
