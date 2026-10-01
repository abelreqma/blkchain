package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/histstore"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/skillcat"
)

// replengage.go is the gate-governed engage path reachable from the REPL. The
// session autonomy mode (secgate.Safe/Auto, held on the tui model as engageMode)
// and the auto-scope override (engageOverride) feed buildEngageGate, so a REPL
// engagement is gated exactly like `blk engage`: LOCAL always confirms, the
// unattended /auto bound falls back to HITL, and the RoE/override rules hold. The
// three helpers below back the UI/UX session's /safe//auto commands and ribbon.

// validateEngageMode mirrors the gate.Start precondition without building a gate:
// /auto needs a usable scope (in-scope targets or a local directive) OR an
// explicit override. Safe always validates. It lets the REPL surface a clear
// message before an engagement starts.
func validateEngageMode(mode secgate.Mode, override bool, scope *secgate.Scope) error {
	if mode == secgate.Auto && (scope == nil || (scope.Empty() && !scope.Local())) && !override {
		return errors.New("engage: /auto needs a scope (an ROE.md with in-scope targets) or an override")
	}
	return nil
}

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

// unattendedBoundEmpty reports whether unattended /auto for cwd would fall back to
// HITL because the .blkchain/config.yaml allowed_binaries bound permits nothing.
// A missing or unreadable config is an empty bound (true). allowed_binaries: true
// means everything is allowed unattended, so the bound is not empty (false).
func unattendedBoundEmpty(cwd string) bool {
	cfg, _, err := autodetectEngageConfig(cwd)
	if err != nil || cfg == nil {
		return true
	}
	if cfg.AllowedBinaries.All {
		return false
	}
	return len(cfg.AllowedBinaries.List) == 0
}

// runReplEngage builds a gate from the session mode + override and runs the gated
// orchestrator for goal. scope and config policy autodetect from cwd (ROE.md +
// .blkchain/config.yaml); the engagement runs in wsDir (empty picks a fresh
// timestamped workspace under the config dir). confirm is the TUI confirmer: in
// a LOCAL engagement every command is confirmed and a nil confirmer fails closed.
// progress is nil-safe and, when set, feeds a live view of the engagement store.
// Every command the engagement issues passes the single secgate.Gate.
func runReplEngage(ctx context.Context, wsDir, cwd string, mode secgate.Mode, override bool,
	model toolLoopModel, rc searcher, cfg ragconfig.Config, prefs modelPrefs, cat *skillcat.Catalog,
	confirm secgate.Confirmer, asker askuser.Asker, roeDB *sql.DB, goal string,
	progress func(rev int64, snap engagement.Engagement)) (string, error) {

	scope, _, _, err := resolveEngageScope(engageOpts{}, cwd, roeDB)
	if err != nil {
		return "", fmt.Errorf("engage: %w", err)
	}
	if err := validateEngageMode(mode, override, scope); err != nil {
		return "", err
	}
	policy, err := resolveEngageConfigPolicy(engageOpts{autoOverride: override}, cwd)
	if err != nil {
		return "", fmt.Errorf("engage: %w", err)
	}
	// Fail closed: a LOCAL engagement confirms every command, so with no confirmer
	// it cannot run.
	if scope != nil && scope.Local() && confirm == nil {
		return "", errors.New("engage: a local/post-access engagement needs interactive confirmation")
	}

	if wsDir == "" {
		if wsDir, err = engageWorkspaceDir(""); err != nil {
			return "", fmt.Errorf("engage: %w", err)
		}
	}
	ws, err := engagement.OpenWorkspace(wsDir)
	if err != nil {
		return "", fmt.Errorf("engage: cannot open workspace: %w", err)
	}
	defer ws.Close()

	scratch, err := os.MkdirTemp("", "blkreplengage-")
	if err != nil {
		return "", fmt.Errorf("engage: cannot create scratch dir: %w", err)
	}
	defer os.RemoveAll(scratch)

	gate := buildEngageGate(ws, scope, mode, confirm, secgate.NewSessionApprovals(), scratch, policy, func(action, detail string) {
		_ = ws.AuditLine("secgate", action, detail)
	})
	if err := gate.Start(); err != nil {
		return "", fmt.Errorf("engage: %w", err)
	}
	if asker == nil {
		asker = askuser.AutoAsker{}
	}
	deps := buildEngageDeps(model, rc, cfg, prefs, ws.Store, gate, scratch, cat, asker, confirm, progress)
	return runOrchestrator(ctx, deps, goal)
}
