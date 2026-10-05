package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/histstore"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/skillcat"
)

// loadEngageCatalog loads the skill catalog from BLKCHAIN_SKILLS_DIR. An
// unset or empty dir yields an empty catalog and no error.
func loadEngageCatalog() (*skillcat.Catalog, error) {
	return skillcat.Load(os.Getenv("BLKCHAIN_SKILLS_DIR"))
}

// engageOpts holds `blk engage`'s flags.
type engageOpts struct {
	scope        string
	auto         bool
	autoOverride bool
	workspace    string
	model        string
}

// defineEngageFlags declares `blk engage`'s flags.
func defineEngageFlags(fs *flag.FlagSet, o *engageOpts) {
	fs.StringVar(&o.scope, "scope", "", "scope file: in-scope targets, `local`, and `allow <bin>` lines")
	fs.BoolVar(&o.auto, "auto", false, "run without confirmation prompts (bounded by scope and allowed_binaries)")
	fs.BoolVar(&o.autoOverride, "auto-override", false, "allow --auto with no scope (logged to audit.jsonl); only no-target recon runs autonomously")
	fs.StringVar(&o.workspace, "workspace", "", "engagement workspace directory (default: a new one under the config dir)")
	fs.StringVar(&o.model, "model", "", "chat model id (default: the resolved model)")
}

// runEngage builds a gated engagement and runs the orchestrator for goal.
//
// All argument, goal, and scope validation happens first and returns a usage
// error before any live service is touched (the model, the retrieval client,
// the workspace), so a usage mistake is caught without qdrant, embed_server,
// or the LLM server running.
func runEngage(args []string) error {
	if len(args) > 0 && args[0] == "web" {
		return runWebAnalysis(args[1:])
	}
	// `blk engage arm <task-id>` is the operator-only arm subcommand: it sets
	// Armed on an exploit/post-ex task so it can run under the gate. It is a
	// subcommand of engage, not a goal.
	if len(args) > 0 && args[0] == "arm" {
		return runEngageArm(args[1:])
	}
	if len(args) > 0 && args[0] == "resume" {
		return runEngageResume(args[1:])
	}

	var o engageOpts
	fs := newFlagSet("engage")
	defineEngageFlags(fs, &o)
	valueFlags := map[string]bool{"scope": true, "workspace": true, "model": true}
	if err := parseFlags(fs, reorder(args, valueFlags)); err != nil {
		return err
	}

	goal := strings.Join(fs.Args(), " ")
	if strings.TrimSpace(goal) == "" {
		return missingArg("engage", "missing goal", `engage --scope scope.txt "enumerate 10.0.0.5"`)
	}
	return runEngageWithOptions(o, goal, nil)
}

func runEngageWithOptions(o engageOpts, goal string, checkpoint *engageCheckpoint) error {
	cwd, _ := os.Getwd()
	if checkpoint != nil {
		cwd = checkpoint.ProjectDir
		if checkpoint.ScopeKind == "scope" {
			o.scope = filepath.Join(o.workspace, "scope.txt")
		}
	}
	// Shared memory store for RoE recall-by-directory (best-effort; nil degrades).
	var roeDB *sql.DB
	if store := histstore.OpenDefault(); store != nil {
		defer store.Close()
		roeDB = store.DB()
	}

	var scope *secgate.Scope
	var scopeDesc, roeUsed string
	var err error
	if checkpoint != nil {
		scope, scopeDesc, roeUsed, err = checkpointScope(o.workspace, *checkpoint)
	} else {
		scope, scopeDesc, roeUsed, err = resolveEngageScope(o, cwd, roeDB)
	}
	if err != nil {
		return fmt.Errorf("engage: %w", err)
	}
	policy, err := resolveEngageConfigPolicy(o, cwd)
	if err != nil {
		return fmt.Errorf("engage: %w", err)
	}

	mode := secgate.Safe
	if o.auto {
		mode = secgate.Auto
	}

	// No-RoE floor: --auto needs a scope OR an explicit logged override.
	if mode == secgate.Auto && (scope == nil || (scope.Empty() && !scope.Local())) && !o.autoOverride {
		return usageErr(`engage: --auto needs a scope (via --scope, or an ROE.md with "## In Scope") or --auto-override. Example: blk engage --auto --scope scope.txt "enumerate 10.0.0.5". See "blk help engage".`)
	}

	cat, err := loadEngageCatalog()
	if err != nil {
		return fmt.Errorf("engage: %w", err)
	}
	if len(cat.Errors()) > 0 {
		fmt.Fprintf(os.Stderr, "skill catalog: %d skill(s) excluded\n", len(cat.Errors()))
	}

	cfg := loadConfig()
	prefs := loadPrefs()

	wsDir, err := engageWorkspaceDir(o.workspace)
	if err != nil {
		return fmt.Errorf("engage: %w", err)
	}
	ws, err := engagement.OpenWorkspace(wsDir)
	if err != nil {
		return fmt.Errorf("engage: cannot open workspace: %w", err)
	}
	defer ws.Close()
	if checkpoint == nil {
		kind, source := "none", ""
		if roeUsed != "" {
			kind, source = "roe", roeUsed
		} else if o.scope != "" {
			kind, source = "scope", o.scope
		}
		entry := engageCheckpoint{Goal: goal, ProjectDir: cwd, ScopeKind: kind, Auto: o.auto, AutoOverride: o.autoOverride}
		if err := saveEngageCheckpoint(ws.Dir, entry, source); err != nil {
			return fmt.Errorf("engage: checkpoint: %w", err)
		}
		if kind != "none" {
			saved, loadErr := loadEngageCheckpoint(ws.Dir)
			if loadErr != nil {
				return fmt.Errorf("engage: checkpoint: %w", loadErr)
			}
			scope, scopeDesc, roeUsed, err = checkpointScope(ws.Dir, saved)
			if err != nil {
				return fmt.Errorf("engage: snapshotted scope: %w", err)
			}
		}
	}

	// When no RoE was found and no explicit scope was given, drop a pre-formatted
	// ROE.md template into the workspace (idempotent; never overwrites).
	if checkpoint == nil && roeUsed == "" && strings.TrimSpace(o.scope) == "" {
		if _, werr := writeRoETemplate(ws.Dir); werr != nil {
			fmt.Fprintf(os.Stderr, "engage: could not write ROE.md template: %v\n", werr)
		}
	}
	policy.AutoActions, err = checkpointAutoActions(ws.Dir)
	if err != nil {
		return fmt.Errorf("engage: autonomous actions: %w", err)
	}

	tty := isTerminalFile(os.Stdin)
	var confirm secgate.Confirmer
	// The mmdflux viz session replaces this with its widget confirmer by assigning confirm here before the gate is built.
	// A terminal confirmer is provided on any TTY: /safe confirms every command,
	// /auto local confirms every command (the human is the positive control), and
	// /auto external falls back to HITL for a binary not in allowed_binaries.
	if tty {
		confirm = newTerminalConfirmer(os.Stdin, os.Stdout)
	}
	if scope != nil && scope.Local() && confirm == nil &&
		(mode != secgate.Auto || !policy.AutoActions.hasLocalRule() || !policy.LocalUnattendedReady) {
		return fmt.Errorf("engage: local/post-access engagements require interactive confirmation or RoE autonomous actions with local_unattended_binaries")
	}

	// The scratch dir lives outside the workspace: run_command's cwd, so a
	// relative ".." in a tool's file-writing flag cannot reach audit.jsonl,
	// engagement.db, or evidence inside ws.Dir (see secgate.FileAccessViolation
	// for the complementary path-policy check on the command args themselves).
	scratch, err := os.MkdirTemp("", "blkengage-")
	if err != nil {
		return fmt.Errorf("engage: cannot create scratch dir: %w", err)
	}
	defer os.RemoveAll(scratch)
	signalCtx, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignal()
	runCtx, cancelRun := context.WithCancelCause(signalCtx)
	defer cancelRun(nil)
	telemetry := newEngageTelemetry(ws, cancelRun)
	runCtx = withEngageTelemetry(runCtx, telemetry)

	gate := buildEngageGate(ws, scope, mode, confirm, secgate.NewSessionApprovals(), scratch, policy, telemetry.gate)
	if err := gate.Start(); err != nil {
		return fmt.Errorf("engage: %w", err)
	}

	var asker askuser.Asker = askuser.AutoAsker{}
	if mode == secgate.Safe && tty {
		asker = newTerminalAsker(os.Stdin, os.Stdout)
	}

	model, err := newOMLX(cfg, o.model)
	if err != nil {
		return fmt.Errorf("engage: %w", err)
	}
	rc, err := newRetrievalClient(cfg)
	if err != nil {
		return fmt.Errorf("engage: %w", err)
	}
	defer rc.Close()

	r := newVizRenderer(newMmdfluxRunner())
	deps := buildEngageDeps(model, rc, cfg, prefs, ws.Store, gate, scratch, cat, asker, confirm, makeEngageProgress(os.Stdout, r, prefs.Viz))
	deps.ExploitTools = policy.ExploitTools
	deps.AutoActions = policy.AutoActions
	deps.MaxActions, deps.WallSeconds = policy.MaxActions, policy.WallSeconds
	toolHelp, toolHelpClose := openToolHelpCache()
	defer toolHelpClose()
	deps.ToolHelp = toolHelp

	// Resumable engagement report: a projection of the store written to the
	// workspace, refreshed on each commit and rebuilt from the store on resume.
	modeStr := "safe"
	if o.auto {
		modeStr = "auto"
	}
	rw := newReportWriter(ws.Store, wsDir, goal, scopeDesc, modeStr)
	if err := rw.RestoreFinal(); err != nil {
		return fmt.Errorf("engage: prior report: %w", err)
	}
	if err := rw.Flush("in-progress"); err != nil {
		fmt.Fprintf(os.Stderr, "report: initial write failed: %v\n", err)
	}
	stopReport := rw.Start()
	defer stopReport()
	reportStatus := "complete"
	deps.OnStop = func(string) { reportStatus = "paused" }

	// Seed the engagement's initial vantage from scope: an external
	// engagement starts external-unauth (local/ad-cloud locked until a logged
	// access-yielding exploit advances the vantage); a local scope starts with an
	// internal foothold. A seed error is logged, not fatal.
	if serr := seedInitialVantage(context.Background(), ws.Store, scope); serr != nil {
		fmt.Fprintf(os.Stderr, "engage: vantage seed failed: %v\n", serr)
	}

	final, err := runOrchestrator(runCtx, deps, goal)
	stopReport() // stop the live render loop before the terminal flush (idempotent)
	if err != nil {
		if cause := context.Cause(runCtx); cause != nil && cause != context.Canceled {
			err = cause
		}
		status := "interrupted"
		if err == errEngageDenialBurst {
			status = "paused"
			rw.SetFinal(err.Error())
		}
		if ferr := rw.Flush(status); ferr != nil {
			fmt.Fprintf(os.Stderr, "report: final write failed: %v\n", ferr)
		}
		mdPath, jsonPath := reportPaths(wsDir)
		fmt.Fprintf(os.Stderr, "Report: %s\n        %s\n", mdPath, jsonPath)
		return fmt.Errorf("engage: %w", err)
	}
	rw.SetFinal(final)
	if ferr := rw.Flush(reportStatus); ferr != nil {
		fmt.Fprintln(os.Stdout, final)
		return fmt.Errorf("engage: final report write failed: %w", ferr)
	}
	// Fold the finished report into the REPL's persistent memory so it surfaces in
	// /history. Best-effort: a memory error never fails a completed engagement.
	if ierr := ingestEngageRun(wsDir); ierr != nil {
		fmt.Fprintf(os.Stderr, "history: could not record engagement: %v\n", ierr)
	}
	fmt.Fprintln(os.Stdout, final)
	mdPath, jsonPath := reportPaths(wsDir)
	fmt.Fprintf(os.Stdout, "\nReport: %s\n        %s\n", mdPath, jsonPath)
	return nil
}

// resolveEngageScope resolves the engagement scope from the flags and the
// project directory. An explicit --scope file wins (the back-compat line-based
// format). Otherwise an ROE.md in cwd, or the ROE.md remembered for cwd, is
// parsed into the extended scope and remembered for next time. With no scope
// source, scope is nil, scopeDesc is "(none)", and roeUsed is "" (the caller
// writes a workspace template). db may be nil (recall degrades to a miss).
func resolveEngageScope(o engageOpts, cwd string, db *sql.DB) (scope *secgate.Scope, scopeDesc, roeUsed string, err error) {
	if strings.TrimSpace(o.scope) != "" {
		f, oerr := os.Open(o.scope)
		if oerr != nil {
			return nil, "", "", fmt.Errorf("cannot read scope file: %w", oerr)
		}
		s, perr := secgate.ParseScope(f)
		f.Close()
		if perr != nil {
			return nil, "", "", perr
		}
		return s, o.scope, "", nil
	}
	roePath := ""
	cand := filepath.Join(cwd, "ROE.md")
	if fi, serr := os.Stat(cand); serr == nil && !fi.IsDir() {
		roePath = cand
	} else if p, ok := recallRoE(db, cwd); ok {
		roePath = p
	}
	if roePath == "" {
		return nil, "(none)", "", nil
	}
	f, oerr := os.Open(roePath)
	if oerr != nil {
		return nil, "", "", fmt.Errorf("cannot read ROE.md: %w", oerr)
	}
	roe, perr := ParseRoE(f)
	f.Close()
	if perr != nil {
		return nil, "", "", fmt.Errorf("ROE.md: %w", perr)
	}
	_ = rememberRoE(db, cwd, roePath) // best-effort recall-by-directory
	return roe.Scope, roePath, roePath, nil
}

// resolveEngageConfigPolicy autodetects .blkchain/config.yaml in cwd and builds
// the gate policy. The unattended-/auto bound (UnattendedAllow) is always set:
// an absent config yields an empty allowlist, so unattended /auto falls back to
// HITL (the no-allowlist floor, decision 8). The auto-scope override comes from
// the flag.
func resolveEngageConfigPolicy(o engageOpts, cwd string) (gatePolicy, error) {
	cfg, _, err := autodetectEngageConfig(cwd)
	if err != nil {
		return gatePolicy{}, err
	}
	var denied []string
	var exploitTools []string
	var localUnattended []string
	var maxActions, wallSeconds int
	poc := false
	// Default (no config): an empty, non-nil unattended bound, so unattended /auto
	// falls back to HITL (the no-allowlist floor).
	unattended := secgate.NewAllowlist()
	if cfg != nil {
		denied = cfg.DeniedBinaries
		maxActions, wallSeconds = cfg.MaxActions, cfg.WallSeconds
		poc = cfg.AllowInterpreterPoC
		exploitTools = cfg.ExploitTools
		localUnattended = cfg.LocalUnattendedBinaries
		if cfg.AllowedBinaries.All {
			// allowed_binaries: true -> everything allowed unattended (no bound).
			unattended = nil
		} else {
			unattended = secgate.NewAllowlist(cfg.AllowedBinaries.List...)
		}
	}
	return gatePolicy{
		DeniedBinaries:       denied,
		UnattendedAllow:      unattended,
		LocalUnattendedAllow: secgate.NewAllowlist(localUnattended...),
		LocalUnattendedReady: len(localUnattended) > 0,
		AllowInterpreterPoC:  poc,
		AutoScopeOverride:    o.autoOverride,
		MaxActions:           maxActions,
		WallSeconds:          wallSeconds,
		ExploitTools:         exploitTools,
	}, nil
}

// runEngageArm implements `blk engage arm [--workspace <dir>] <task-id>`: the
// operator-only arm action over armTask. It opens the engagement workspace (the
// most recent one under the config dir when --workspace is omitted), confirms the
// task is an exploit/post-ex task, sets Armed via armTask, and logs the arm to the
// workspace audit log. The model has no arming path (planTaskArgs carries no Armed
// field); only this operator command and the REPL arm affordance call armTask.
func runEngageArm(args []string) error {
	fs := newFlagSet("engage arm")
	var wsDir string
	fs.StringVar(&wsDir, "workspace", "", "engagement workspace directory (default: the most recent engagement)")
	if err := parseFlags(fs, reorder(args, map[string]bool{"workspace": true})); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 || strings.TrimSpace(rest[0]) == "" {
		return missingArg("engage arm", "missing task id", `engage arm t1   (or: engage arm --workspace <dir> t1)`)
	}
	taskID := strings.TrimSpace(rest[0])

	if wsDir == "" {
		latest, err := latestEngagementDir()
		if err != nil {
			return fmt.Errorf("engage arm: %w", err)
		}
		wsDir = latest
	}
	ws, err := engagement.OpenWorkspace(wsDir)
	if err != nil {
		return fmt.Errorf("engage arm: cannot open workspace %s: %w", wsDir, err)
	}
	defer ws.Close()

	task, err := ws.Store.GetTask(taskID)
	if err != nil {
		return fmt.Errorf("engage arm: task %q not found in %s: %w", taskID, wsDir, err)
	}
	if task.Phase != engagement.PhaseExploit && task.Phase != engagement.PhasePostEx {
		return fmt.Errorf("engage arm: task %q is phase %q; only exploit and post-ex tasks are armed", taskID, task.Phase)
	}
	if err := armTask(context.Background(), ws.Store, taskID); err != nil {
		return fmt.Errorf("engage arm: %w", err)
	}
	_ = ws.AuditLine("operator", "arm", taskID)
	fmt.Fprintf(os.Stdout, "armed task %s (%s/%s) in %s\n", taskID, task.Phase, task.Surface, wsDir)
	return nil
}

// latestEngagementDir returns the most recent timestamped engagement workspace
// under the config dir (~/.config/blkchain/engagements). The directory names are
// UTC timestamps (engageWorkspaceDir), so the lexical maximum is the newest.
func latestEngagementDir() (string, error) {
	cfgPath, err := configPath()
	if err != nil {
		return "", err
	}
	root := filepath.Join(filepath.Dir(cfgPath), "engagements")
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("no engagements found under %s (run `blk engage` first, or pass --workspace): %w", root, err)
	}
	latest := ""
	for _, e := range entries {
		if e.IsDir() && e.Name() > latest {
			latest = e.Name()
		}
	}
	if latest == "" {
		return "", fmt.Errorf("no engagement workspace found under %s; run `blk engage` first, or pass --workspace", root)
	}
	return filepath.Join(root, latest), nil
}

// engageWorkspaceDir returns dir when set, else a fresh, timestamped
// engagement directory under the config dir (~/.config/blkchain/engagements),
// so two engagements never collide and no part of the goal text reaches the
// filesystem path.
func engageWorkspaceDir(dir string) (string, error) {
	if dir != "" {
		return dir, nil
	}
	cfgPath, err := configPath()
	if err != nil {
		return "", err
	}
	name := time.Now().UTC().Format("20060102-150405")
	return filepath.Join(filepath.Dir(cfgPath), "engagements", name), nil
}
