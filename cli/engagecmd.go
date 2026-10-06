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
	roe          string
	safe         bool
	transcript   string
	resume       string
	scope        string
	auto         bool
	autoOverride bool
	workspace    string
	model        string
}

// defineEngageFlags declares `blk engage`'s flags.
func defineEngageFlags(fs *flag.FlagSet, o *engageOpts) {
	fs.StringVar(&o.roe, "roe", "", "operator ROE.md path")
	fs.BoolVar(&o.safe, "safe", false, "enable interactive action approval")
	fs.StringVar(&o.transcript, "transcript", "important", "action output: off, important, or full")
	fs.StringVar(&o.resume, "resume", "", "continue an interrupted engagement workspace")
	fs.BoolVar(&o.auto, "auto", false, "run RoE-authorized actions without prompts (default)")
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
	if len(args) > 0 {
		switch args[0] {
		case "web":
			return runWebAnalysis(args[1:])
		case "arm":
			return runEngageArm(args[1:])
		case "resume":
			return runEngageResume(args[1:])
		case "setup":
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			return setupEngageRunner(ctx)
		case "stop":
			return stopEngageWorkspace(args[1:])
		case "migrate":
			return migrateEngagePolicy(args[1:])
		}
	}
	o, goal, err := parseEngageArgs(args)
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	var db *sql.DB
	if store := histstore.OpenDefault(); store != nil {
		defer store.Close()
		db = store.DB()
	}
	var confirm secgate.Confirmer
	var asker askuser.Asker = askuser.AutoAsker{}
	if o.safe && isTerminalFile(os.Stdin) {
		confirm = newTerminalConfirmer(os.Stdin, os.Stdout)
		asker = newTerminalAsker(os.Stdin, os.Stdout)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	renderer := newVizRenderer(newMmdfluxRunner())
	prefs := loadPrefs()
	final, err := runEngageSession(ctx, engageRunInput{Opts: o, Cwd: cwd, Goal: goal, Cfg: loadConfig(), Prefs: prefs, Confirm: confirm, Asker: asker, DB: db, Progress: makeEngageProgress(os.Stdout, renderer, prefs.Viz), Output: os.Stdout})
	if final != "" {
		fmt.Fprintln(os.Stdout, terminalSafe(final))
	}
	return err
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
