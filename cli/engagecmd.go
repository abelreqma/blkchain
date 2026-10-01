package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	cwd, _ := os.Getwd()
	// Shared memory store for RoE recall-by-directory (best-effort; nil degrades).
	var roeDB *sql.DB
	if store := histstore.OpenDefault(); store != nil {
		defer store.Close()
		roeDB = store.DB()
	}

	scope, scopeDesc, roeUsed, err := resolveEngageScope(o, cwd, roeDB)
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

	// When no RoE was found and no explicit scope was given, drop a pre-formatted
	// ROE.md template into the workspace (idempotent; never overwrites).
	if roeUsed == "" && strings.TrimSpace(o.scope) == "" {
		if _, werr := writeRoETemplate(ws.Dir); werr != nil {
			fmt.Fprintf(os.Stderr, "engage: could not write ROE.md template: %v\n", werr)
		}
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
	// Fail closed: a local engagement with no way to confirm cannot run, because
	// every local command needs human approval and none is available off a TTY.
	if scope != nil && scope.Local() && confirm == nil {
		return fmt.Errorf("engage: local/post-access engagements require interactive confirmation; run on a TTY (or over MCP with confirm=elicit)")
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

	gate := buildEngageGate(ws, scope, mode, confirm, secgate.NewSessionApprovals(), scratch, policy, func(action, detail string) {
		_ = ws.AuditLine("secgate", action, detail)
	})
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
	if err := rw.Flush("in-progress"); err != nil {
		fmt.Fprintf(os.Stderr, "report: initial write failed: %v\n", err)
	}
	stopReport := rw.Start()
	defer stopReport()

	if serr := seedInitialVantage(context.Background(), ws.Store, scope); serr != nil {
		fmt.Fprintf(os.Stderr, "engage: vantage seed failed: %v\n", serr)
	}

	final, err := runOrchestrator(context.Background(), deps, goal)
	stopReport() // stop the live render loop before the terminal flush (idempotent)
	if err != nil {
		if ferr := rw.Flush("interrupted"); ferr != nil {
			fmt.Fprintf(os.Stderr, "report: final write failed: %v\n", ferr)
		}
		return fmt.Errorf("engage: %w", err)
	}
	if ferr := rw.Flush("complete"); ferr != nil {
		fmt.Fprintf(os.Stderr, "report: final write failed: %v\n", ferr)
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
	poc := false
	// Default (no config): an empty, non-nil unattended bound, so unattended /auto
	// falls back to HITL (the no-allowlist floor).
	unattended := secgate.NewAllowlist()
	if cfg != nil {
		denied = cfg.DeniedBinaries
		poc = cfg.AllowInterpreterPoC
		if cfg.AllowedBinaries.All {
			// allowed_binaries: true -> everything allowed unattended (no bound).
			unattended = nil
		} else {
			unattended = secgate.NewAllowlist(cfg.AllowedBinaries.List...)
		}
	}
	return gatePolicy{
		DeniedBinaries:      denied,
		UnattendedAllow:     unattended,
		AllowInterpreterPoC: poc,
		AutoScopeOverride:   o.autoOverride,
	}, nil
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
