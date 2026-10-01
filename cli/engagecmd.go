package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/engagement"
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
	scope     string
	auto      bool
	workspace string
	model     string
}

// defineEngageFlags declares `blk engage`'s flags.
func defineEngageFlags(fs *flag.FlagSet, o *engageOpts) {
	fs.StringVar(&o.scope, "scope", "", "scope file: in-scope targets, `local`, and `allow <bin>` lines")
	fs.BoolVar(&o.auto, "auto", false, "run without confirmation prompts (bounded by scope); requires --scope")
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
	if o.auto && strings.TrimSpace(o.scope) == "" {
		return usageErr(`engage: --auto requires --scope. Example: blk engage --auto --scope scope.txt "enumerate 10.0.0.5". See "blk help engage".`)
	}

	var scope *secgate.Scope
	if o.scope != "" {
		f, err := os.Open(o.scope)
		if err != nil {
			return fmt.Errorf("engage: cannot read scope file: %w", err)
		}
		s, perr := secgate.ParseScope(f)
		f.Close()
		if perr != nil {
			return fmt.Errorf("engage: %w", perr)
		}
		scope = s
	}

	mode := secgate.Safe
	if o.auto {
		mode = secgate.Auto
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

	tty := isTerminalFile(os.Stdin)
	var confirm secgate.Confirmer
	// The mmdflux viz session replaces this with its widget confirmer by assigning confirm here before the gate is built.
	// A local/post-access engagement requires per-command confirmation in every
	// mode (the human is the positive control), so a terminal confirmer is
	// provided for /auto local too, not only /safe.
	if tty && (mode == secgate.Safe || (scope != nil && scope.Local())) {
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

	gate := buildEngageGate(ws, scope, mode, confirm, secgate.NewSessionApprovals(), scratch, func(action, detail string) {
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

	// Resumable engagement report: a projection of the store written to the
	// workspace, refreshed on each commit and rebuilt from the store on resume.
	modeStr := "safe"
	if o.auto {
		modeStr = "auto"
	}
	scopeDesc := o.scope
	if scopeDesc == "" {
		scopeDesc = "(none)"
	}
	rw := newReportWriter(ws.Store, wsDir, goal, scopeDesc, modeStr)
	if err := rw.Flush("in-progress"); err != nil {
		fmt.Fprintf(os.Stderr, "report: initial write failed: %v\n", err)
	}
	stopReport := rw.Start()
	defer stopReport()

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
