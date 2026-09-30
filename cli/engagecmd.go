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

// defaultEngageAllowlist is the base allowlist merged with the scope's allow
// lines. It is conservative: shells, wrappers, and interpreters (sudo, env,
// bash, sh, python, find, xargs) are excluded because secgate's classifier
// denies them outright regardless of the allowlist, so listing them here would
// only be misleading. An operator who needs one of those tools runs it by
// hand, outside run_command.
func defaultEngageAllowlist() []string {
	return []string{
		"nmap", "curl", "wget", "dig", "whois", "nc", "ncat",
		"id", "whoami", "uname", "hostname", "ps", "ls", "cat", "head", "tail", "grep",
		"stat", "getcap", "ss", "netstat", "ip", "ifconfig",
	}
}

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

	allowBins := defaultEngageAllowlist()
	if scope != nil {
		allowBins = append(allowBins, scope.AllowedBins()...)
	}
	allow := secgate.NewAllowlist(allowBins...)

	tty := isTerminalFile(os.Stdin)
	var confirm secgate.Confirmer
	if mode == secgate.Safe && tty {
		confirm = newTerminalConfirmer(os.Stdin, os.Stdout)
	}

	gate := &secgate.Gate{
		Mode:      mode,
		Scope:     scope,
		Allow:     allow,
		Confirm:   confirm,
		Approvals: secgate.NewSessionApprovals(),
		Audit: func(action, detail string) {
			_ = ws.AuditLine("secgate", action, detail)
		},
	}
	if err := gate.Start(); err != nil {
		return fmt.Errorf("engage: %w", err)
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
	deps := engageDeps{
		Model:    model,
		RC:       rc,
		Cfg:      cfg,
		Prefs:    prefs,
		Store:    ws.Store,
		Asker:    asker,
		Gate:     gate,
		Runs:     NewRunOutputs(),
		WorkDir:  scratch,
		Catalog:  cat,
		Progress: makeEngageProgress(os.Stdout, r, prefs.Viz),
	}

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
