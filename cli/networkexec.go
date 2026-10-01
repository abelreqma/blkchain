package main

import (
	"context"
	"fmt"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"

	"github.com/tmc/langchaingo/llms"
)

type networkExecutor struct {
	genericExecutor
}

// init registers the network executor. The network recon tier ladder is already
// defined in recon_ladder.go and the "recon" persona in domains.go, so this file
// only wires the executor factory; it registers neither a ladder nor a persona.
func init() {
	registerExecutor(engagement.SurfaceNetwork, func(d engageDeps) surfaceExecutor {
		return networkExecutor{genericExecutor{d: d}}
	})
}

// networkVantageSkew returns a one-line technique-emphasis note for the network
// recon tier prompt, skewed by the engagement vantage. Vantage is CONTEXT, not a
// persona axis: there is one network/recon persona, and this note only shifts
// which techniques it leans on. From outside (external or unset vantage) the
// emphasis is host/port/service enumeration; from an internal foothold or better
// it shifts to internal SMB/LDAP/SNMP and lateral-movement surface. The note is
// non-binding guidance appended to the tier prompt; the model still proposes
// structured commands that pass help-grounding and the gate.
func networkVantageSkew(v engagement.Vantage) string {
	// Reaches(SurfaceLocal) is true only at internal-foothold or higher, so it is
	// the external-vs-internal boundary (an unset vantage reads as external).
	if v.Reaches(engagement.SurfaceLocal) {
		return "Vantage context: internal foothold (" + string(v) + "). You are inside the network, so emphasize internal enumeration over external host discovery: SMB/NetBIOS shares and sessions (smbclient, rpcclient, nbtscan), LDAP/directory (ldapsearch), SNMP (snmpwalk), and the lateral-movement surface. Skew kb_search and route_skill queries toward internal network enumeration and lateral movement."
	}
	pos := string(v)
	if pos == "" {
		pos = "unset, treated as external"
	}
	return "Vantage context: external (" + pos + "). Enumerate from outside: emphasize host discovery, port and service sweeps, and service/version detection (nmap, DNS). Skew kb_search and route_skill queries toward external host, port, and service enumeration."
}

func (e networkExecutor) Run(ctx context.Context, task engagement.Task) (string, error) {
	if e.d.ReconTiers && task.Phase == engagement.PhaseRecon && e.d.Gate != nil && e.d.Runs != nil {
		// Read the vantage once, for the technique skew. The reachability refusal
		// below is defense-in-depth: SurfaceNetwork is reachable at every vantage
		// (engagement/vantage.go), so it never fires for this executor, but it fails
		// closed on a store read error and mirrors genericExecutor.Run's contract.
		v, err := e.d.Store.Vantage(ctx)
		if err != nil {
			return fmt.Sprintf("executor: task %s could not read the engagement vantage: %v", task.ID, err), nil
		}
		if v != "" && !v.Reaches(task.Surface) {
			return fmt.Sprintf("executor: task %s surface %q is not reachable at the current vantage %q; advance the vantage first", task.ID, task.Surface, v), nil
		}
		return e.networkRunReconPhase(ctx, task, v)
	}
	return e.genericExecutor.Run(ctx, task)
}

func (e networkExecutor) networkRunReconPhase(ctx context.Context, task engagement.Task, v engagement.Vantage) (string, error) {
	runTimeout, runCap := resolveRunCaps()
	execDir, cleanup, err := newExecutorScratchDir(e.d.WorkDir)
	if err != nil {
		return "", err
	}
	defer cleanup()

	cmdCtx := secgate.Command{
		Phase:   secgate.Phase(string(task.Phase)),
		Surface: secgate.Surface(string(task.Surface)),
		Armed:   task.Armed,
	}
	grounder := newTaskGrounder(e.d.ToolHelp, e.d.Gate, execDir, cmdCtx)
	activeTask := func() string { return task.ID }

	reg := tooldef.NewRegistry()
	for _, t := range []tooldef.Tool{
		newKBSearchTool(e.d.RC, e.d.Cfg),
		newKBAnswerTool(e.d.RC, e.d.Cfg, !e.d.Prefs.Web),
		newRouteSkillTool(e.d.Catalog, e.d.Store, activeTask),
		newRunCommandToolForTask(e.d.Gate, runCap, runTimeout, execDir, activeTask, e.d.Runs.Add, cmdCtx, grounder),
		newVerifiedRecordEvidenceTool(e.d.Store, e.d.Runs.Contains),
	} {
		if err := reg.Register(t); err != nil {
			return "", err
		}
	}

	dom := domainFor(task.Kind)

	var exploitSel exploitSelector
	if e.d.RC != nil {
		exploitSel = newKBExploitSelector(e.d.Model, e.d.RC, e.d.Cfg)
	}

	runTier := func(ctx context.Context, _ engagement.Surface, asset string, tier reconTier, sel reconSelection) (tierOutcome, error) {
		beforeCmds := e.d.Runs.Count(task.ID)
		beforeRows, err := e.d.Store.EvidenceRowsFor(task.ID)
		if err != nil {
			return tierOutcome{}, err
		}
		msgs := []llms.MessageContent{
			{Role: llms.ChatMessageTypeSystem, Parts: []llms.ContentPart{llms.TextPart(dom.Prompt)}},
			{Role: llms.ChatMessageTypeHuman, Parts: []llms.ContentPart{llms.TextPart(networkTierPrompt(task, asset, tier, sel, v))}},
		}
		if _, _, err := runToolLoop(ctx, e.d.Model, reg, msgs, LoopCaps{MaxRounds: 4, MaxCalls: 8}); err != nil {
			return tierOutcome{}, err
		}
		afterRows, err := e.d.Store.EvidenceRowsFor(task.ID)
		if err != nil {
			return tierOutcome{}, err
		}
		newRows := afterRows[len(beforeRows):]
		out := tierOutcomeFromSignals(tier, e.d.Runs.Count(task.ID)-beforeCmds, len(newRows))
		out.NewAssets = e.correlateNewEvidence(ctx, task.ID, newRows, exploitSel)
		return out, nil
	}

	d := reconDeps{
		Store:     e.d.Store,
		Surface:   task.Surface,
		Grader:    newLLMReconGrader(e.d.Model, e.d.Cfg),
		RunTier:   runTier,
		Backstop:  defaultReconBackstop(),
		Now:       time.Now,
		TaskIDFor: func(string) string { return task.ID },
	}
	if e.d.RC != nil {
		d.Selector = newKBReconSelector(e.d.Model, e.d.RC, e.d.Cfg)
	}
	res, err := ReconLoop(ctx, d, reconSeeds(task.Target), task.ID)
	if err != nil {
		return "", err
	}
	return reconSummary(task, res), nil
}

// networkTierPrompt is the per-tier human prompt for network recon: the shared
// per-tier instruction (reconTierPrompt) plus the vantage-skewed technique
// emphasis. One persona, vantage only colors the emphasis.
func networkTierPrompt(task engagement.Task, asset string, tier reconTier, sel reconSelection, v engagement.Vantage) string {
	return reconTierPrompt(task, asset, tier, sel) + "\n" + networkVantageSkew(v)
}
