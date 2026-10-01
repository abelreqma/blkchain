package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"

	"github.com/tmc/langchaingo/llms"
)

// recon_live.go wires the ReconLoop engine (recon.go) into the live, gated
// executor. It is the adapter genericExecutor.Run calls for a recon-phase task:
// it builds the same gated tool set the generic loop uses (run_command with
// help-grounding, verified record_evidence, and read-only kb_search/route_skill
// enrichment) and hands ReconLoop a tierRunner that drives those tools once per
// tier, plus the LLM sufficiency grader. Code owns the ladder, saturation, the
// backstop, and per-asset recursion; the LLM only proposes commands within a
// tier and grades.

// runReconPhase runs the recon tier ladder for one recon-phase task. The caller
// (genericExecutor.Run) has already applied the vantage check.
func (e genericExecutor) runReconPhase(ctx context.Context, task engagement.Task) (string, error) {
	runTimeout, runCap := resolveRunCaps()
	execDir, cleanup, err := newExecutorScratchDir(e.d.WorkDir)
	if err != nil {
		return "", err
	}
	defer cleanup()

	// Stamp the task's engagement context so the gate tiers every run_command
	// (recon is auto-tier; the structural denials and scope always apply).
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

	// Corpus technique advisor for correlation, read-only; nil when retrieval is
	// unavailable (the pure-catalog path). Built once and shared across tiers so
	// it caches per product.
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
			{Role: llms.ChatMessageTypeHuman, Parts: []llms.ContentPart{llms.TextPart(reconTierPrompt(task, asset, tier, sel))}},
		}
		if _, _, err := runToolLoop(ctx, e.d.Model, reg, msgs, LoopCaps{MaxRounds: 4, MaxCalls: 8}); err != nil {
			return tierOutcome{}, err
		}
		afterRows, err := e.d.Store.EvidenceRowsFor(task.ID)
		if err != nil {
			return tierOutcome{}, err
		}
		// Evidence is append-only, so the rows past the pre-pass length are exactly
		// what this pass recorded.
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
	// Corpus-driven next-action selection, read-only, only when retrieval is
	// available. A nil selector is the pure-ladder path.
	if e.d.RC != nil {
		d.Selector = newKBReconSelector(e.d.Model, e.d.RC, e.d.Cfg)
	}
	res, err := ReconLoop(ctx, d, reconSeeds(task.Target), task.ID)
	if err != nil {
		return "", err
	}
	return reconSummary(task, res), nil
}

// tierOutcomeFromSignals turns the code-owned per-tier deltas into a tierOutcome:
// a tier that recorded at least one new verified evidence quote has covered its
// dimensions. The caller fills NewAssets from the parsed evidence.
func tierOutcomeFromSignals(tier reconTier, commandDelta, evidenceDelta int) tierOutcome {
	out := tierOutcome{Commands: commandDelta}
	if evidenceDelta > 0 {
		out.DimensionsCovered = tier.Dimensions
	}
	return out
}

// correlateNewEvidence parses the evidence rows a tier pass recorded into (a)
// newly discovered in-scope assets, returned for per-asset recon recursion, and
// (b) candidate exploit tasks, which it applies to the store (unarmed; the gate
// enforces arming at execution time). Provenance is the running task plus each
// quote's row id. The selector, when set, only annotates a candidate's objective
// with the advised technique and its corpus basis (provenance); the
// deterministic catalog owns whether a candidate exists. An out-of-scope asset
// is never returned for recursion.
func (e genericExecutor) correlateNewEvidence(ctx context.Context, taskID string, newRows []engagement.EvidenceRow, sel exploitSelector) []string {
	// The in-scope filter below needs a scope. In production all three engage
	// entry paths build a non-nil gate, and a scope is present for any engagement
	// that defines targets; a nil scope (e.g. a Safe-mode run with no scope)
	// skips the filter here, but an out-of-scope recon command still fails closed
	// at the gate, so recursion onto such a host cannot actually execute. The
	// filter is a defense-in-depth pre-prune, not the sole scope control.
	var scope *secgate.Scope
	if e.d.Gate != nil {
		scope = e.d.Gate.Scope
	}
	assetSeen := map[string]bool{}
	candSeen := map[string]bool{}
	var newAssets []string
	var candidates []engagement.Task
	for _, r := range newRows {
		prov := Provenance{TaskID: taskID, EvidenceID: r.ID}
		for _, a := range parseAssets(prov, r.Quote) {
			if a.Host == "" || assetSeen[a.Host] {
				continue
			}
			if scope != nil && !scope.InScope(a.Host) {
				continue
			}
			assetSeen[a.Host] = true
			newAssets = append(newAssets, a.Host)
		}
		for _, svc := range parseServices(prov, r.Quote) {
			cand, ok := correlateService(svc)
			if !ok || candSeen[cand.ID] {
				continue
			}
			candSeen[cand.ID] = true
			if sel != nil {
				if tech, cit := sel(ctx, svc); tech != "" {
					cand.Objective = cand.Objective + "; technique: " + tech

					cand.Citation = cit
				}
			}
			candidates = append(candidates, cand)
		}

		for _, cand := range correlateLogicGaps(prov, r.Quote) {
			if candSeen[cand.ID] {
				continue
			}
			candSeen[cand.ID] = true
			candidates = append(candidates, cand)
		}
	}
	if len(candidates) > 0 {
		if _, err := e.d.Store.Apply(engagement.Delta{Kind: "correlate", Detail: taskID, Upserts: candidates}); err != nil {
			_ = e.d.Store.Audit("correlate", "apply-failed", err.Error())
		}
	}
	return newAssets
}

func reconSeeds(target string) []string {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	return []string{target}
}

// reconTierPrompt instructs the model to perform only this tier's step for this
// asset, using run_command and recording an exact-quote of real output. When the
// selector prioritized a technique (sel.Parsed), it is offered as non-binding
// guidance; the model still proposes structured commands that pass grounding and
// the gate.
func reconTierPrompt(task engagement.Task, asset string, tier reconTier, sel reconSelection) string {
	hint := ""
	if sel.Parsed && sel.Action != "" {
		hint = fmt.Sprintf("Corpus-prioritized technique for this tier (guidance, not a command): %s\n", sel.Action)
	}
	return fmt.Sprintf(
		"Engagement recon task %s on the %s surface.\n"+
			"Asset: %s\n"+
			"Tier: %s (coverage: %s)\n"+
			"Objective: %s\n"+
			"%s\n"+
			"Perform ONLY this tier's step for this asset now. Propose commands with run_command "+
			"(structured argv, no shell, in scope). When a command returns useful output, record an "+
			"exact quote of it with record_evidence for this task id. Do not move on to other tiers or "+
			"other assets; the harness advances the ladder.",
		task.ID, task.Surface, asset, tier.Name, strings.Join(tier.Dimensions, ", "), task.Objective, hint)
}

// reconSummary renders the loop outcome for the executor's return value.
func reconSummary(task engagement.Task, res reconResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "recon task %s (%s surface): %d asset(s), %d tier pass(es), %d command(s); ",
		task.ID, task.Surface, len(res.Assets), res.Tiers, res.Commands)
	if res.Halted {
		fmt.Fprintf(&b, "backstop-halted (%s) - human review needed", res.HaltReason)
	} else {
		fmt.Fprintf(&b, "stopped: %s", res.StopReason)
	}
	return b.String()
}
