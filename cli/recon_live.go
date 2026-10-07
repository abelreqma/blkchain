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
	execDir, cleanup, err := newExecutorScratchDir(ctx, e.d.WorkDir)
	if err != nil {
		return "", err
	}
	defer cleanup()

	// Stamp the task's engagement context so the gate tiers every run_command
	// (recon is auto-tier; the structural denials and scope always apply).
	cmdCtx := secgate.Command{
		TaskID:  task.ID,
		Phase:   secgate.Phase(string(task.Phase)),
		Surface: secgate.Surface(string(task.Surface)),
		Armed:   task.Armed,
		// Kind/Target carry the read-only invariant to the gate.
		Kind:   task.Kind,
		Target: task.Target,
	}
	grounder := newTaskGrounder(e.d.ToolHelp, e.d.Gate, execDir, cmdCtx)
	activeTask := func() string { return task.ID }

	reg := tooldef.NewRegistry()
	webTools, closeWeb := webToolsForTask(e.d.Gate, task, webCapture{Store: e.d.Store, Runs: e.d.Runs})
	defer closeWeb()
	tools := []tooldef.Tool{
		newKBSearchTool(e.d.RC, e.d.Cfg),
		newKBAnswerTool(e.d.RC, e.d.Cfg, !e.d.Prefs.Web),
		newRouteSkillTool(e.d.Catalog, e.d.Store, activeTask),
		newRunCommandToolForTask(e.d.Gate, runCap, runTimeout, execDir, activeTask, e.d.Runs.Add, cmdCtx, grounder),
		newVerifiedRecordEvidenceTool(e.d.Store, e.d.Runs.Contains),
	}
	tools = append(tools, webTools...)
	for _, t := range tools {
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

	// runTier drives one tier: it asks the model to perform only this tier's step
	// for this asset through the gated tools, then derives the outcome from code-
	// owned signals - commands captured and evidence recorded for the task - never
	// from the model's say-so. The evidence this pass recorded is parsed in code:
	// newly discovered in-scope assets recurse per-asset, and discovered
	// services correlate to candidate exploit tasks.
	runTier := func(ctx context.Context, _ engagement.Surface, asset string, tier reconTier, sel reconSelection) (tierOutcome, error) {
		beforeCmds := e.d.Runs.Count(task.ID)
		beforeRows, err := e.d.Store.EvidenceRowsFor(task.ID)
		if err != nil {
			return tierOutcome{}, err
		}
		msgs := []llms.MessageContent{
			{Role: llms.ChatMessageTypeSystem, Parts: []llms.ContentPart{llms.TextPart(effectiveEngagePrompt(e.d.Gate, dom.Prompt))}},
			{Role: llms.ChatMessageTypeHuman, Parts: []llms.ContentPart{llms.TextPart(reconTierPrompt(task, asset, tier, sel))}},
		}
		if _, _, err := runToolLoop(ctx, e.d.Model, reg, msgs, LoopCaps{MaxRounds: 4, MaxCalls: 8}); err != nil {
			return tierOutcome{}, err
		}
		// Code-side evidence capture: the model's record_evidence is not relied on.
		// captureTierEvidence returns the model's rows when it recorded any, else a
		// code-side backstop records this pass's captured command output as evidence
		// (so a row exists regardless of the model), and surfaces a coverage-gap when
		// nothing was captured at all.
		newRows, err := e.captureTierEvidence(task.ID, string(task.Surface), asset, tier.Name, beforeRows, beforeCmds)
		if err != nil {
			return tierOutcome{}, err
		}
		out := tierOutcomeFromSignals(tier, e.d.Runs.Count(task.ID)-beforeCmds, len(newRows))
		out.NewAssets = e.correlateNewEvidence(ctx, task.ID, asset, newRows, exploitSel)
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

// coverageGapMarker is appended to a coverage-gap candidate's Objective so the
// operator sees, in the plan/REPL, that it was detected deterministically but has
// no grounding citation and is not actionable yet.
const coverageGapMarker = " [corpus-coverage-gap: no grounding citation; non-actionable until grounded]"

// markCoverageGap turns a deterministic-detector candidate that found no accepted
// citation into a NON-ACTIONABLE coverage-gap candidate: Status blocked (the arm
// step refuses a blocked candidate), empty Citation, and the Objective marker. The
// candidate is still emitted and operator-visible (no silent drop); the caller
// writes the paired "corpus-coverage-gap" audit row.
func markCoverageGap(cand *engagement.Task) {
	cand.Status = engagement.StatusBlocked
	cand.CoverageGap = true
	cand.Citation = engagement.Citation{}
	if !strings.Contains(cand.Objective, "corpus-coverage-gap") {
		cand.Objective += coverageGapMarker
	}
}

// tierOutcomeFromSignals turns the code-owned per-tier deltas into a tierOutcome:
// a tier that recorded at least one new verified evidence quote has covered its
// dimensions. The caller fills NewAssets from the parsed evidence.
// captureTierEvidence returns the evidence rows a tier pass produced, with a
// code-side backstop so evidence-row creation does not depend on the model
// calling record_evidence (the latent no-silent-drop gap: a surface whose model
// never records drops its findings and loops to the round cap).
//
//   - If the model recorded rows this pass, they are returned unchanged (the
//     model-curated path; no backstop, so no double-count).
//   - Else the backstop records the command output captured THIS pass to d.Runs
//     as authoritative evidence, sourced ONLY from captured output (already
//     capBytes-bounded) and never from model text (no fabrication).
//   - If even then nothing was captured, the pass made no progress: it surfaces a
//     recon coverage-gap audit (no-silent-drop) and returns no rows.
//
// It mirrors localexec's code-side evidence precedent, made conditional so it
// coexists with the model path.
func (e genericExecutor) captureTierEvidence(taskID, surface, asset, tierName string, beforeRows []engagement.EvidenceRow, beforeCmds int) ([]engagement.EvidenceRow, error) {
	afterRows, err := e.d.Store.EvidenceRowsFor(taskID)
	if err != nil {
		return nil, err
	}
	// Evidence is append-only, so rows past the pre-pass length are this pass's.
	if modelRows := afterRows[len(beforeRows):]; len(modelRows) > 0 {
		return modelRows, nil
	}
	// Backstop: the model recorded nothing this pass. Record the command output
	// captured this pass (outputs added to d.Runs after beforeCmds) as evidence.
	outputs := e.d.Runs.Outputs(taskID)
	for i := beforeCmds; i < len(outputs); i++ {
		if strings.TrimSpace(outputs[i]) == "" {
			continue
		}
		if _, err := e.d.Store.RecordEvidence(taskID, outputs[i]); err != nil {
			return nil, err
		}
	}
	afterRows, err = e.d.Store.EvidenceRowsFor(taskID)
	if err != nil {
		return nil, err
	}
	newRows := afterRows[len(beforeRows):]
	if len(newRows) == 0 {
		// No model evidence and nothing captured: no progress. Surface a recon
		// coverage-gap so the no-evidence outcome is recorded, never silently
		// dropped. (Correlation surfaces finding-level gaps; this is the tier
		// no-evidence gap.)
		if err := e.d.Store.Audit("recon", "coverage-gap", surface+"/"+asset+"/"+tierName+": tier produced no evidence"); err != nil {
			return nil, err
		}
	}
	return newRows, nil
}

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
//
// asset is the host this tier pass scanned, which the recon ladder supplies. A
// service row parsed without a host of its own takes it as the candidate's
// target, so a model-curated quote that holds the service table without the
// scan report header still yields an addressable candidate.
func (e genericExecutor) correlateNewEvidence(ctx context.Context, taskID, asset string, newRows []engagement.EvidenceRow, sel exploitSelector) []string {
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
	// auditFn writes the shared "corpus-coverage-gap" audit row for a coverage-gap
	// candidate (finalizeCandidate/groundCandidate call it), so every detector
	// surfaces a gap through the one audit path.
	auditFn := func(action, detail string) { _ = e.d.Store.Audit("correlate", action, detail) }
	fallbackHost := assetFallbackHost(asset)
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
			if svc.Host == "" {
				svc.Host = fallbackHost
			}
			if svc.Host == "" {
				// Without a host there is no target to act on, and the candidate's
				// id would collide with every other hostless one on this port. The
				// finding is surfaced rather than dropped silently.
				auditFn("missing-host", fmt.Sprintf("%s port=%d product=%q reason=no-host-in-evidence-or-asset", taskID, svc.Port, svc.Product))
				continue
			}
			cand, inCatalog := correlateService(svc)
			var tech string
			var cit engagement.Citation
			if sel != nil && svc.Prov.valid() {
				tech, cit = sel(ctx, svc)
			}
			if !inCatalog {
				// Path 2: no deterministic detector match, so the CORPUS grounding is
				// the detection. Emit ONLY when grounded (an accepted citation) AND the
				// model named a technique; otherwise there is genuinely no finding (emit
				// nothing - not a drop). Fields stay code-derived (candidateTask).
				if tech == "" || cit.Source == "" {
					continue
				}
				cand = candidateTask(svc, tech)
				cand.Citation = cit
			} else {

				if tech != "" && cit.Source != "" {
					cand.Objective = cand.Objective + "; technique: " + tech
				}
				cand = finalizeCandidate(cand, cit, auditFn,
					fmt.Sprintf("%s product=%q ver=%q reason=no-accepted-citation", cand.ID, svc.Product, svc.Version))
			}
			if candSeen[cand.ID] {
				continue
			}
			candSeen[cand.ID] = true
			candidates = append(candidates, cand)
		}

		for _, hit := range logicGapHits(prov, r.Quote) {
			cand := groundCandidate(ctx, e.d.RC, e.d.Cfg, auditFn, hit.Task, hit.Query, hit.Term)
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

// reconSeeds returns the seed assets for a recon task from its target. An empty
// target yields no seeds (nothing to recon). Splitting a CIDR or a target list
// into individual assets is surface-executor work; the target is one seed asset.
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
			"Perform ONLY this tier's step for this asset now. Use current coverage and observed evidence to select "+
			"the highest-value unresolved question in this tier. Issue one bounded run_command call now (structured argv, no shell, in scope). "+
			"Then inspect its actual output and state the hypothesis, prerequisite, and expected signal. "+
			"Record an exact quote of material output with record_evidence for this task id. Do not repeat completed "+
			"probes or move to other tiers or assets; the harness advances the ladder.",
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
