package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"blkchain/cli/internal/engagement"
)

// recon.go is the code-orchestrated recon tier loop (ReconLoop). It mirrors
// rag.AnswerLoop: code owns every control-flow decision - which tier runs next,
// when an asset is saturated, when to recurse into a newly discovered asset, and
// when a deterministic backstop halts the run - while the LLM only advises
// through the sufficiency grader. The loop never lets the grader extend autonomy
// past the backstop, and a malformed grader reply stops the loop (fail-closed).

// tierOutcome is what running one tier on one asset produced. NewAssets are
// newly discovered in-scope assets that recurse (per-asset, not a global
// restart); DimensionsCovered are the coverage dimensions this pass satisfied;
// Commands is how many commands the pass executed (counts toward the budget).
type tierOutcome struct {
	NewAssets         []string
	DimensionsCovered []string
	Commands          int
}

// tierRunner runs one tier on one asset and reports what it found. sel is the
// corpus-driven prioritization for this tier (empty when there is no selector or
// the selector failed closed to the ladder step). The live adapter drives the
// gated surface executor; tests inject a fake.
type tierRunner func(ctx context.Context, surface engagement.Surface, asset string, tier reconTier, sel reconSelection) (tierOutcome, error)

// reconDeps carries what ReconLoop needs. Grader and RunTier are func-field
// seams so the loop runs with no LLM and no gate. Now is an injectable clock for
// the wall-clock backstop (nil uses time.Now). TaskIDFor maps an already-known
// asset to the task id that should be the basis for assets it discovers (nil, or
// an empty return, falls back to the loop's basisTaskID).
type reconDeps struct {
	Store   *engagement.Store
	Surface engagement.Surface
	Grader  reconGrader
	RunTier tierRunner
	// Selector, when set, prioritizes the next probe within the tier nextTier
	// already chose (corpus-driven, read-only). It fails closed to the
	// deterministic ladder step (an empty selection), distinct from the saturation
	// grader which fails closed to STOP. nil is the pure-ladder path.
	Selector  reconSelector
	Backstop  reconBackstop
	Now       func() time.Time
	TaskIDFor func(asset string) string
}

// reconResult is the outcome of a ReconLoop run. Halted is true only when the
// deterministic backstop stopped the run (HaltReason names which bound);
// StopReason always names why the loop ended (a backstop reason, or one of
// checklist-complete / novelty-zero / grader-stop / grader-parse-fail).
type reconResult struct {
	Halted     bool
	HaltReason reconHalt
	StopReason string
	Assets     []string
	Commands   int
	Tiers      int
}

// ReconLoop runs the per-surface tier ladder over seedAssets with per-asset
// recursion, code-computed saturation, the fail-closed grader, and the
// deterministic backstop. It persists ReconCoverage via Delta and records each
// newly discovered asset as a recon task (plan_add + basis_ids). basisTaskID is
// the default provenance for a discovered asset when TaskIDFor gives none.
func ReconLoop(ctx context.Context, d reconDeps, seedAssets []string, basisTaskID string) (reconResult, error) {
	ladder := ladderFor(d.Surface)
	now := d.Now
	if now == nil {
		now = time.Now
	}
	start := now()

	var queue []string
	seen := map[string]bool{}
	var order []string
	enqueue := func(a string) {
		if a == "" || seen[a] {
			return
		}
		seen[a] = true
		queue = append(queue, a)
		order = append(order, a)
	}
	for _, a := range seedAssets {
		enqueue(a)
	}

	totalTiers, totalCommands := 0, 0
	stopReason := "checklist-complete"

	for len(queue) > 0 {
		asset := queue[0]
		queue = queue[1:]
		cov, err := loadOrInitCoverage(d.Store, d.Surface, asset, ladder)
		if err != nil {
			return reconResult{}, err
		}

	inner:
		for {
			if h := d.Backstop.check(totalTiers, totalCommands, len(seen), now().Sub(start)); h != haltNone {
				_ = d.Store.Audit("recon", "backstop-halted", string(h))
				return reconResult{
					Halted: true, HaltReason: h, StopReason: string(h),
					Assets: order, Commands: totalCommands, Tiers: totalTiers,
				}, nil
			}

			tier, ok := nextTier(ladder, cov)
			if !ok {
				stopReason = "checklist-complete"
				break inner
			}

			// Corpus-driven selection operates strictly WITHIN the tier the ladder
			// already chose - it can prioritize the probe but cannot jump a tier,
			// skip saturation, or override the backstop. It fails closed to the
			// deterministic ladder step (an empty selection), never inventing an
			// action. This is distinct from the saturation grader (which stops).
			sel := reconSelection{}
			if d.Selector != nil {
				if s := d.Selector(ctx, d.Surface, asset, tier, cov); s.Parsed {
					sel = s
					if s.Basis != "" {
						_ = d.Store.Audit("recon", "select", asset+"/"+tier.Name+": "+s.Basis)
					}
				}
			}

			outcome, err := d.RunTier(ctx, d.Surface, asset, tier, sel)
			if err != nil {
				return reconResult{}, fmt.Errorf("recon tier %s on %s: %w", tier.Name, asset, err)
			}
			totalTiers++
			totalCommands += outcome.Commands
			cov.IterationCount++

			novelty := false
			for _, dim := range outcome.DimensionsCovered {
				if isLadderDim(ladder, dim) && cov.Dimensions[dim] != engagement.ReconCovered {
					cov.Dimensions[dim] = engagement.ReconCovered
					novelty = true
				}
			}

			var newCov []engagement.ReconCoverage
			var newTasks []engagement.Task
			for _, na := range outcome.NewAssets {
				if na == "" || seen[na] {
					continue
				}
				enqueue(na)
				newCov = append(newCov, initCoverage(d.Surface, na, ladder))
				newTasks = append(newTasks, d.newReconTask(na, asset, basisTaskID))
				novelty = true
			}

			if err := d.persistTierPass(asset, tier, &cov, novelty, newCov, newTasks); err != nil {
				return reconResult{}, err
			}

			// Saturation: continue only if the checklist is incomplete AND this
			// pass produced novelty AND the grader says continue. Any one failing
			// stops this asset. A grader parse-failure stops (fail-closed).
			if checklistComplete(ladder, cov) {
				stopReason = "checklist-complete"
				break inner
			}
			if !novelty {
				stopReason = "novelty-zero"
				break inner
			}
			v := d.Grader(ctx, d.Surface, asset, coverageSummary(cov))
			if !v.Parsed {
				stopReason = "grader-parse-fail"
				break inner
			}
			if !v.Continue {
				stopReason = "grader-stop"
				break inner
			}
		}
	}

	return reconResult{
		StopReason: stopReason,
		Assets:     order,
		Commands:   totalCommands,
		Tiers:      totalTiers,
	}, nil
}

// persistTierPass writes the tier pass's coverage, any newly discovered assets'
// coverage rows, and their recon tasks in ONE Delta. A novel pass marks the
// asset's row with the ReconNoveltyThisRev sentinel, which applyLocked resolves
// to the committing revision - so the novelty revision is recorded without a
// second write. The sentinel goes on a copy, so the in-memory cov is not
// polluted across iterations.
func (d reconDeps) persistTierPass(asset string, tier reconTier, cov *engagement.ReconCoverage, novelty bool, newCov []engagement.ReconCoverage, newTasks []engagement.Task) error {
	row := *cov
	if novelty {
		row.LastNoveltyRev = engagement.ReconNoveltyThisRev
	}
	upserts := append([]engagement.ReconCoverage{row}, newCov...)
	_, err := d.Store.Apply(engagement.Delta{
		Kind:         "recon_tier",
		Detail:       asset + "/" + tier.Name,
		ReconUpserts: upserts,
		Upserts:      newTasks,
	})
	return err
}

// newReconTask builds the recon task for a newly discovered asset. It is stamped
// Phase=recon and the loop's surface, with basis_ids tracing provenance to the
// asset that discovered it (via TaskIDFor, else the loop's basisTaskID).
func (d reconDeps) newReconTask(asset, fromAsset, basisTaskID string) engagement.Task {
	basis := basisTaskID
	if d.TaskIDFor != nil {
		if id := d.TaskIDFor(fromAsset); id != "" {
			basis = id
		}
	}
	var basisIDs []string
	if basis != "" {
		basisIDs = []string{basis}
	}
	return engagement.Task{
		ID:        reconTaskID(asset),
		Kind:      "recon",
		Target:    asset,
		Objective: "recon newly discovered asset " + asset,
		Status:    engagement.StatusTodo,
		Phase:     engagement.PhaseRecon,
		Surface:   d.Surface,
		BasisIDs:  basisIDs,
	}
}

// loadOrInitCoverage returns the stored coverage for (surface, asset), filling
// any ladder dimension the stored row lacks with ReconPending, or a fresh
// all-pending row when none is stored.
func loadOrInitCoverage(st *engagement.Store, surface engagement.Surface, asset string, ladder reconLadder) (engagement.ReconCoverage, error) {
	cov, found, err := st.ReconCoverageFor(surface, asset)
	if err != nil {
		return engagement.ReconCoverage{}, err
	}
	if !found {
		return initCoverage(surface, asset, ladder), nil
	}
	if cov.Dimensions == nil {
		cov.Dimensions = map[string]engagement.ReconDimStatus{}
	}
	for _, dim := range ladder.allDimensions() {
		if _, ok := cov.Dimensions[dim]; !ok {
			cov.Dimensions[dim] = engagement.ReconPending
		}
	}
	return cov, nil
}

// initCoverage builds a fresh coverage row with every ladder dimension pending.
func initCoverage(surface engagement.Surface, asset string, ladder reconLadder) engagement.ReconCoverage {
	dims := map[string]engagement.ReconDimStatus{}
	for _, dim := range ladder.allDimensions() {
		dims[dim] = engagement.ReconPending
	}
	return engagement.ReconCoverage{Surface: surface, Asset: asset, Dimensions: dims}
}

// isLadderDim reports whether dim is a dimension of the ladder, so an outcome
// cannot mark a coverage dimension the ladder does not define.
func isLadderDim(l reconLadder, dim string) bool {
	for _, d := range l.allDimensions() {
		if d == dim {
			return true
		}
	}
	return false
}

// reconTaskID is a stable task id for an asset's recon task, with characters
// outside [A-Za-z0-9._-] replaced so the id is safe to key on.
func reconTaskID(asset string) string {
	var b strings.Builder
	b.WriteString("recon-")
	for _, r := range asset {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// coverageSummary renders a compact, deterministic "dim: status" list for the
// grader prompt.
func coverageSummary(cov engagement.ReconCoverage) string {
	keys := make([]string, 0, len(cov.Dimensions))
	for k := range cov.Dimensions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+string(cov.Dimensions[k]))
	}
	return strings.Join(parts, ", ")
}
