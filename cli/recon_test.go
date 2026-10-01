package main

import (
	"context"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
)

// recon test fakes: a scripted tierRunner and simple grader stand-ins so the
// loop runs with no LLM, no gate, and no network.

func graderContinue(context.Context, engagement.Surface, string, string) reconVerdict {
	return reconVerdict{Continue: true, Parsed: true}
}
func graderStop(context.Context, engagement.Surface, string, string) reconVerdict {
	return reconVerdict{Continue: false, Parsed: true}
}
func graderParseFail(context.Context, engagement.Surface, string, string) reconVerdict {
	return reconVerdict{Parsed: false}
}

// coverEachTier is a tierRunner that covers exactly the dimensions of whatever
// tier it is handed and finds no new assets. A full ladder run saturates.
func coverEachTier(_ context.Context, _ engagement.Surface, _ string, tier reconTier, _ reconSelection) (tierOutcome, error) {
	return tierOutcome{DimensionsCovered: tier.Dimensions, Commands: 1}, nil
}

// noLimit is a backstop with every axis disabled, so saturation or the grader
// (never the backstop) ends a run.
var noLimit = reconBackstop{}

func newReconDeps(st *engagement.Store, grader reconGrader, run tierRunner, b reconBackstop) reconDeps {
	return reconDeps{
		Store:    st,
		Surface:  engagement.SurfaceNetwork,
		Grader:   grader,
		RunTier:  run,
		Backstop: b,
		Now:      time.Now,
	}
}

func TestReconLoopRunsLadderToSaturation(t *testing.T) {
	st := openStore(t)
	d := newReconDeps(st, graderContinue, coverEachTier, noLimit)
	res, err := ReconLoop(context.Background(), d, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Halted {
		t.Fatalf("result halted unexpectedly: %+v", res)
	}
	if res.StopReason != "checklist-complete" {
		t.Fatalf("StopReason = %q, want checklist-complete", res.StopReason)
	}
	if res.Tiers != 4 {
		t.Fatalf("Tiers = %d, want 4 (full network ladder)", res.Tiers)
	}
	cov, ok, err := st.ReconCoverageFor(engagement.SurfaceNetwork, "10.0.0.1")
	if err != nil || !ok {
		t.Fatalf("coverage for the asset missing (ok=%v err=%v)", ok, err)
	}
	for _, dim := range ladderFor(engagement.SurfaceNetwork).allDimensions() {
		if cov.Dimensions[dim] != engagement.ReconCovered {
			t.Fatalf("dimension %q = %q, want covered", dim, cov.Dimensions[dim])
		}
	}
}

func TestReconLoopStopsOnGraderParseFail(t *testing.T) {
	st := openStore(t)
	d := newReconDeps(st, graderParseFail, coverEachTier, noLimit)
	res, err := ReconLoop(context.Background(), d, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.StopReason != "grader-parse-fail" {
		t.Fatalf("StopReason = %q, want grader-parse-fail (fail closed)", res.StopReason)
	}
	// Fail-closed is the OPPOSITE of the RAG grader: a malformed reply must halt
	// recon, not extend it, so the checklist must NOT be complete.
	cov, ok, err := st.ReconCoverageFor(engagement.SurfaceNetwork, "10.0.0.1")
	if err != nil || !ok {
		t.Fatalf("coverage missing (ok=%v err=%v)", ok, err)
	}
	if checklistComplete(ladderFor(engagement.SurfaceNetwork), cov) {
		t.Fatalf("checklist complete after a grader parse-failure; the loop did not stop fail-closed")
	}
}

func TestReconLoopStopsOnGraderStop(t *testing.T) {
	st := openStore(t)
	d := newReconDeps(st, graderStop, coverEachTier, noLimit)
	res, err := ReconLoop(context.Background(), d, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.StopReason != "grader-stop" {
		t.Fatalf("StopReason = %q, want grader-stop", res.StopReason)
	}
}

func TestReconLoopNoveltyGateStops(t *testing.T) {
	st := openStore(t)
	// Tier 0 covers hosts (novel); tier 1 covers nothing and finds nothing.
	run := func(_ context.Context, _ engagement.Surface, _ string, tier reconTier, _ reconSelection) (tierOutcome, error) {
		if tier.Index == 0 {
			return tierOutcome{DimensionsCovered: []string{"hosts"}, Commands: 1}, nil
		}
		return tierOutcome{Commands: 1}, nil
	}
	d := newReconDeps(st, graderContinue, run, noLimit)
	res, err := ReconLoop(context.Background(), d, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.StopReason != "novelty-zero" {
		t.Fatalf("StopReason = %q, want novelty-zero", res.StopReason)
	}
	cov, _, _ := st.ReconCoverageFor(engagement.SurfaceNetwork, "10.0.0.1")
	if cov.Dimensions["ports"] == engagement.ReconCovered {
		t.Fatalf("ports covered; the novelty gate should have stopped with the checklist still open")
	}
}

func TestReconLoopPerAssetRecursion(t *testing.T) {
	st := openStore(t)
	const assetA, assetB = "10.0.0.10", "10.0.0.11"
	// A pre-existing recon task for A, so B's basis_ids reference a known id.
	if _, err := st.Apply(engagement.Delta{
		Kind: "seed",
		Upserts: []engagement.Task{{
			ID: "recon-a", Kind: "recon", Target: assetA,
			Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	// A's tier 0 discovers B and covers hosts; every other pass covers nothing.
	run := func(_ context.Context, _ engagement.Surface, asset string, tier reconTier, _ reconSelection) (tierOutcome, error) {
		if asset == assetA && tier.Index == 0 {
			return tierOutcome{NewAssets: []string{assetB}, DimensionsCovered: []string{"hosts"}, Commands: 1}, nil
		}
		return tierOutcome{Commands: 1}, nil
	}
	d := newReconDeps(st, graderContinue, run, noLimit)
	d.TaskIDFor = func(a string) string {
		if a == assetA {
			return "recon-a"
		}
		return ""
	}
	if _, err := ReconLoop(context.Background(), d, []string{assetA}, "recon-a"); err != nil {
		t.Fatal(err)
	}

	// Exactly one new recon task for B, stamped recon/network, basis = A's task.
	bTask, err := st.GetTask(reconTaskID(assetB))
	if err != nil {
		t.Fatalf("new recon task for B missing: %v", err)
	}
	if bTask.Kind != "recon" || bTask.Phase != engagement.PhaseRecon || bTask.Surface != engagement.SurfaceNetwork {
		t.Fatalf("B task = %+v, want kind=recon phase=recon surface=network", bTask)
	}
	if len(bTask.BasisIDs) != 1 || bTask.BasisIDs[0] != "recon-a" {
		t.Fatalf("B task BasisIDs = %v, want [recon-a]", bTask.BasisIDs)
	}
	// B has its own coverage row (all pending; its tier 0 covered nothing).
	if _, ok, _ := st.ReconCoverageFor(engagement.SurfaceNetwork, assetB); !ok {
		t.Fatalf("coverage row for B missing")
	}
	// A was not reset: hosts stays covered. No global restart.
	covA, _, _ := st.ReconCoverageFor(engagement.SurfaceNetwork, assetA)
	if covA.Dimensions["hosts"] != engagement.ReconCovered {
		t.Fatalf("A hosts = %q, want covered (A must not be reset)", covA.Dimensions["hosts"])
	}
	if _, err := st.GetTask("recon-a"); err != nil {
		t.Fatalf("A's original task vanished: %v", err)
	}
}

func TestReconLoopBackstopTiers(t *testing.T) {
	st := openStore(t)
	// Always novel, never completes: only the backstop can stop this.
	run := func(_ context.Context, _ engagement.Surface, _ string, tier reconTier, _ reconSelection) (tierOutcome, error) {
		return tierOutcome{DimensionsCovered: []string{tier.Dimensions[0]}, Commands: 1}, nil
	}
	d := newReconDeps(st, graderContinue, run, reconBackstop{MaxTiersPerSurface: 1})
	res, err := ReconLoop(context.Background(), d, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Halted || res.HaltReason != haltBackstopTiers {
		t.Fatalf("result = %+v, want Halted with HaltReason=%q", res, haltBackstopTiers)
	}
}

func TestReconLoopBackstopCommandBudget(t *testing.T) {
	st := openStore(t)
	run := func(_ context.Context, _ engagement.Surface, _ string, tier reconTier, _ reconSelection) (tierOutcome, error) {
		return tierOutcome{DimensionsCovered: []string{tier.Dimensions[0]}, Commands: 5}, nil
	}
	d := newReconDeps(st, graderContinue, run, reconBackstop{CommandBudget: 5})
	res, err := ReconLoop(context.Background(), d, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Halted || res.HaltReason != haltBackstopBudget {
		t.Fatalf("result = %+v, want Halted with HaltReason=%q", res, haltBackstopBudget)
	}
}

func TestReconLoopBackstopWallClock(t *testing.T) {
	st := openStore(t)
	base := time.Now()
	ticks := []time.Time{base, base, base.Add(2 * time.Second)}
	i := 0
	clock := func() time.Time {
		tm := ticks[i]
		if i < len(ticks)-1 {
			i++
		}
		return tm
	}
	run := func(_ context.Context, _ engagement.Surface, _ string, tier reconTier, _ reconSelection) (tierOutcome, error) {
		return tierOutcome{DimensionsCovered: []string{tier.Dimensions[0]}, Commands: 1}, nil
	}
	d := newReconDeps(st, graderContinue, run, reconBackstop{WallClock: time.Second})
	d.Now = clock
	res, err := ReconLoop(context.Background(), d, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Halted || res.HaltReason != haltBackstopClock {
		t.Fatalf("result = %+v, want Halted with HaltReason=%q", res, haltBackstopClock)
	}
}

func TestReconLoopBackstopMaxAssets(t *testing.T) {
	st := openStore(t)
	const assetA, assetB = "10.0.0.10", "10.0.0.11"
	run := func(_ context.Context, _ engagement.Surface, asset string, tier reconTier, _ reconSelection) (tierOutcome, error) {
		if asset == assetA && tier.Index == 0 {
			return tierOutcome{NewAssets: []string{assetB}, DimensionsCovered: []string{"hosts"}, Commands: 1}, nil
		}
		return tierOutcome{DimensionsCovered: []string{tier.Dimensions[0]}, Commands: 1}, nil
	}
	d := newReconDeps(st, graderContinue, run, reconBackstop{MaxAssets: 2})
	res, err := ReconLoop(context.Background(), d, []string{assetA}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Halted || res.HaltReason != haltBackstopAssets {
		t.Fatalf("result = %+v, want Halted with HaltReason=%q", res, haltBackstopAssets)
	}
}

func TestReconLoopResumesFromPersistedCoverage(t *testing.T) {
	st := openStore(t)
	const asset = "10.0.0.1"
	// Pre-seed A with hosts already covered (a prior run).
	if _, err := st.Apply(engagement.Delta{
		Kind: "seed",
		ReconUpserts: []engagement.ReconCoverage{{
			Surface: engagement.SurfaceNetwork, Asset: asset,
			Dimensions: map[string]engagement.ReconDimStatus{"hosts": engagement.ReconCovered},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	var ranTiers []int
	run := func(_ context.Context, _ engagement.Surface, _ string, tier reconTier, _ reconSelection) (tierOutcome, error) {
		ranTiers = append(ranTiers, tier.Index)
		return tierOutcome{DimensionsCovered: tier.Dimensions, Commands: 1}, nil
	}
	d := newReconDeps(st, graderContinue, run, noLimit)
	if _, err := ReconLoop(context.Background(), d, []string{asset}, ""); err != nil {
		t.Fatal(err)
	}
	if len(ranTiers) == 0 || ranTiers[0] != 1 {
		t.Fatalf("ranTiers = %v, want to resume at tier 1 (hosts already covered), never tier 0", ranTiers)
	}
	for _, idx := range ranTiers {
		if idx == 0 {
			t.Fatalf("ranTiers = %v, tier 0 should not be re-run after resume", ranTiers)
		}
	}
}

func TestReconLoopSelectorConsultedWithinTier(t *testing.T) {
	st := openStore(t)
	var selTiers []int
	sel := func(_ context.Context, _ engagement.Surface, _ string, tier reconTier, _ engagement.ReconCoverage) reconSelection {
		selTiers = append(selTiers, tier.Index)
		return reconSelection{Action: "probe-" + tier.Name, Basis: "kb_search:x", Parsed: true}
	}
	var gotActions []string
	run := func(_ context.Context, _ engagement.Surface, _ string, tier reconTier, s reconSelection) (tierOutcome, error) {
		gotActions = append(gotActions, s.Action)
		return tierOutcome{DimensionsCovered: tier.Dimensions, Commands: 1}, nil
	}
	d := newReconDeps(st, graderContinue, run, noLimit)
	d.Selector = sel
	res, err := ReconLoop(context.Background(), d, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.StopReason != "checklist-complete" {
		t.Fatalf("StopReason = %q, want checklist-complete", res.StopReason)
	}
	// The selector is consulted once per tier, in ladder order, never beyond the
	// tier nextTier chose - selection operates within the allowed tier only.
	want := []int{0, 1, 2, 3}
	if len(selTiers) != len(want) {
		t.Fatalf("selector consulted for tiers %v, want %v", selTiers, want)
	}
	for i, idx := range want {
		if selTiers[i] != idx {
			t.Fatalf("selector tier[%d] = %d, want %d (selTiers=%v)", i, selTiers[i], idx, selTiers)
		}
	}
	// The selected hint reached RunTier.
	if len(gotActions) == 0 || gotActions[0] != "probe-host-discovery" {
		t.Fatalf("RunTier actions = %v, want the selector's hint for tier 0", gotActions)
	}
}

func TestReconLoopSelectorParseFailFallsBackToLadder(t *testing.T) {
	st := openStore(t)
	// The selector always fails to parse. Unlike the saturation grader (which
	// stops on parse failure), the selector must fall back to the deterministic
	// ladder step and the loop must keep going.
	sel := func(_ context.Context, _ engagement.Surface, _ string, _ reconTier, _ engagement.ReconCoverage) reconSelection {
		return reconSelection{Parsed: false}
	}
	var sawParsed []bool
	run := func(_ context.Context, _ engagement.Surface, _ string, tier reconTier, s reconSelection) (tierOutcome, error) {
		sawParsed = append(sawParsed, s.Parsed)
		return tierOutcome{DimensionsCovered: tier.Dimensions, Commands: 1}, nil
	}
	d := newReconDeps(st, graderContinue, run, noLimit)
	d.Selector = sel
	res, err := ReconLoop(context.Background(), d, []string{"10.0.0.1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.StopReason != "checklist-complete" || res.Tiers != 4 {
		t.Fatalf("result = %+v, want the ladder to run to saturation (a selector parse-fail must not stop recon)", res)
	}
	for i, p := range sawParsed {
		if p {
			t.Fatalf("RunTier call %d received a parsed selection; a selector parse-fail must hand the deterministic ladder step (empty selection)", i)
		}
	}
}

func TestReconLoopNilSelectorHandsEmptySelection(t *testing.T) {
	st := openStore(t)
	var sawParsed []bool
	run := func(_ context.Context, _ engagement.Surface, _ string, tier reconTier, s reconSelection) (tierOutcome, error) {
		sawParsed = append(sawParsed, s.Parsed)
		return tierOutcome{DimensionsCovered: tier.Dimensions, Commands: 1}, nil
	}
	d := newReconDeps(st, graderContinue, run, noLimit) // Selector nil = pure ladder
	if _, err := ReconLoop(context.Background(), d, []string{"10.0.0.1"}, ""); err != nil {
		t.Fatal(err)
	}
	for _, p := range sawParsed {
		if p {
			t.Fatal("nil selector should hand an empty (unparsed) selection to RunTier")
		}
	}
}
