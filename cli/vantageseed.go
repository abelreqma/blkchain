package main

import (
	"context"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

// vantageseed.go seeds an engagement's initial Vantage from its scope and
// advances Vantage (plus the recon tasks a newly-reached surface needs) when an
// exploit yields new access. It is pure package-main glue over the existing
// engagement store; it executes no commands.

// seedVantageFor derives the starting Vantage from the operator's declarations,
// deterministically and fail-safe: anything other than a confirmed local scope
// or a declared foothold gets the most-locked vantage, external-unauth.
//
// A declared foothold is internal access the operator asserts, the same kind of
// assertion as a local scope, so it starts the engagement at internal-foothold
// and the surfaces that vantage reaches are open from the first task. An
// engagement with no foothold still advances through advanceVantage when an
// exploit yields access; it simply has no carrier, so those tasks run in the
// sandbox worker and record that as their destination.
func seedVantageFor(scope *secgate.Scope, foothold *secgate.Foothold) engagement.Vantage {
	if foothold != nil {
		return engagement.VantageInternalFoothold
	}
	if scope != nil && scope.Local() {
		return engagement.VantageInternalFoothold
	}
	return engagement.VantageExternalUnauth
}

func seedInitialVantage(ctx context.Context, store *engagement.Store, scope *secgate.Scope, foothold *secgate.Foothold) error {
	cur, err := store.Vantage(ctx)
	if err != nil {
		return err
	}
	if cur != "" {
		return nil
	}
	v := seedVantageFor(scope, foothold)
	_, err = store.Apply(engagement.Delta{
		Kind:       "vantage",
		Detail:     "seed " + string(v),
		SetVantage: &v,
	})
	return err
}

// advanceVantage moves the engagement's Vantage to newV and seeds one Phase
// Recon T0 task per surface that newV reaches but the current vantage did not,
// as a single atomic Delta. It iterates the canonical engagement.AllSurfaces()
// set, so the seeding tracks whatever surfaces the model defines (local, network,
// web, ad, cloud and its per-CSP variants, container, ai-security) with no
// per-surface list to maintain here. applyLocked enforces monotonicity: a newV
// that moves the vantage backward makes Apply (and this call) return a non-nil
// error, with nothing written.
//
// basisTaskID, when non-empty, must be the id of a task that already exists in
// the store (applyLocked rejects a Delta whose Upserts reference an unknown
// basis task). Pass "" when there is no such task.
func advanceVantage(ctx context.Context, store *engagement.Store, newV engagement.Vantage, pivotAsset, basisTaskID string) error {
	old, err := store.Vantage(ctx)
	if err != nil {
		return err
	}

	var basisIDs []string
	if basisTaskID != "" {
		basisIDs = []string{basisTaskID}
	}

	var upserts []engagement.Task
	for _, s := range engagement.AllSurfaces() {
		if newV.Reaches(s) && !old.Reaches(s) {
			upserts = append(upserts, engagement.Task{
				ID:        reconTaskID(pivotAsset) + "-" + string(s),
				Kind:      "recon",
				Target:    pivotAsset,
				Objective: "recon " + pivotAsset + " on newly-reachable " + string(s) + " surface after vantage advance",
				Status:    engagement.StatusTodo,
				Phase:     engagement.PhaseRecon,
				Surface:   s,
				BasisIDs:  basisIDs,
			})
		}
	}

	_, err = store.Apply(engagement.Delta{
		Kind:       "vantage",
		Detail:     "advance " + string(old) + " -> " + string(newV),
		SetVantage: &newV,
		Upserts:    upserts,
	})
	return err
}
