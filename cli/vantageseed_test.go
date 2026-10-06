package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

func TestVantageSeedForLocalScope(t *testing.T) {
	scope, err := secgate.ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := seedVantageFor(scope, nil); got != engagement.VantageInternalFoothold {
		t.Errorf("seedVantageFor(local scope) = %q, want %q", got, engagement.VantageInternalFoothold)
	}
}

func TestVantageSeedForNilScope(t *testing.T) {
	if got := seedVantageFor(nil, nil); got != engagement.VantageExternalUnauth {
		t.Errorf("seedVantageFor(nil, nil) = %q, want %q", got, engagement.VantageExternalUnauth)
	}
}

func TestVantageSeedForNonLocalScope(t *testing.T) {
	scope, err := secgate.ParseScope(strings.NewReader("10.0.0.0/8\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := seedVantageFor(scope, nil); got != engagement.VantageExternalUnauth {
		t.Errorf("seedVantageFor(non-local scope) = %q, want %q", got, engagement.VantageExternalUnauth)
	}
}

func TestVantageSeedInitialFreshStoreNilScope(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()

	if err := seedInitialVantage(ctx, st, nil, nil); err != nil {
		t.Fatal(err)
	}
	v, err := st.Vantage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v != engagement.VantageExternalUnauth {
		t.Errorf("after seed, vantage = %q, want %q", v, engagement.VantageExternalUnauth)
	}
}

func TestVantageSeedInitialIsNoopWhenAlreadySet(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()

	if err := seedInitialVantage(ctx, st, nil, nil); err != nil {
		t.Fatal(err)
	}
	// Calling it again must not error and must not change the stored value.
	if err := seedInitialVantage(ctx, st, nil, nil); err != nil {
		t.Fatal(err)
	}
	v, err := st.Vantage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v != engagement.VantageExternalUnauth {
		t.Errorf("after repeat seed, vantage = %q, want %q", v, engagement.VantageExternalUnauth)
	}
}

func TestVantageSeedInitialLeavesHigherVantageAlone(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()

	higher := engagement.VantageInternalFoothold
	if _, err := st.Apply(engagement.Delta{Kind: "vantage", Detail: "preset", SetVantage: &higher}); err != nil {
		t.Fatal(err)
	}

	if err := seedInitialVantage(ctx, st, nil, nil); err != nil {
		t.Fatal(err)
	}
	v, err := st.Vantage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v != engagement.VantageInternalFoothold {
		t.Errorf("after seed over higher vantage, vantage = %q, want %q (unchanged)", v, engagement.VantageInternalFoothold)
	}
}

func TestVantageAdvanceFromUnsetSeedsNewlyReachableSurfaces(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()

	basis := engagement.Task{
		ID: "exploit-basis", Kind: "exploit-dev", Target: "10.0.0.5",
		Objective: "pivot", Status: engagement.StatusDone, Phase: engagement.PhaseExploit, Surface: engagement.SurfaceNetwork,
	}
	if _, err := st.Apply(engagement.Delta{Kind: "task", Detail: "basis", Upserts: []engagement.Task{basis}}); err != nil {
		t.Fatal(err)
	}

	if err := advanceVantage(ctx, st, engagement.VantageInternalFoothold, "10.0.0.5", basis.ID); err != nil {
		t.Fatal(err)
	}

	v, err := st.Vantage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v != engagement.VantageInternalFoothold {
		t.Fatalf("vantage = %q, want %q", v, engagement.VantageInternalFoothold)
	}

	localID := reconTaskID("10.0.0.5") + "-" + string(engagement.SurfaceLocal)
	lt, err := st.GetTask(localID)
	if err != nil {
		t.Fatalf("local recon task not seeded: %v", err)
	}
	if lt.Phase != engagement.PhaseRecon {
		t.Errorf("seeded local task phase = %q, want %q", lt.Phase, engagement.PhaseRecon)
	}
	if lt.Surface != engagement.SurfaceLocal {
		t.Errorf("seeded local task surface = %q, want %q", lt.Surface, engagement.SurfaceLocal)
	}
	if lt.Status != engagement.StatusTodo {
		t.Errorf("seeded local task status = %q, want %q", lt.Status, engagement.StatusTodo)
	}
	if len(lt.BasisIDs) != 1 || lt.BasisIDs[0] != basis.ID {
		t.Errorf("seeded local task basis ids = %v, want [%s]", lt.BasisIDs, basis.ID)
	}

	adID := reconTaskID("10.0.0.5") + "-" + string(engagement.SurfaceAD)
	if _, err := st.GetTask(adID); err != nil {
		t.Fatalf("ad recon task not seeded: %v", err)
	}
}

func TestVantageAdvanceBackwardIsRejected(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()

	if err := advanceVantage(ctx, st, engagement.VantageInternalFoothold, "10.0.0.5", ""); err != nil {
		t.Fatal(err)
	}
	if err := advanceVantage(ctx, st, engagement.VantageExternalUnauth, "10.0.0.5", ""); err == nil {
		t.Error("advanceVantage backward: want non-nil error, got nil")
	}
}

// TestDeclaredFootholdSeedsInternalVantage pins the authorization half of the
// pivot: a declared foothold is internal access the operator asserts, so the
// surfaces that vantage reaches are open from the first task rather than waiting
// for an exploit to yield access.
func TestDeclaredFootholdSeedsInternalVantage(t *testing.T) {
	scope, err := secgate.BuildScope(secgate.ScopeSpec{In: []string{"10.10.5.21"}})
	if err != nil {
		t.Fatal(err)
	}
	foothold := &secgate.Foothold{Host: "10.10.5.21", Transport: "ssh", User: "svc", Key: "k", Surfaces: []secgate.Surface{secgate.SurfaceLocal}}
	if got := seedVantageFor(scope, foothold); got != engagement.VantageInternalFoothold {
		t.Errorf("seedVantageFor(foothold) = %q, want %q", got, engagement.VantageInternalFoothold)
	}
	if got := seedVantageFor(scope, nil); got != engagement.VantageExternalUnauth {
		t.Errorf("seedVantageFor(no foothold) = %q, want %q", got, engagement.VantageExternalUnauth)
	}
	if !engagement.VantageInternalFoothold.Reaches(engagement.SurfaceLocal) {
		t.Error("internal-foothold does not reach the local surface; the seed would not open it")
	}
}
