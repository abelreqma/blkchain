package main

import "time"

// recon_backstop.go is the deterministic backstop for the recon tier loop. It
// dominates the LLM sufficiency grader: when any bound is reached the loop halts
// for human review (backstop-halted), regardless of what the grader advises.

// reconHalt names why the backstop halted a recon run, or haltNone when no bound
// was reached.
type reconHalt string

const (
	haltNone           reconHalt = ""
	haltBackstopAssets reconHalt = "backstop-assets"
	haltBackstopTiers  reconHalt = "backstop-tiers"
	haltBackstopBudget reconHalt = "backstop-command-budget"
	haltBackstopClock  reconHalt = "backstop-wall-clock"
)

// reconBackstop bounds a per-surface recon run. A zero or negative value on any
// axis means that axis is unbounded, so a test (or an operator) can isolate one
// limit without tripping the others.
type reconBackstop struct {
	MaxTiersPerSurface int           // cap on tier passes across the surface
	CommandBudget      int           // cap on commands executed in the recon phase
	WallClock          time.Duration // cap on elapsed time since the run started
	MaxAssets          int           // cap on distinct assets discovered/processed
}

// Env overrides for the default backstop limits.
const (
	reconMaxTiersEnv      = "BLKCHAIN_RECON_MAX_TIERS"
	reconCommandBudgetEnv = "BLKCHAIN_RECON_COMMAND_BUDGET"
	reconWallClockSecEnv  = "BLKCHAIN_RECON_WALL_CLOCK_SEC"
	reconMaxAssetsEnv     = "BLKCHAIN_RECON_MAX_ASSETS"
)

// Built-in backstop defaults. Chosen to let saturation or the grader stop a
// normal run first, while still bounding a runaway loop.
const (
	reconDefaultMaxTiers      = 24
	reconDefaultCommandBudget = 200
	reconDefaultWallClockSec  = 900 // 15 minutes
	reconDefaultMaxAssets     = 64
)

// defaultReconBackstop returns the built-in limits, each env-overridable and
// clamped to a sane range. An unset or unparsable env value keeps the default.
func defaultReconBackstop() reconBackstop {
	return reconBackstop{
		MaxTiersPerSurface: clampEnvInt(reconMaxTiersEnv, reconDefaultMaxTiers, 1, 10_000),
		CommandBudget:      clampEnvInt(reconCommandBudgetEnv, reconDefaultCommandBudget, 1, 1_000_000),
		WallClock:          time.Duration(clampEnvInt(reconWallClockSecEnv, reconDefaultWallClockSec, 1, 86_400)) * time.Second,
		MaxAssets:          clampEnvInt(reconMaxAssetsEnv, reconDefaultMaxAssets, 1, 1_000_000),
	}
}

// check reports the first bound that has been reached, or haltNone. The order
// (assets, tiers, budget, clock) is fixed so the halt reason is deterministic
// when several bounds are reached at once. A non-positive limit disables its
// axis.
func (b reconBackstop) check(tiers, commands, assets int, elapsed time.Duration) reconHalt {
	if b.MaxAssets > 0 && assets >= b.MaxAssets {
		return haltBackstopAssets
	}
	if b.MaxTiersPerSurface > 0 && tiers >= b.MaxTiersPerSurface {
		return haltBackstopTiers
	}
	if b.CommandBudget > 0 && commands >= b.CommandBudget {
		return haltBackstopBudget
	}
	if b.WallClock > 0 && elapsed >= b.WallClock {
		return haltBackstopClock
	}
	return haltNone
}
