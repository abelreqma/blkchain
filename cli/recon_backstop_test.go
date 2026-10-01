package main

import (
	"testing"
	"time"
)

func TestBackstopTiers(t *testing.T) {
	b := reconBackstop{MaxTiersPerSurface: 1}
	if got := b.check(1, 0, 0, 0); got != haltBackstopTiers {
		t.Fatalf("check(1 tier) = %q, want %q", got, haltBackstopTiers)
	}
	if got := b.check(0, 0, 0, 0); got != haltNone {
		t.Fatalf("check(0 tiers) = %q, want haltNone", got)
	}
}

func TestBackstopCommandBudget(t *testing.T) {
	b := reconBackstop{CommandBudget: 10}
	if got := b.check(0, 10, 0, 0); got != haltBackstopBudget {
		t.Fatalf("check(10 commands) = %q, want %q", got, haltBackstopBudget)
	}
	if got := b.check(0, 9, 0, 0); got != haltNone {
		t.Fatalf("check(9 commands) = %q, want haltNone", got)
	}
}

func TestBackstopWallClock(t *testing.T) {
	b := reconBackstop{WallClock: time.Second}
	if got := b.check(0, 0, 0, time.Second); got != haltBackstopClock {
		t.Fatalf("check(1s elapsed) = %q, want %q", got, haltBackstopClock)
	}
	if got := b.check(0, 0, 0, 999*time.Millisecond); got != haltNone {
		t.Fatalf("check(999ms elapsed) = %q, want haltNone", got)
	}
}

func TestBackstopMaxAssets(t *testing.T) {
	b := reconBackstop{MaxAssets: 1}
	if got := b.check(0, 0, 1, 0); got != haltBackstopAssets {
		t.Fatalf("check(1 asset) = %q, want %q", got, haltBackstopAssets)
	}
	if got := b.check(0, 0, 0, 0); got != haltNone {
		t.Fatalf("check(0 assets) = %q, want haltNone", got)
	}
}

func TestBackstopZeroLimitMeansNoLimit(t *testing.T) {
	b := reconBackstop{}
	if got := b.check(1_000_000, 1_000_000, 1_000_000, time.Hour); got != haltNone {
		t.Fatalf("zero-limit backstop halted (%q); zero must mean no limit", got)
	}
}

func TestBackstopFirstReasonOrderAssets(t *testing.T) {
	b := reconBackstop{MaxTiersPerSurface: 1, CommandBudget: 1, WallClock: time.Second, MaxAssets: 1}
	if got := b.check(1, 1, 1, time.Second); got != haltBackstopAssets {
		t.Fatalf("all limits reached: check = %q, want deterministic first reason %q", got, haltBackstopAssets)
	}
}

func TestDefaultReconBackstopIsPositive(t *testing.T) {
	b := defaultReconBackstop()
	if b.MaxTiersPerSurface <= 0 || b.CommandBudget <= 0 || b.WallClock <= 0 || b.MaxAssets <= 0 {
		t.Fatalf("defaultReconBackstop has a non-positive limit: %+v", b)
	}
}
