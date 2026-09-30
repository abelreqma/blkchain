package secgate

import (
	"testing"
	"time"
)

func TestClampCapsDefaultsAndCeilings(t *testing.T) {
	got := ClampCaps(Caps{}) // all zero -> defaults
	if got.MaxCommands != 50 || got.MaxOutputBytes != 1<<20 || got.Wall != 30*time.Minute {
		t.Errorf("defaults wrong: %+v", got)
	}
	huge := ClampCaps(Caps{MaxCommands: 1 << 30, MaxOutputBytes: 1 << 30, Wall: 100 * time.Hour})
	if huge.MaxCommands != 1000 || huge.MaxOutputBytes != 16<<20 || huge.Wall != 6*time.Hour {
		t.Errorf("ceilings wrong: %+v", huge)
	}
	neg := ClampCaps(Caps{MaxCommands: -5, MaxOutputBytes: -1, Wall: -time.Second})
	if neg.MaxCommands != 50 || neg.MaxOutputBytes != 1<<20 || neg.Wall != 30*time.Minute {
		t.Errorf("negatives should fall back to defaults: %+v", neg)
	}
}

func TestEpisodeCommandCapBoundary(t *testing.T) {
	e := NewEpisode(Caps{MaxCommands: 2, MaxOutputBytes: 1000, Wall: time.Hour}, nil)
	if ok, _ := e.AllowCommand(); !ok {
		t.Fatal("1st command should be allowed")
	}
	if ok, _ := e.AllowCommand(); !ok {
		t.Fatal("2nd command should be allowed")
	}
	if ok, reason := e.AllowCommand(); ok || reason == "" {
		t.Fatalf("3rd command must be denied at the cap, got ok=%v reason=%q", ok, reason)
	}
}

func TestEpisodeWallClock(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	e := NewEpisode(Caps{MaxCommands: 100, MaxOutputBytes: 1000, Wall: time.Minute}, clock)
	if ok, _ := e.AllowCommand(); !ok {
		t.Fatal("within wall clock, should allow")
	}
	now = now.Add(2 * time.Minute) // advance past the deadline
	if ok, reason := e.AllowCommand(); ok || reason == "" {
		t.Fatalf("past wall clock must deny, got ok=%v reason=%q", ok, reason)
	}
}

func TestEpisodeTrip(t *testing.T) {
	e := NewEpisode(Caps{MaxCommands: 100, MaxOutputBytes: 1000, Wall: time.Hour}, nil)
	e.Trip("mid-loop anomaly")
	if !e.Tripped() {
		t.Error("breaker should be tripped")
	}
	if ok, _ := e.AllowCommand(); ok {
		t.Error("a tripped breaker must deny all commands")
	}
}

func TestCapOutput(t *testing.T) {
	e := NewEpisode(Caps{MaxCommands: 1, MaxOutputBytes: 10, Wall: time.Hour}, nil)
	if e.CapOutput(100) != 10 || e.CapOutput(5) != 5 {
		t.Error("CapOutput must clamp to MaxOutputBytes")
	}
	if e.CapOutput(-1) != 0 {
		t.Error("CapOutput must return 0 for a negative n")
	}
}
