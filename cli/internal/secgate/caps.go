package secgate

import (
	"fmt"
	"time"
)

const (
	defaultMaxCommands = 50
	ceilMaxCommands    = 1000
	defaultMaxOutput   = 1 << 20
	ceilMaxOutput      = 16 << 20
	defaultWall        = 30 * time.Minute
	ceilWall           = 6 * time.Hour
)

// Caps bounds one engagement episode.
type Caps struct {
	MaxCommands    int
	MaxOutputBytes int
	Wall           time.Duration
}

// ClampCaps applies the safe default for any non-positive field and the ceiling
// for any field above it. Every field is bounded on both ends.
func ClampCaps(c Caps) Caps {
	c.MaxCommands = clampInt(c.MaxCommands, defaultMaxCommands, ceilMaxCommands)
	c.MaxOutputBytes = clampInt(c.MaxOutputBytes, defaultMaxOutput, ceilMaxOutput)
	if c.Wall <= 0 {
		c.Wall = defaultWall
	} else if c.Wall > ceilWall {
		c.Wall = ceilWall
	}
	return c
}

// clampInt returns def when v<=0, ceil when v>ceil, else v.
func clampInt(v, def, ceil int) int {
	if v <= 0 {
		return def
	}
	if v > ceil {
		return ceil
	}
	return v
}

// Episode tracks one bounded run: executed-command count, wall-clock deadline,
// and a circuit breaker independent of any pentest logic.
type Episode struct {
	caps     Caps
	now      func() time.Time
	deadline time.Time
	count    int
	tripped  bool
	tripMsg  string
}

// NewEpisode starts an episode. caps is clamped. now is injectable for tests; a
// nil now uses time.Now.
func NewEpisode(caps Caps, now func() time.Time) *Episode {
	if now == nil {
		now = time.Now
	}
	caps = ClampCaps(caps)
	return &Episode{caps: caps, now: now, deadline: now().Add(caps.Wall)}
}

// AllowCommand reports whether another command may run, incrementing the count
// when it allows. The cap counts authorization attempts, not executions: a
// command denied later in the gate still consumed a slot (intended fail-safe). It denies once the breaker is tripped, past the wall-clock
// deadline, or at/over the command cap.
func (e *Episode) AllowCommand() (bool, string) {
	if e.tripped {
		return false, "circuit breaker tripped: " + e.tripMsg
	}
	if !e.now().Before(e.deadline) {
		return false, "wall-clock cap reached"
	}
	if e.count >= e.caps.MaxCommands {
		return false, fmt.Sprintf("command cap reached (%d)", e.caps.MaxCommands)
	}
	e.count++
	return true, ""
}

// Trip trips the circuit breaker with a reason.
func (e *Episode) Trip(reason string) {
	e.tripped = true
	e.tripMsg = reason
}

// Tripped reports whether the breaker is tripped.
func (e *Episode) Tripped() bool { return e.tripped }

// CapOutput clamps n to the output-size cap.
func (e *Episode) CapOutput(n int) int {
	if n < 0 {
		return 0
	}
	if n > e.caps.MaxOutputBytes {
		return e.caps.MaxOutputBytes
	}
	return n
}
