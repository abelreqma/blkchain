package modeleval

import (
	"math"
	"testing"
	"time"
)

func TestTokensPerSec(t *testing.T) {
	if got := TokensPerSec(100, 2*time.Second); got != 50 {
		t.Errorf("TokensPerSec(100,2s)=%v want 50", got)
	}
	// zero duration must not divide by zero.
	if got := TokensPerSec(100, 0); got != 0 {
		t.Errorf("TokensPerSec zero-duration=%v want 0", got)
	}
	if got := TokensPerSec(0, time.Second); got != 0 {
		t.Errorf("TokensPerSec zero-tokens=%v want 0", got)
	}
}

func TestScoreSanity(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	inf := math.Inf(1)
	scores := []*float64{f(0.9), nil, f(0.5), f(1.5), f(inf), f(-0.2)}
	// nil (sanitized null) and +Inf are non-finite; 1.5 and -0.2 are out of [0,1].
	nf, oor := ScoreSanity(scores)
	if nf != 2 {
		t.Errorf("nonFinite=%d want 2", nf)
	}
	if oor != 2 {
		t.Errorf("outOfRange=%d want 2", oor)
	}
}

func TestFormatElapsed(t *testing.T) {
	if got := FormatElapsed(1500 * time.Millisecond); got != "1.5s" {
		t.Errorf("FormatElapsed=%q want 1.5s", got)
	}
	if got := FormatElapsed(420 * time.Millisecond); got != "420ms" {
		t.Errorf("FormatElapsed=%q want 420ms", got)
	}
}
