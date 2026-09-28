package main

import (
	"strings"
	"testing"
	"time"
)

func TestLiveReadout(t *testing.T) {
	out := liveReadout(120, 2*time.Second, true)
	for _, want := range []string{"120 tok", "tok/s", "2.0s"} {
		if !strings.Contains(out, want) {
			t.Errorf("liveReadout missing %q in %q", want, out)
		}
	}
	// zero tokens (before first token) shows a bare elapsed, no divide-by-zero.
	if got := liveReadout(0, 0, true); strings.Contains(got, "NaN") || strings.Contains(got, "+Inf") {
		t.Errorf("liveReadout zero case produced %q", got)
	}
}
