package main

import (
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/modeleval"
)

func TestRenderReportChatReady(t *testing.T) {
	r := modeleval.ModelReport{
		Kind:         modeleval.KindChat,
		Ready:        true,
		ReadyElapsed: 1200 * time.Millisecond,
		Perf: &modeleval.PerfResult{
			ModelID: "supergemma4-26b", TTFT: 180 * time.Millisecond,
			GenTokens: 60, TokensPerSec: 492.3, UsageReported: true,
		},
	}
	out := renderReport(r)
	for _, want := range []string{"chat", "supergemma4-26b", "tok/s", "ttft"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderReportUnreachable(t *testing.T) {
	r := modeleval.ModelReport{Kind: modeleval.KindEmbed, Ready: false, Err: modeleval.ErrUnreachable()}
	out := renderReport(r)
	if !strings.Contains(out, "blk up") {
		t.Errorf("unreachable render should mention `blk up`, got:\n%s", out)
	}
}

func TestRenderReportRerankNonFinite(t *testing.T) {
	r := modeleval.ModelReport{
		Kind: modeleval.KindRerank, Ready: true,
		Perf: &modeleval.PerfResult{PoolSize: 5, Ms: 41, NonFinite: 2},
	}
	out := renderReport(r)
	if !strings.Contains(out, "non-finite") {
		t.Errorf("expected non-finite flag, got:\n%s", out)
	}
}
