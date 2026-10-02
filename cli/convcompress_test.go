package main

import (
	"context"
	"strings"
	"testing"

	"github.com/tmc/langchaingo/llms"
)

// convTurns builds n alternating human/ai turns (human first), each padded to
// about `size` characters and tagged with its index so order is checkable.
func convTurns(n, size int) []priorTurn {
	out := make([]priorTurn, n)
	for i := 0; i < n; i++ {
		role := "human"
		if i%2 == 1 {
			role = "ai"
		}
		pad := strings.Repeat("x", size)
		out[i] = priorTurn{Role: role, Content: fmtTurn(i) + pad}
	}
	return out
}

func fmtTurn(i int) string { return "turn#" + string(rune('A'+i%26)) + "-" }

func TestCompressTurnsUnderBudgetUnchanged(t *testing.T) {
	turns := convTurns(3, 100) // ~300 chars
	fake := &fakeModel{queue: []*llms.ContentResponse{textResp("DIGEST")}}
	got := compressTurns(context.Background(), fake, turns, 2000)
	if fake.calls != 0 {
		t.Fatalf("model called %d times under budget, want 0", fake.calls)
	}
	if len(got) != len(turns) {
		t.Fatalf("under budget changed length: got %d want %d", len(got), len(turns))
	}
	for i := range turns {
		if got[i] != turns[i] {
			t.Fatalf("under budget mutated turn %d", i)
		}
	}
}

func TestCompressTurnsOverBudgetSummarizes(t *testing.T) {
	turns := convTurns(50, 100) // ~5000 chars, well over budget
	budget := 2000
	fake := &fakeModel{queue: []*llms.ContentResponse{textResp("DIGEST")}}
	got := compressTurns(context.Background(), fake, turns, budget)

	if fake.calls != 1 {
		t.Fatalf("summarizer called %d times, want 1", fake.calls)
	}
	// Nothing is silently dropped: a digest turn stands in for the older span.
	foundDigest := false
	for _, pt := range got {
		if strings.Contains(pt.Content, "DIGEST") {
			foundDigest = true
		}
	}
	if !foundDigest {
		t.Fatalf("compressed history has no digest turn: %+v", got)
	}
	// The first turn is preserved verbatim (the anchor).
	if got[0] != turns[0] {
		t.Fatalf("first turn not preserved: got %q", got[0].Content)
	}
	// The most recent turns are preserved verbatim.
	for i := 1; i <= 6; i++ {
		if got[len(got)-i] != turns[len(turns)-i] {
			t.Fatalf("recent turn -%d not preserved verbatim", i)
		}
	}
	// It actually shrank and fits the budget.
	if len(got) >= len(turns) {
		t.Fatalf("compression did not shrink history: %d >= %d", len(got), len(turns))
	}
	if conversationChars(got) > budget {
		t.Fatalf("compressed history %d chars exceeds budget %d", conversationChars(got), budget)
	}
	// The summarizer prompt must carry the conversation instruction (untrusted-data framing).
	if len(fake.seen) == 0 {
		t.Fatal("summarizer saw no request")
	}
	var prompt strings.Builder
	for _, m := range fake.seen[0] {
		prompt.WriteString(msgText(m))
	}
	if !strings.Contains(prompt.String(), "UNTRUSTED DATA") {
		t.Fatalf("summarizer prompt lacks the untrusted-data instruction")
	}
}

func TestCompressTurnsModelErrorFallsBack(t *testing.T) {
	turns := convTurns(50, 100)
	budget := 2000
	got := compressTurns(context.Background(), errModel{}, turns, budget)
	// Fallback is the lossy bound, not a digest.
	want := boundTurns(turns, budget)
	if len(got) != len(want) {
		t.Fatalf("fallback length %d, want boundTurns length %d", len(got), len(want))
	}
	for _, pt := range got {
		if strings.Contains(pt.Content, "DIGEST") {
			t.Fatalf("fallback should not contain a digest")
		}
	}
	if conversationChars(got) > budget {
		t.Fatalf("fallback %d chars exceeds budget %d", conversationChars(got), budget)
	}
}

func TestCompressTurnsNilModelFallsBack(t *testing.T) {
	turns := convTurns(50, 100)
	budget := 2000
	got := compressTurns(context.Background(), nil, turns, budget)
	want := boundTurns(turns, budget)
	if len(got) != len(want) {
		t.Fatalf("nil-model fallback length %d, want %d", len(got), len(want))
	}
}

func TestConversationBudgetEnvOverride(t *testing.T) {
	if got := conversationBudget(); got != conversationMaxChars {
		t.Fatalf("default budget = %d, want %d", got, conversationMaxChars)
	}
	t.Setenv("BLKCHAIN_CONVERSATION_MAX_CHARS", "1234")
	if got := conversationBudget(); got != 1234 {
		t.Fatalf("env budget = %d, want 1234", got)
	}
	t.Setenv("BLKCHAIN_CONVERSATION_MAX_CHARS", "nope")
	if got := conversationBudget(); got != conversationMaxChars {
		t.Fatalf("bad env should fall back to %d, got %d", conversationMaxChars, got)
	}
	t.Setenv("BLKCHAIN_CONVERSATION_MAX_CHARS", "-5")
	if got := conversationBudget(); got != conversationMaxChars {
		t.Fatalf("non-positive env should fall back to %d, got %d", conversationMaxChars, got)
	}
}
