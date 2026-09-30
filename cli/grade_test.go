package main

import (
	"context"
	"testing"

	"blkchain/cli/internal/ragconfig"

	"github.com/tmc/langchaingo/llms"
)

// emptyChoices is a model response with no choices and no error, the oMLX quirk
// gradeContext must tolerate (and, after two of them, treat as a failure).
func emptyChoices() *llms.ContentResponse { return &llms.ContentResponse{} }

func TestGradeContextErrsAfterTwoEmptyResponses(t *testing.T) {
	m := &fakeModel{queue: []*llms.ContentResponse{emptyChoices(), emptyChoices()}}
	_, err := gradeContext(context.Background(), m, ragconfig.Load(), "q", nil)
	if err == nil {
		t.Fatal("want an error after two empty responses, got nil")
	}
	if m.calls != 2 {
		t.Errorf("made %d grade attempts, want 2 (one retry)", m.calls)
	}
}

func TestGradeContextStopsOnCanceledContext(t *testing.T) {
	m := &fakeModel{queue: []*llms.ContentResponse{emptyChoices(), emptyChoices()}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := gradeContext(ctx, m, ragconfig.Load(), "q", nil)
	if err == nil {
		t.Fatal("want a context error, got nil")
	}
	if m.calls != 0 {
		t.Errorf("made %d grade attempts on a canceled context, want 0", m.calls)
	}
}

func TestParseGrade(t *testing.T) {
	g := parseGrade("chatter {\"sufficient\": true, \"rewrite\": \"x\", \"use_web\": false} tail")
	if !g.Sufficient || g.Rewrite != "x" || g.UseWeb {
		t.Fatalf("got %+v", g)
	}
	bad := parseGrade("no json here")
	if bad.Sufficient || bad.UseWeb || bad.Rewrite != "" {
		t.Fatalf("default should be all-false/empty, got %+v", bad)
	}
}
