package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	eng "blkchain/cli/internal/engagement"
)

func sampleStoreSnapshot() eng.Engagement {
	return eng.Engagement{
		Revision: 7,
		Name:     "acme",
		ActiveID: "t2",
		Stage:    eng.Stage{Label: "probe", Step: 2, Total: 5, Tool: "nmap"},
		Tasks: []eng.Task{
			{ID: "t1", Kind: "recon", Objective: "enumerate host", Status: eng.StatusDone},
			{ID: "t2", Kind: "web", Objective: "SQLi on login", Status: eng.StatusActive, DependsOn: []string{"t1"}},
		},
	}
}

func TestEngageProgressDisabled(t *testing.T) {
	var buf bytes.Buffer
	r := newVizRenderer(&fakeRunner{out: "x"})
	if makeEngageProgress(&buf, r, false) != nil {
		t.Fatal("viz=false must return nil")
	}
	if makeEngageProgress(&buf, nil, true) != nil {
		t.Fatal("nil renderer must return nil")
	}
}

func TestEngageProgressWritesBlock(t *testing.T) {
	var buf bytes.Buffer
	fr := &fakeRunner{out: "recon: enumerate host\nweb: SQLi on login"}
	fn := makeEngageProgress(&buf, newVizRenderer(fr), true)
	if fn == nil {
		t.Fatal("expected callback")
	}
	fn(7, sampleStoreSnapshot())
	fn(8, sampleStoreSnapshot())
	out := stripANSI(buf.String())
	if !strings.Contains(out, "recon: enumerate host") || !strings.Contains(out, "web: SQLi on login") {
		t.Fatalf("block missing task labels: %q", out)
	}
	if fr.calls != 2 {
		t.Fatalf("runner calls = %d, want 2 (no caching)", fr.calls)
	}
}

func TestBlockForFramed(t *testing.T) {
	r := newVizRenderer(&fakeRunner{out: "recon: enumerate host\nweb: SQLi on login"})
	got := stripANSI(r.blockFor(context.Background(), sampleStoreSnapshot()))
	if !strings.Contains(got, "engagement acme rev 7") || !strings.Contains(got, "recon: enumerate host") || !strings.Contains(got, "1 done") {
		t.Fatalf("framed block wrong: %q", got)
	}
}

func TestBlockForFallbackOnError(t *testing.T) {
	r := newVizRenderer(&fakeRunner{err: errors.New("boom")})
	got := stripANSI(r.blockFor(context.Background(), sampleStoreSnapshot()))
	if !strings.Contains(got, "renderer unavailable") || !strings.Contains(got, "recon: enumerate host") {
		t.Fatalf("fallback wrong: %q", got)
	}
}

type panicRunner struct{}

func (panicRunner) Render(ctx context.Context, mermaid string, ascii bool) (string, error) {
	panic("boom")
}

func TestEngageProgressRecoversPanic(t *testing.T) {
	var buf bytes.Buffer
	fn := makeEngageProgress(&buf, newVizRenderer(panicRunner{}), true)
	if fn == nil {
		t.Fatal("expected a callback")
	}
	fn(1, sampleStoreSnapshot())
}
