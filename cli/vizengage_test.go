package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
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

func TestConvertEngagementStatuses(t *testing.T) {
	in := eng.Engagement{Revision: 3, Name: "n", ActiveID: "b", Stage: eng.Stage{Label: "l", Step: 1, Total: 4, Tool: "curl"}}
	statuses := []eng.Status{eng.StatusTodo, eng.StatusActive, eng.StatusDone, eng.StatusNA, eng.StatusBlocked}
	want := []TaskStatus{TaskTodo, TaskActive, TaskDone, TaskNA, TaskBlocked}
	for i, s := range statuses {
		in.Tasks = append(in.Tasks, eng.Task{
			ID: string(rune('a' + i)), Kind: "k", Target: "tg", Objective: "o", Status: s,
			DependsOn: []string{"x"}, DoneWhen: "ignored",
		})
	}
	got := convertEngagement(in)
	if got.Revision != 3 || got.Name != "n" || got.ActiveID != "b" {
		t.Fatalf("scalar fields not copied: %+v", got)
	}
	if got.Stage != (Stage{Label: "l", Step: 1, Total: 4, Tool: "curl"}) {
		t.Fatalf("stage not copied: %+v", got.Stage)
	}
	if len(got.Tasks) != len(want) {
		t.Fatalf("task count = %d", len(got.Tasks))
	}
	for i, tk := range got.Tasks {
		if tk.Status != want[i] {
			t.Fatalf("task %d status = %v, want %v", i, tk.Status, want[i])
		}
		if tk.Kind != "k" || tk.Target != "tg" || tk.Objective != "o" || !reflect.DeepEqual(tk.DependsOn, []string{"x"}) {
			t.Fatalf("task %d fields not copied: %+v", i, tk)
		}
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
	got := stripANSI(r.blockFor(context.Background(), convertEngagement(sampleStoreSnapshot())))
	if !strings.Contains(got, "engagement acme rev 7") || !strings.Contains(got, "recon: enumerate host") || !strings.Contains(got, "1 done") {
		t.Fatalf("framed block wrong: %q", got)
	}
}

func TestBlockForFallbackOnError(t *testing.T) {
	r := newVizRenderer(&fakeRunner{err: errors.New("boom")})
	got := stripANSI(r.blockFor(context.Background(), convertEngagement(sampleStoreSnapshot())))
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
