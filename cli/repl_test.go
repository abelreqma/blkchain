package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	tea "github.com/charmbracelet/bubbletea"
)

func TestPlainVizSnapshotWritesBlock(t *testing.T) {
	fr := &fakeRunner{out: "recon: enumerate host\nweb: SQLi on /login"}
	stub := newStubEngagement("acme")
	stub.setSnapshot(sampleEngagement(0))
	var out strings.Builder
	plainVizSnapshot(&out, newVizRenderer(fr), stub)
	if !strings.Contains(out.String(), "SQLi on /login") {
		t.Fatalf("snapshot missing block: %q", out.String())
	}
}

type failingView struct{}

func (failingView) Revision(context.Context) (int64, error) { return 0, errors.New("boom") }
func (failingView) Snapshot(context.Context) (eng.Engagement, error) {
	return eng.Engagement{}, errors.New("boom")
}

func TestPlainVizSnapshotSilentOnError(t *testing.T) {
	var out strings.Builder
	plainVizSnapshot(&out, newVizRenderer(&fakeRunner{out: "x"}), failingView{})
	if out.Len() != 0 {
		t.Fatalf("view error should write nothing; got %q", out.String())
	}
}

func TestRagArg(t *testing.T) {
	cases := []struct {
		arg      string
		toggle   bool
		on       bool
		question string
	}{
		{"", false, false, ""},
		{"on", true, true, ""},
		{"off", true, false, ""},
		{" ON ", true, true, ""},
		{"Off", true, false, ""},
		{"what is ssrf", false, false, "what is ssrf"},
		{"on the wire protocol", false, false, "on the wire protocol"},
	}
	for _, c := range cases {
		toggle, on, q := ragArg(c.arg)
		if toggle != c.toggle || on != c.on || q != c.question {
			t.Errorf("ragArg(%q) = (%v,%v,%q), want (%v,%v,%q)", c.arg, toggle, on, q, c.toggle, c.on, c.question)
		}
	}
}

// ragTurnCall is what the adaptive router stub saw.
type ragTurnCall struct {
	force           bool
	question, model string
}

// runRagQuestionTurn dispatches "/rag foo", runs the turn cmd, and returns the
// model after dispatch plus what the router received.
func runRagQuestionTurn(t *testing.T) (model, ragTurnCall) {
	t.Helper()
	useDeadServices(t)
	old := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = old })
	calls := make(chan ragTurnCall, 1)
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, q string, _ enabledRoutes, force bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		calls <- ragTurnCall{force: force, question: q, model: opts.Model}
		return "hi", nil, false, nil, 1, "ground", nil
	}

	m := frameModel(t)
	m.ragModel = "ragmodel"
	nm, cmd := m.dispatchInput("/rag foo")
	got := nm.(model)
	if !got.working {
		t.Fatal("/rag <question> did not start a turn")
	}
	if cmd == nil {
		t.Fatal("dispatchInput returned no command")
	}
	// The turn cmd is a tea.Batch; run each member so streamCmd reaches the
	// router. Ticks and pollers are harmless here and end on their own.
	batch, ok := cmd().(tea.BatchMsg)
	if !ok {
		t.Fatal("turn cmd did not produce a tea.BatchMsg")
	}
	for _, c := range batch {
		if c != nil {
			go c()
		}
	}
	select {
	case c := <-calls:
		return got, c
	case <-time.After(5 * time.Second):
		t.Fatal("the adaptive router was never reached")
	}
	return got, ragTurnCall{}
}

// /rag <question> runs a forced turn for exactly that question.
func TestTUIRagQuestionStartsForcedTurn(t *testing.T) {
	got, c := runRagQuestionTurn(t)
	if got.forceRag {
		t.Error("forceRag leaked after the forced turn")
	}
	if !c.force {
		t.Error("router was reached with force=false; /rag <question> must force grounding")
	}
	if c.question != "foo" {
		t.Errorf("router question = %q; want foo", c.question)
	}
	if c.model != "ragmodel" {
		t.Errorf("router model = %q; want ragmodel", c.model)
	}
}

func TestInteractiveSearchSynthesizesAnAnswer(t *testing.T) {
	useDeadServices(t)
	original := adaptiveAnswerFn
	defer func() { adaptiveAnswerFn = original }()
	var seen string
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, query string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		seen = query
		opts.Stream([]byte("Synthesis from retrieved evidence."))
		return "Synthesis from retrieved evidence.", nil, false, nil, 8, "rag", nil
	}
	for _, line := range []string{"/search current LLM testing techniques", "search for current LLM testing techniques", "s current LLM testing techniques"} {
		m := frameModel(t)
		updated, cmd := m.dispatchInput(line)
		if !updated.(model).working {
			t.Fatalf("%q did not start synthesis", line)
		}
		found := false
		for _, msg := range drain(cmd) {
			if done, ok := msg.(streamDoneMsg); ok && done.full == "Synthesis from retrieved evidence." {
				found = true
			}
			if _, raw := msg.(searchMsg); raw {
				t.Fatalf("%q returned raw matches", line)
			}
		}
		if !found || seen == "" {
			t.Fatalf("%q did not reach synthesis", line)
		}
	}
}

func TestEmptySearchDoesNotForceTheNextTurn(t *testing.T) {
	m := frameModel(t)
	updated, _ := m.dispatchInput("/search")
	if updated.(model).forceRag {
		t.Fatal("empty search leaked forced retrieval into the next turn")
	}
}
