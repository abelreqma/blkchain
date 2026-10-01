package main

import (
	"context"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"blkchain/cli/internal/askuser"
)

// The conversion carries every field both ways between the askuser protocol and
// the TUI clarify overlay types.
func TestEngageAskerConversion(t *testing.T) {
	c := askuser.Clarification{
		Question:    "pick a lead",
		Detail:      "two found",
		AllowCustom: true,
		Options:     []askuser.ClarifyOption{{Label: "SQLi", Note: "login", Value: "sqli"}, {Label: "IDOR", Value: "idor"}},
	}
	got := clarificationFromAskuser(c)
	if got.Question != c.Question || got.Detail != c.Detail || !got.AllowCustom || len(got.Options) != 2 {
		t.Fatalf("clarification conversion dropped a field: %+v", got)
	}
	if got.Options[0].Label != "SQLi" || got.Options[0].Note != "login" || got.Options[0].Value != "sqli" {
		t.Fatalf("option conversion dropped a field: %+v", got.Options[0])
	}
	r := clarifyResultToAskuser(ClarifyResult{Value: "sqli", Custom: "x", Canceled: true})
	if r.Value != "sqli" || r.Custom != "x" || !r.Canceled {
		t.Fatalf("result conversion dropped a field: %+v", r)
	}
}

// The asker routes an orchestrator clarification to the clarify overlay via prog
// and returns the operator's converted answer.
func TestEngageAskerBridgesToOverlay(t *testing.T) {
	fp := &fakeProg{got: make(chan tea.Msg, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	asker := startEngageAsker(ctx, fp)

	ans := make(chan askuser.ClarifyResult, 1)
	go func() {
		ans <- asker.Ask(ctx, askuser.Clarification{Question: "q", Options: []askuser.ClarifyOption{{Label: "A", Value: "a"}}})
	}()
	msg := (<-fp.got).(clarifyMsg)
	if msg.c.Question != "q" || len(msg.c.Options) != 1 || msg.c.Options[0].Value != "a" {
		t.Fatalf("the pump posted a wrong clarification: %+v", msg.c)
	}
	msg.reply <- ClarifyResult{Value: "a"}
	if got := <-ans; got.Value != "a" || got.Canceled {
		t.Fatalf("asker returned %+v; want value a", got)
	}
}

// A context cancel while a clarification is in flight unblocks the asker with a
// canceled result.
func TestEngageAskerCancelUnblocks(t *testing.T) {
	fp := &fakeProg{got: make(chan tea.Msg, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	asker := startEngageAsker(ctx, fp)

	ans := make(chan askuser.ClarifyResult, 1)
	go func() {
		ans <- asker.Ask(ctx, askuser.Clarification{Question: "q"})
	}()
	<-fp.got // the pump posted the clarifyMsg
	cancel()
	if got := <-ans; !got.Canceled {
		t.Fatalf("a canceled context should return a canceled result, got %+v", got)
	}
}
