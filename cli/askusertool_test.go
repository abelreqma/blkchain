package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/askuser"
)

func TestAskUserToolAutoSuppressed(t *testing.T) {
	tool := newAskUserTool(askuser.AutoAsker{})
	out, err := tool.Call(context.Background(), `{"question":"which target?","allow_custom":true}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(out), "suppress") && !strings.Contains(strings.ToLower(out), "cancel") {
		t.Errorf("auto ask_user result = %q, want a canceled/suppressed message", out)
	}
}

func TestAskUserToolReturnsChoice(t *testing.T) {
	a, reqs := askuser.NewChannelAsker()
	go func() {
		<-reqs
		a.Reply(askuser.ClarifyResult{Value: "10.0.0.9"})
	}()
	tool := newAskUserTool(a)
	out, err := tool.Call(context.Background(), `{"question":"which target?"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "10.0.0.9") {
		t.Errorf("ask_user result = %q, want the chosen value", out)
	}
}

func TestAskUserToolEmptyAnswer(t *testing.T) {
	a, reqs := askuser.NewChannelAsker()
	go func() {
		<-reqs
		a.Reply(askuser.ClarifyResult{})
	}()
	out, err := newAskUserTool(a).Call(context.Background(), `{"question":"which target?"}`)
	if err != nil {
		t.Fatal(err)
	}
	if out != "user gave no answer" {
		t.Errorf("ask_user result = %q, want %q", out, "user gave no answer")
	}
}

func TestAskUserToolNilAskerDefaultsToAuto(t *testing.T) {
	out, err := newAskUserTool(nil).Call(context.Background(), `{"question":"q"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(out), "suppress") && !strings.Contains(strings.ToLower(out), "cancel") {
		t.Errorf("nil-asker result = %q, want a canceled/suppressed message", out)
	}
}
