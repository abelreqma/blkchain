package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/secgate"
)

func TestTerminalConfirmerYes(t *testing.T) {
	var out bytes.Buffer
	c := newTerminalConfirmer(strings.NewReader("y\n"), &out)
	if !c.Confirm(context.Background(), secgate.Command{Binary: "nmap", Args: []string{"-p", "22", "10.0.0.5"}}) {
		t.Error("y should confirm")
	}
	if !strings.Contains(out.String(), "nmap") {
		t.Error("prompt should show the command")
	}
}

func TestTerminalConfirmerNoAndEOF(t *testing.T) {
	if newTerminalConfirmer(strings.NewReader("n\n"), &bytes.Buffer{}).Confirm(context.Background(), secgate.Command{Binary: "x"}) {
		t.Error("n should deny")
	}
	if newTerminalConfirmer(strings.NewReader(""), &bytes.Buffer{}).Confirm(context.Background(), secgate.Command{Binary: "x"}) {
		t.Error("EOF should deny (fail closed)")
	}
}

func TestTerminalAskerChoiceAndCancel(t *testing.T) {
	var out bytes.Buffer
	a := newTerminalAsker(strings.NewReader("10.0.0.5\n"), &out)
	r := a.Ask(context.Background(), askuser.Clarification{Question: "which host?", AllowCustom: true})
	if r.Canceled || (r.Value == "" && r.Custom == "") {
		t.Errorf("expected an answer, got %+v", r)
	}
	if newTerminalAsker(strings.NewReader("\n"), &bytes.Buffer{}).Ask(context.Background(), askuser.Clarification{Question: "q"}).Canceled != true {
		t.Error("empty line should cancel")
	}
}

func TestTerminalAskerOptionMatch(t *testing.T) {
	c := askuser.Clarification{Question: "q", Options: []askuser.ClarifyOption{{Label: "Local", Value: "local"}}}
	r := newTerminalAsker(strings.NewReader("LOCAL\n"), &bytes.Buffer{}).Ask(context.Background(), c)
	if r.Value != "local" || r.Canceled {
		t.Errorf("label match should return value, got %+v", r)
	}
	r = newTerminalAsker(strings.NewReader("other\n"), &bytes.Buffer{}).Ask(context.Background(), c)
	if !r.Canceled {
		t.Errorf("no match without AllowCustom should cancel, got %+v", r)
	}
}
