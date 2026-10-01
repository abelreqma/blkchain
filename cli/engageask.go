package main

import (
	"context"

	"blkchain/cli/internal/askuser"
)

// engageask.go is the Safe-mode clarification bridge for a REPL engagement. The
// orchestrator asks through askuser.Asker; in Safe mode we route those questions
// to the existing clarify overlay (clarify.go) over the event loop, so the
// operator answers in the TUI instead of the run auto-canceling. /auto uses
// askuser.AutoAsker (no questions) instead.
//
// askuser.ChannelAsker already serializes one Ask at a time and answers exactly
// once; the pump below is the interactive reader it expects: it reads each
// request, posts a clarifyMsg (which the base Update answers exactly once, the
// displaced case included), and relays the answer back with Reply.

// clarificationFromAskuser converts an askuser clarification to the TUI clarify
// overlay's type. The two are structurally identical but distinct packages.
func clarificationFromAskuser(c askuser.Clarification) Clarification {
	opts := make([]ClarifyOption, len(c.Options))
	for i, o := range c.Options {
		opts[i] = ClarifyOption{Label: o.Label, Note: o.Note, Value: o.Value}
	}
	return Clarification{Question: c.Question, Detail: c.Detail, Options: opts, AllowCustom: c.AllowCustom}
}

// clarifyResultToAskuser converts a TUI clarify result back to the askuser type.
func clarifyResultToAskuser(r ClarifyResult) askuser.ClarifyResult {
	return askuser.ClarifyResult{Value: r.Value, Custom: r.Custom, Canceled: r.Canceled}
}

// startEngageAsker returns a Safe-mode asker and starts the pump that bridges the
// orchestrator's clarifications to the clarify overlay via prog. The pump runs
// until ctx is done. A nil prog yields an AutoAsker (no overlay to post to).
func startEngageAsker(ctx context.Context, prog progSender) askuser.Asker {
	if prog == nil {
		return askuser.AutoAsker{}
	}
	a, reqs := askuser.NewChannelAsker()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case c := <-reqs:
				reply := make(chan ClarifyResult, 1)
				prog.Send(clarifyMsg{c: clarificationFromAskuser(c), reply: reply})
				select {
				case r := <-reply:
					a.Reply(clarifyResultToAskuser(r))
				case <-ctx.Done():
					a.Reply(askuser.ClarifyResult{Canceled: true})
					return
				}
			}
		}
	}()
	return a
}
