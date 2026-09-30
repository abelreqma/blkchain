package askuser

import (
	"context"
	"testing"
	"time"
)

func TestAutoAskerNeverBlocksAndCancels(t *testing.T) {
	done := make(chan ClarifyResult, 1)
	go func() {
		done <- AutoAsker{}.Ask(context.Background(), Clarification{Question: "which target?"})
	}()
	select {
	case r := <-done:
		if !r.Canceled {
			t.Errorf("AutoAsker result = %+v, want Canceled", r)
		}
	case <-time.After(time.Second):
		t.Fatal("AutoAsker.Ask blocked")
	}
}

func TestChannelAskerRoundTrip(t *testing.T) {
	a, reqs := NewChannelAsker()
	go func() {
		c := <-reqs
		if c.Question != "which target?" {
			t.Errorf("question = %q", c.Question)
		}
		a.Reply(ClarifyResult{Value: "10.0.0.5"})
	}()
	r := a.Ask(context.Background(), Clarification{Question: "which target?"})
	if r.Value != "10.0.0.5" || r.Canceled {
		t.Errorf("result = %+v, want Value 10.0.0.5", r)
	}
}

func TestChannelAskerCancelByContext(t *testing.T) {
	a, reqs := NewChannelAsker()
	go func() { <-reqs }() // read the request, never reply
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	r := a.Ask(ctx, Clarification{Question: "q"})
	if !r.Canceled {
		t.Errorf("result = %+v, want Canceled on ctx cancel", r)
	}
}

func TestChannelAskerLateReplyDoesNotLeakToNextAsk(t *testing.T) {
	a, reqs := NewChannelAsker()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-reqs }()
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	if r := a.Ask(ctx, Clarification{Question: "old"}); !r.Canceled {
		t.Fatalf("first Ask = %+v, want Canceled", r)
	}
	a.Reply(ClarifyResult{Value: "stale"}) // user answers the old prompt late

	go func() {
		c := <-reqs
		if c.Question != "new" {
			t.Errorf("question = %q, want new", c.Question)
		}
		a.Reply(ClarifyResult{Value: "fresh"})
	}()
	r := a.Ask(context.Background(), Clarification{Question: "new"})
	if r.Value != "fresh" || r.Canceled {
		t.Errorf("second Ask = %+v, want fresh", r)
	}
}

func TestChannelAskerReplyWithNoPendingAskDoesNotBlock(t *testing.T) {
	a, _ := NewChannelAsker()
	done := make(chan struct{})
	go func() {
		a.Reply(ClarifyResult{Value: "a"})
		a.Reply(ClarifyResult{Value: "b"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Reply blocked with no pending Ask")
	}
}
