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
