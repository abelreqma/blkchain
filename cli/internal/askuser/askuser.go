// Package askuser is the clarification protocol between the harness orchestrator
// and the interactive REPL. It has no store or model dependency so both sides
// can import it. In /auto the AutoAsker suppresses questions.
package askuser

import (
	"context"
	"sync"
)

// ClarifyOption is one offered answer to a clarification.
type ClarifyOption struct {
	Label string
	Note  string
	Value string
}

// Clarification is a question the orchestrator asks the operator.
type Clarification struct {
	Question    string
	Detail      string
	Options     []ClarifyOption
	AllowCustom bool
}

// ClarifyResult is the operator's answer. Canceled is true when no answer was given
// (context canceled, or suppressed in /auto).
type ClarifyResult struct {
	Value    string
	Custom   string
	Canceled bool
}

// Asker asks the operator a clarification and returns the answer.
type Asker interface {
	Ask(ctx context.Context, c Clarification) ClarifyResult
}

// AutoAsker suppresses clarifications: it returns a canceled result at once and
// never blocks. Used in /auto.
type AutoAsker struct{}

// Ask returns a canceled result without blocking.
func (AutoAsker) Ask(ctx context.Context, c Clarification) ClarifyResult {
	return ClarifyResult{Canceled: true}
}

// ChannelAsker delivers a clarification to a reader on a request channel and
// blocks for a reply. The interactive side reads the channel returned by
// NewChannelAsker and calls Reply. Asks are serialized: one is in flight at a
// time, so a reply can only reach the Ask it answers.
type ChannelAsker struct {
	reqs chan Clarification
	slot chan struct{} // capacity 1: held for the duration of one Ask

	mu      sync.Mutex
	pending chan ClarifyResult // reply channel of the in-flight Ask, or nil
}

// NewChannelAsker returns the asker and the request channel the interactive side
// reads.
func NewChannelAsker() (*ChannelAsker, <-chan Clarification) {
	a := &ChannelAsker{
		reqs: make(chan Clarification),
		slot: make(chan struct{}, 1),
	}
	return a, a.reqs
}

// Ask sends c and blocks until Reply is called or ctx is done.
func (a *ChannelAsker) Ask(ctx context.Context, c Clarification) ClarifyResult {
	select {
	case a.slot <- struct{}{}:
	case <-ctx.Done():
		return ClarifyResult{Canceled: true}
	}
	defer func() { <-a.slot }()

	p := make(chan ClarifyResult, 1)
	a.mu.Lock()
	a.pending = p
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		if a.pending == p {
			a.pending = nil
		}
		a.mu.Unlock()
	}()

	select {
	case a.reqs <- c:
	case <-ctx.Done():
		return ClarifyResult{Canceled: true}
	}
	select {
	case r := <-p:
		return r
	case <-ctx.Done():
		return ClarifyResult{Canceled: true}
	}
}

// Reply hands the answer to the in-flight Ask. It never blocks. A reply with no
// pending Ask (late after a cancel, or a duplicate) is dropped.
func (a *ChannelAsker) Reply(r ClarifyResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending == nil {
		return
	}
	select {
	case a.pending <- r:
	default:
	}
	a.pending = nil
}
