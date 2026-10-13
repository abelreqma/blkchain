// Package askuser is the clarification protocol between the harness orchestrator
// and the interactive REPL. It has no store or model dependency so both sides
// can import it. In /auto the AutoAsker suppresses questions.
package askuser

import "context"

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
