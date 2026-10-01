package main

import (
	"strings"
	"sync"
)

// RunOutputs holds raw command outputs captured this episode, keyed by task id.
// It is goroutine-safe: mu guards byTask in Add and Contains.
type RunOutputs struct {
	mu     sync.Mutex
	byTask map[string][]string
}

// NewRunOutputs returns an empty capture store.
func NewRunOutputs() *RunOutputs { return &RunOutputs{byTask: map[string][]string{}} }

// Add records one captured output for a task.
func (r *RunOutputs) Add(taskID, output string) {
	if taskID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byTask[taskID] = append(r.byTask[taskID], output)
}

// Count returns how many outputs have been captured for taskID.
func (r *RunOutputs) Count(taskID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byTask[taskID])
}

// Outputs returns a copy of the outputs captured for taskID, in capture order.
// The copy is safe to read without holding the lock. The code-side evidence
// backstop uses it to turn captured run_command output into evidence rows when
// the model recorded none.
func (r *RunOutputs) Outputs(taskID string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.byTask[taskID]))
	copy(out, r.byTask[taskID])
	return out
}

// Contains reports whether quote is a non-empty substring of some captured
// output for taskID.
func (r *RunOutputs) Contains(taskID, quote string) bool {
	if strings.TrimSpace(quote) == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, out := range r.byTask[taskID] {
		if strings.Contains(out, quote) {
			return true
		}
	}
	return false
}
