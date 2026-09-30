package main

import "strings"

// RunOutputs holds raw command outputs captured this episode, keyed by task id.
// It is not goroutine-safe: tool calls run sequentially. Revisit if execution parallelizes.
type RunOutputs struct {
	byTask map[string][]string
}

// NewRunOutputs returns an empty capture store.
func NewRunOutputs() *RunOutputs { return &RunOutputs{byTask: map[string][]string{}} }

// Add records one captured output for a task.
func (r *RunOutputs) Add(taskID, output string) {
	if taskID == "" {
		return
	}
	r.byTask[taskID] = append(r.byTask[taskID], output)
}

// Contains reports whether quote is a non-empty substring of some captured
// output for taskID.
func (r *RunOutputs) Contains(taskID, quote string) bool {
	if strings.TrimSpace(quote) == "" {
		return false
	}
	for _, out := range r.byTask[taskID] {
		if strings.Contains(out, quote) {
			return true
		}
	}
	return false
}
