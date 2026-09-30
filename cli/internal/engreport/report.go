// Package engreport renders an engagement report as Markdown and JSON. The
// renderers are pure functions over an in-memory Model assembled from the
// engagement store; they perform no I/O so they are deterministic and testable.
package engreport

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"blkchain/cli/internal/engagement"
)

// Model is the assembled, render-ready view of an engagement.
type Model struct {
	Goal        string                          `json:"goal"`
	Scope       string                          `json:"scope"`
	Mode        string                          `json:"mode"`
	Workspace   string                          `json:"workspace"`
	Status      string                          `json:"status"` // complete | in-progress | interrupted
	GeneratedAt string                          `json:"generated_at"`
	Engagement  engagement.Engagement           `json:"engagement"`
	Evidence    map[string][]string             `json:"evidence"` // task id -> evidence quotes
	Receipts    map[string][]engagement.Receipt `json:"receipts"` // task id -> skill receipts
	Transitions []engagement.Transition         `json:"transitions"`
}

// RenderJSON emits the model as indented JSON.
func RenderJSON(m Model) ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// RenderMarkdown renders the model as a Markdown report.
func RenderMarkdown(m Model) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Engagement Report\n\n")
	fmt.Fprintf(&b, "- Goal: %s\n", m.Goal)
	fmt.Fprintf(&b, "- Scope: %s\n", m.Scope)
	fmt.Fprintf(&b, "- Mode: %s\n", m.Mode)
	fmt.Fprintf(&b, "- Workspace: %s\n", m.Workspace)
	fmt.Fprintf(&b, "- Status: %s\n", m.Status)
	fmt.Fprintf(&b, "- Generated: %s\n", m.GeneratedAt)
	fmt.Fprintf(&b, "- Revision: %d\n\n", m.Engagement.Revision)

	tasks := m.Engagement.Tasks

	// Coverage.
	b.WriteString("## Coverage\n\n")
	byStatus := map[string]int{}
	byKind := map[string]int{}
	for _, t := range tasks {
		byStatus[string(t.Status)]++
		byKind[t.Kind]++
	}
	fmt.Fprintf(&b, "- Total tasks: %d\n", len(tasks))
	b.WriteString("- By status:")
	if len(byStatus) == 0 {
		b.WriteString(" none")
	}
	for _, k := range sortedKeys(byStatus) {
		fmt.Fprintf(&b, " %s=%d", k, byStatus[k])
	}
	b.WriteString("\n- By kind:")
	if len(byKind) == 0 {
		b.WriteString(" none")
	}
	for _, k := range sortedKeys(byKind) {
		fmt.Fprintf(&b, " %s=%d", k, byKind[k])
	}
	b.WriteString("\n\n")

	// Findings: done tasks with their evidence and skill receipts.
	b.WriteString("## Findings\n\n")
	findings := 0
	for _, t := range tasks {
		if t.Status != engagement.StatusDone {
			continue
		}
		findings++
		fmt.Fprintf(&b, "### %s [%s] %s\n\n", t.ID, t.Kind, t.Target)
		if t.Objective != "" {
			fmt.Fprintf(&b, "- Objective: %s\n", t.Objective)
		}
		if t.DoneWhen != "" {
			fmt.Fprintf(&b, "- Done when: %s\n", t.DoneWhen)
		}
		quotes := m.Evidence[t.ID]
		if len(quotes) > 0 {
			b.WriteString("- Evidence:\n")
			for _, q := range quotes {
				fmt.Fprintf(&b, "  > %s\n", sanitizeQuote(q))
			}
		}
		receipts := m.Receipts[t.ID]
		if len(receipts) > 0 {
			b.WriteString("- Skills used:")
			for _, r := range receipts {
				fmt.Fprintf(&b, " %s", r.Skill)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if findings == 0 {
		b.WriteString("None yet.\n\n")
	}

	// Task graph.
	b.WriteString("## Tasks\n\n")
	if len(tasks) == 0 {
		b.WriteString("None.\n\n")
	}
	for _, t := range tasks {
		fmt.Fprintf(&b, "- %s [%s] status=%s target=%s", t.ID, t.Kind, t.Status, t.Target)
		if len(t.DependsOn) > 0 {
			fmt.Fprintf(&b, " depends_on=%s", strings.Join(t.DependsOn, ","))
		}
		if len(t.BasisIDs) > 0 {
			fmt.Fprintf(&b, " basis=%s", strings.Join(t.BasisIDs, ","))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// Timeline.
	b.WriteString("## Timeline\n\n")
	if len(m.Transitions) == 0 {
		b.WriteString("No transitions.\n\n")
	}
	for _, tr := range m.Transitions {
		fmt.Fprintf(&b, "- rev %d %s [%s] %s\n", tr.Rev, tr.At, tr.Kind, sanitizeQuote(tr.Detail))
	}
	b.WriteString("\n")

	// Next steps: open tasks, only when the engagement is not complete.
	if m.Status != "complete" {
		b.WriteString("## Next steps\n\n")
		open := 0
		for _, t := range tasks {
			if t.Status == engagement.StatusTodo || t.Status == engagement.StatusActive || t.Status == engagement.StatusBlocked {
				open++
				fmt.Fprintf(&b, "- %s [%s] status=%s objective=%s\n", t.ID, t.Kind, t.Status, t.Objective)
			}
		}
		if open == 0 {
			b.WriteString("No open tasks.\n")
		}
		b.WriteString("\n")
	}

	return b.String()
}

// sortedKeys returns the map keys in sorted order for deterministic output.
func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sanitizeQuote makes an untrusted evidence quote or transition detail safe to
// embed in a single Markdown line: backticks become apostrophes, CR/LF and other
// control characters become spaces, so the quote cannot break the document.
func sanitizeQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '`':
			b.WriteByte('\'')
		case r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
