// Package engreport renders an engagement report as Markdown and JSON. The
// renderers are pure functions over an in-memory Model assembled from the
// engagement store; they perform no I/O so they are deterministic and testable.
package engreport

import (
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/webanalysis"
)

// Model is the assembled, render-ready view of an engagement.
type Model struct {
	Final          string                          `json:"final,omitempty"`
	Web            *webanalysis.Snapshot           `json:"web,omitempty"`
	Goal           string                          `json:"goal"`
	Scope          string                          `json:"scope"`
	Mode           string                          `json:"mode"`
	Workspace      string                          `json:"workspace"`
	Status         string                          `json:"status"` // complete | in-progress | interrupted | paused
	GeneratedAt    string                          `json:"generated_at"`
	Engagement     engagement.Engagement           `json:"engagement"`
	Evidence       map[string][]string             `json:"evidence"` // task id -> evidence quotes
	Receipts       map[string][]engagement.Receipt `json:"receipts"` // task id -> skill receipts
	Transitions    []engagement.Transition         `json:"transitions"`
	Denials        []Denial                        `json:"denials,omitempty"`
	DenialsOmitted int                             `json:"denials_omitted,omitempty"`
}

type Denial struct {
	Action string `json:"action"`
	Detail string `json:"detail"`
}

// RenderJSON emits the model as indented JSON.
func RenderJSON(m Model) ([]byte, error) {
	if m.Web != nil {
		w := webanalysis.Display(*m.Web)
		m.Web = &w
	}
	return json.MarshalIndent(m, "", "  ")
}

// RenderMarkdown renders the model as a Markdown report.
func RenderMarkdown(m Model) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Engagement Report\n\n")
	fmt.Fprintf(&b, "- Goal: %s\n", safeMarkdownLine(m.Goal))
	fmt.Fprintf(&b, "- Scope: %s\n", safeMarkdownLine(m.Scope))
	fmt.Fprintf(&b, "- Mode: %s\n", safeMarkdownLine(m.Mode))
	fmt.Fprintf(&b, "- Workspace: %s\n", safeMarkdownLine(m.Workspace))
	fmt.Fprintf(&b, "- Status: %s\n", safeMarkdownLine(m.Status))
	fmt.Fprintf(&b, "- Generated: %s\n", safeMarkdownLine(m.GeneratedAt))
	fmt.Fprintf(&b, "- Revision: %d\n\n", m.Engagement.Revision)
	if strings.TrimSpace(m.Final) != "" {
		b.WriteString("## Final assessment\n\n")
		b.WriteString(sanitizeFinal(m.Final))
		b.WriteString("\n\n")
	}

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
		fmt.Fprintf(&b, " %s=%d", safeMarkdownLine(k), byStatus[k])
	}
	b.WriteString("\n- By kind:")
	if len(byKind) == 0 {
		b.WriteString(" none")
	}
	for _, k := range sortedKeys(byKind) {
		fmt.Fprintf(&b, " %s=%d", safeMarkdownLine(k), byKind[k])
	}
	b.WriteString("\n\n")
	if len(m.Denials) > 0 || m.DenialsOmitted > 0 {
		b.WriteString("## Policy denials\n\n")
		for _, denial := range m.Denials {
			fmt.Fprintf(&b, "- %s: %s\n", safeMarkdownLine(denial.Action), safeMarkdownLine(denial.Detail))
		}
		if m.DenialsOmitted > 0 {
			fmt.Fprintf(&b, "- %d additional denial(s) remain in the audit log.\n", m.DenialsOmitted)
		}
		b.WriteString("\n")
	}

	// Findings: done tasks with their evidence and skill receipts.
	b.WriteString("## Findings\n\n")
	findings := 0
	for _, t := range tasks {
		if t.Status != engagement.StatusDone {
			continue
		}
		findings++
		fmt.Fprintf(&b, "### %s [%s] %s\n\n", safeMarkdownLine(t.ID), safeMarkdownLine(t.Kind), safeMarkdownLine(t.Target))
		if t.Objective != "" {
			fmt.Fprintf(&b, "- Objective: %s\n", safeMarkdownLine(t.Objective))
		}
		if t.DoneWhen != "" {
			fmt.Fprintf(&b, "- Done when: %s\n", safeMarkdownLine(t.DoneWhen))
		}
		quotes := m.Evidence[t.ID]
		if len(quotes) > 0 {
			b.WriteString("- Evidence:\n")
			for _, q := range quotes {
				fmt.Fprintf(&b, "  > %s\n", safeMarkdownLine(q))
			}
		}
		receipts := m.Receipts[t.ID]
		if len(receipts) > 0 {
			b.WriteString("- Skills used:")
			for _, r := range receipts {
				fmt.Fprintf(&b, " %s", safeMarkdownLine(r.Skill))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if m.Web != nil {
		for _, finding := range webanalysis.Display(*m.Web).Findings {
			if finding.Kind != "secret-candidate" || finding.Value == "" {
				continue
			}
			findings++
			data, _ := webanalysis.FindingEvent("", finding)
			fmt.Fprintf(&b, "### Discovered credential\n\n```json\n%s\n```\n\n", data)
		}
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
		fmt.Fprintf(&b, "- %s [%s] status=%s target=%s", safeMarkdownLine(t.ID), safeMarkdownLine(t.Kind), safeMarkdownLine(string(t.Status)), safeMarkdownLine(t.Target))
		if len(t.DependsOn) > 0 {
			fmt.Fprintf(&b, " depends_on=%s", safeMarkdownLine(strings.Join(t.DependsOn, ",")))
		}
		if len(t.BasisIDs) > 0 {
			fmt.Fprintf(&b, " basis=%s", safeMarkdownLine(strings.Join(t.BasisIDs, ",")))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	shownUnfinished := false
	for _, task := range tasks {
		if task.Status == engagement.StatusDone || len(m.Evidence[task.ID]) == 0 {
			continue
		}
		if !shownUnfinished {
			b.WriteString("## Evidence from unfinished tasks\n\n")
			shownUnfinished = true
		}
		fmt.Fprintf(&b, "### %s [%s]\n\n", safeMarkdownLine(task.ID), safeMarkdownLine(string(task.Status)))
		for _, quote := range m.Evidence[task.ID] {
			fmt.Fprintf(&b, "> %s\n", safeMarkdownLine(quote))
		}
		b.WriteString("\n")
	}

	// Timeline.
	b.WriteString("## Timeline\n\n")
	if len(m.Transitions) == 0 {
		b.WriteString("No transitions.\n\n")
	}
	for _, tr := range m.Transitions {
		fmt.Fprintf(&b, "- rev %d %s [%s] %s\n", tr.Rev, safeMarkdownLine(tr.At), safeMarkdownLine(tr.Kind), safeMarkdownLine(tr.Detail))
	}
	b.WriteString("\n")

	// Next steps: open tasks, only when the engagement is not complete.
	if m.Status != "complete" {
		b.WriteString("## Next steps\n\n")
		open := 0
		for _, t := range tasks {
			if t.Status == engagement.StatusTodo || t.Status == engagement.StatusActive || t.Status == engagement.StatusBlocked {
				open++
				fmt.Fprintf(&b, "- %s [%s] status=%s objective=%s\n", safeMarkdownLine(t.ID), safeMarkdownLine(t.Kind), safeMarkdownLine(string(t.Status)), safeMarkdownLine(t.Objective))
			}
		}
		if open == 0 {
			b.WriteString("No open tasks.\n")
		}
		b.WriteString("\n")
	}

	if m.Web != nil {
		w := webanalysis.Display(*m.Web)
		b.WriteString("## Web analysis\n\n")
		fmt.Fprintf(&b, "Artifacts: %d. Source units: %d. Functions: %d. API operations: %d.\n\n", len(w.Artifacts), len(w.Units), len(w.Functions), len(w.Operations))
		for _, o := range w.Operations {
			fmt.Fprintf(&b, "- %s %s%s [%s] discovery=%s features=%s calls=%s\n", safeMarkdownLine(o.Method), safeMarkdownLine(o.Origin), safeMarkdownLine(o.Path), safeMarkdownLine(o.Validation), safeMarkdownLine(strings.Join(o.Discoveries, ",")), safeMarkdownLine(strings.Join(o.Features, ",")), safeMarkdownLine(strings.Join(o.Calls, ",")))
			for _, parameter := range o.Parameters {
				fmt.Fprintf(&b, "  - %s: %s\n", safeMarkdownLine(parameter.Field), safeMarkdownLine(parameter.Expression))
			}
			for _, example := range o.Examples {
				fmt.Fprintf(&b, "  - Request: %s %s, status %d\n", safeMarkdownLine(example.Method), safeMarkdownLine(example.URL), example.Status)
				keys := []string{}
				for key := range example.Headers {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					fmt.Fprintf(&b, "    - %s: %s\n", safeMarkdownLine(key), safeMarkdownLine(strings.Join(example.Headers[key], ", ")))
				}
				if example.Body != "" {
					fmt.Fprintf(&b, "    - Body: %s\n", safeMarkdownLine(example.Body))
				}
			}
		}
		b.WriteString("\n### Analysis leads\n\n")
		for _, f := range w.Findings {
			if f.Kind == "secret-candidate" && f.Value != "" {
				continue
			}
			fmt.Fprintf(&b, "- %s [%s] unit=%s line=%d detector=%s version=%s %s\n", safeMarkdownLine(f.Kind), safeMarkdownLine(string(f.Confidence)), safeMarkdownLine(f.Location.Unit), f.Location.Line, safeMarkdownLine(f.Detector), safeMarkdownLine(f.Version), safeMarkdownLine(f.Preview))
		}
		b.WriteString("\n### Collection coverage\n\n")
		for _, c := range w.Coverage {
			fmt.Fprintf(&b, "- Role %s: %s, %d routes, %d interactions, %d requests, %d bytes\n", safeMarkdownLine(c.Role), safeMarkdownLine(c.State), len(c.Routes), len(c.Interactions), c.Requests, c.Bytes)
			fmt.Fprintf(&b, "  - Stages: %s\n", safeMarkdownLine(strings.Join(c.Stages, ", ")))
			for _, target := range c.Targets {
				fmt.Fprintf(&b, "  - Target: %s\n", safeMarkdownLine(target))
			}
			for _, route := range c.Routes {
				fmt.Fprintf(&b, "  - Visited: %s\n", safeMarkdownLine(route))
			}
			for _, action := range c.Interactions {
				fmt.Fprintf(&b, "  - Interaction: %s\n", safeMarkdownLine(action))
			}
			for _, artifact := range c.Downloaded {
				fmt.Fprintf(&b, "  - Downloaded artifact: %s\n", safeMarkdownLine(artifact))
			}
			for _, g := range c.Gaps {
				fmt.Fprintf(&b, "  - %s %s: %s\n", safeMarkdownLine(g.Stage), safeMarkdownLine(g.URL), safeMarkdownLine(g.Reason))
			}
		}
	}
	return b.String()
}

func sanitizeFinal(s string) string {
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	lines := strings.Split(clean, "\n")
	for i, line := range lines {
		encoded := escapeMarkdownText(line)
		trimmed := strings.TrimLeft(line, " \t")
		if startsMarkdownBlock(trimmed) {
			prefix := len(line) - len(trimmed)
			encoded = encoded[:prefix] + "\\" + encoded[prefix:]
		}
		lines[i] = encoded
	}
	return strings.Join(lines, "\n")
}

func startsMarkdownBlock(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	if strings.Trim(trimmed, "=-") == "" || strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "+ ") {
		return true
	}
	i := 0
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	return i > 0 && i+1 < len(line) && (line[i] == '.' || line[i] == ')') && line[i+1] == ' '
}

var markdownEscaper = strings.NewReplacer(
	"\\", "\\\\", "`", "\\`", "!", "\\!", "[", "\\[", "]", "\\]",
	"(", "\\(", ")", "\\)", "*", "\\*", "_", "\\_", "#", "\\#", "~", "\\~",
)

func escapeMarkdownText(s string) string { return html.EscapeString(markdownEscaper.Replace(s)) }

func safeMarkdownLine(s string) string { return escapeMarkdownText(sanitizeQuote(s)) }

// sortedKeys returns the map keys in sorted order for deterministic output.
func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sanitizeQuote maps control characters to spaces for one Markdown line.
func sanitizeQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
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
