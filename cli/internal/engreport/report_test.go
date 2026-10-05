package engreport

import (
	"encoding/json"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
)

func sampleModel() Model {
	return Model{
		Goal:        "assess example.com",
		Scope:       "in: example.com",
		Mode:        "auto",
		Workspace:   "/ws",
		Status:      "in-progress",
		GeneratedAt: "2026-09-30T00:00:00Z",
		Engagement: engagement.Engagement{
			Revision: 3,
			Name:     "eng1",
			Tasks: []engagement.Task{
				{ID: "t1", Kind: "recon", Target: "example.com", Objective: "enumerate", Status: engagement.StatusDone},
				{ID: "t2", Kind: "web", Target: "example.com", Objective: "test xss", Status: engagement.StatusTodo, DependsOn: []string{"t1"}, BasisIDs: []string{"t1"}},
			},
		},
		Evidence:    map[string][]string{"t1": {"found open port 80"}},
		Receipts:    map[string][]engagement.Receipt{"t1": {{Skill: "recon-http", BundleDigest: "abc123", ContextGen: 2, At: "2026-09-30T00:00:00Z"}}},
		Transitions: []engagement.Transition{{Rev: 1, At: "2026-09-30T00:00:00Z", Kind: "init", Detail: "start"}},
	}
}

func TestRenderMarkdownHasSections(t *testing.T) {
	md := RenderMarkdown(sampleModel())
	for _, want := range []string{
		"assess example.com", // goal
		"Coverage",
		"Findings",
		"t1", "t2",
		"found open port 80", // evidence quote present
		"recon-http",         // receipt skill present
		"Timeline",
		"Next steps", // status != complete and an open task exists
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestRenderMarkdownShowsUnfinishedTaskEvidence(t *testing.T) {
	m := sampleModel()
	m.Engagement.Tasks[1].Status = engagement.StatusActive
	m.Evidence["t2"] = []string{"convergence-fixture-ok"}
	md := RenderMarkdown(m)
	if !strings.Contains(md, "Evidence from unfinished tasks") || !strings.Contains(md, "t2") || !strings.Contains(md, "convergence-fixture-ok") {
		t.Fatalf("unfinished evidence missing: %s", md)
	}
}

func TestRenderMarkdownEncodesUntrustedMarkup(t *testing.T) {
	m := sampleModel()
	m.Goal = "<script>alert(1)</script>"
	m.Final = "![remote](https://example.invalid/pixel)\n## forged section"
	m.Evidence["t2"] = []string{"<img src=https://example.invalid/pixel>"}
	md := RenderMarkdown(m)
	for _, forbidden := range []string{"<script>", "<img", "![remote]", "\n## forged section"} {
		if strings.Contains(md, forbidden) {
			t.Fatalf("active markup %q in report: %s", forbidden, md)
		}
	}
	for _, expected := range []string{"&lt;script&gt;", "&lt;img", "Final assessment", "Evidence from unfinished tasks"} {
		if !strings.Contains(md, expected) {
			t.Fatalf("encoded text %q missing: %s", expected, md)
		}
	}
}

func TestRenderMarkdownFinalCannotCreateSetextHeading(t *testing.T) {
	m := sampleModel()
	m.Final = "Verified coverage\n=================\n=== \n---\n--- \n> quoted line\n- forged item\n1. forged item"
	md := RenderMarkdown(m)
	for _, marker := range []string{"\n=================", "\n=== \n", "\n---\n", "\n--- \n", "\n> quoted line", "\n- forged item", "\n1. forged item"} {
		if strings.Contains(md, marker) {
			t.Fatalf("active Markdown marker %q: %s", marker, md)
		}
	}
	if !strings.Contains(md, "Verified coverage") || !strings.Contains(md, "Final assessment") {
		t.Fatalf("final text missing: %s", md)
	}
}

func TestRenderMarkdownKeepsQuotedBackticks(t *testing.T) {
	m := sampleModel()
	m.Engagement.Tasks[1].Status = engagement.StatusActive
	m.Evidence["t2"] = []string{"value `quoted`"}
	md := RenderMarkdown(m)
	if !strings.Contains(md, "value \\`quoted\\`") || strings.Contains(md, "value 'quoted'") {
		t.Fatalf("backtick evidence changed: %s", md)
	}
}

func TestRenderMarkdownEmptyEngagement(t *testing.T) {
	m := Model{Goal: "g", Status: "in-progress", GeneratedAt: "t"}
	md := RenderMarkdown(m) // must not panic
	if !strings.Contains(md, "g") {
		t.Errorf("empty engagement render missing goal")
	}
}

func TestRenderJSONValid(t *testing.T) {
	b, err := RenderJSON(sampleModel())
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if v["goal"] != "assess example.com" {
		t.Errorf("json goal = %v", v["goal"])
	}
}

func TestRenderMarkdownEscapesEvidence(t *testing.T) {
	m := sampleModel()
	m.Status = "complete"
	m.Evidence = map[string][]string{"t1": {"weird `backtick` and \"quote\" and\nnewline"}}
	md := RenderMarkdown(m)
	// The evidence words must survive (positive presence), safely encoded.
	if !strings.Contains(md, "backtick") || !strings.Contains(md, "quote") {
		t.Errorf("escaped evidence text missing from output")
	}
	// No raw control characters leak into the document.
	if strings.ContainsAny(md, "\x00") {
		t.Errorf("unexpected NUL in output")
	}
	// A completed engagement omits the Next steps section.
	if strings.Contains(md, "Next steps") {
		t.Errorf("completed engagement should not render Next steps")
	}
}
