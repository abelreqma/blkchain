package engreport

import (
	"encoding/json"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/webanalysis"
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
		"Completed tasks",
		"was not independently verified", // completion caveat
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

// secretModel is sampleModel with one valued secret candidate in its web snapshot.
func secretModel() Model {
	m := sampleModel()
	m.Web = &webanalysis.Snapshot{Findings: []webanalysis.Finding{{
		ID: "f1", Kind: "secret-candidate", Detector: "env-assignment", Confidence: "medium",
		Location:    webanalysis.Location{Unit: "app.bundle.js", Line: 1482},
		Preview:     `"fixture-secret-0001"`,
		Value:       "fixture-secret-0001",
		Name:        "STRIPE_API_KEY",
		SourceURL:   "https://app.example.test/static/app.bundle.js",
		Role:        "anonymous",
		Fingerprint: "9f2c1ab4e70d5386",
	}}}
	return m
}

// A secret candidate renders under its own heading with the analyzer's evidence
// grade. The old "Discovered credential" heading claimed more than the detector
// establishes. The matched value stays in the report: a discovered credential is
// target evidence the operator needs in every output.
func TestRenderMarkdownSecretCandidateIsGraded(t *testing.T) {
	md := RenderMarkdown(secretModel())
	for _, want := range []string{
		"## Secret candidates",
		"not a validated credential",
		"has not been tested for validity", // webanalysis evidence grade text
		"Detector confidence: medium",
		"app.bundle.js line 1482",
		"9f2c1ab4e70d5386",
		`"value":"fixture-secret-0001"`,
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	if strings.Contains(md, "Discovered credential") {
		t.Error("report still claims a discovered credential")
	}
}

// The JSON report carries the value too.
func TestRenderJSONKeepsSecretCandidateValue(t *testing.T) {
	data, err := RenderJSON(secretModel())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "fixture-secret-0001") {
		t.Error("JSON report dropped the secret candidate value")
	}
}

// A secret candidate is not a completed task: it must not be counted as one, and
// an engagement with no done tasks still says so.
func TestRenderMarkdownSecretCandidateIsNotACompletedTask(t *testing.T) {
	m := secretModel()
	for i := range m.Engagement.Tasks {
		m.Engagement.Tasks[i].Status = engagement.StatusTodo
	}
	md := RenderMarkdown(m)
	// The document carries a secret candidate, so assert the missing marker
	// rather than printing the rendered report.
	for _, want := range []string{"## Completed tasks\n", "None yet."} {
		if !strings.Contains(md, want) {
			t.Errorf("no done tasks must render an empty completed-task section; missing %q", want)
		}
	}
	if !strings.Contains(md, "## Secret candidates") {
		t.Error("secret candidate section missing")
	}
}

// With no web snapshot the section is omitted entirely rather than rendering an
// empty heading.
func TestRenderMarkdownOmitsEmptySecretCandidateSection(t *testing.T) {
	if strings.Contains(RenderMarkdown(sampleModel()), "Secret candidates") {
		t.Error("secret candidate section rendered with no candidates")
	}
}

// TestRenderMarkdownShowsStatedCompletionBasis pins that a completed task
// renders the basis plan_complete recorded and the evidence ids it cited,
// labelled as the executor's assertion rather than a verified fact.
func TestRenderMarkdownShowsStatedCompletionBasis(t *testing.T) {
	m := sampleModel()
	m.Engagement.Tasks[0].DoneWhen = "an open port is listed in scan output"
	m.Engagement.Tasks[0].CompletionBasis = "the quote lists 80/tcp open"
	m.Engagement.Tasks[0].CompletionEvidenceIDs = []string{"4", "7"}
	md := RenderMarkdown(m)
	for _, want := range []string{
		"- Done when: an open port is listed in scan output",
		"- Completion basis (asserted, not verified): the quote lists 80/tcp open",
		"- Cited evidence: 4, 7",
		"blkChain checked only that the cited evidence exists",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

// TestRenderMarkdownSaysWhenNoCompletionBasisWasStated pins the rendering of a
// task completed with no condition and no basis, as tasks completed before
// plan_complete required them have. Saying nothing would read as a task whose
// condition the report merely omitted.
func TestRenderMarkdownSaysWhenNoCompletionBasisWasStated(t *testing.T) {
	md := RenderMarkdown(sampleModel()) // t1 is done with no DoneWhen and no basis
	for _, want := range []string{
		"- Done when: no condition was recorded for this task.",
		"- Completion basis: none was stated; the task was completed on recorded evidence alone.",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}
