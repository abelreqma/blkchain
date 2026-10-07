package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

// promptText concatenates the text parts of a captured model message, so a test
// can assert what reached the prompt.
func promptText(mc llms.MessageContent) string {
	var b strings.Builder
	for _, p := range mc.Parts {
		if tc, ok := p.(llms.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// perQuerySearcher returns a distinct result set per exact query string, so a test
// can model a product page that only one of the two issued queries surfaces.
type perQuerySearcher struct{ byQuery map[string][]retrieval.Result }

func (p *perQuerySearcher) Search(_ context.Context, q string, _ int, _ map[string]any) ([]retrieval.Result, error) {
	return p.byQuery[q], nil
}

func TestBuildExploitQueries(t *testing.T) {
	q := buildExploitQueries(Service{Product: "GitLab", Version: "11.4.7"})
	if len(q) != 2 {
		t.Fatalf("want 2 queries (version-bearing + version-free), got %v", q)
	}
	if !strings.Contains(q[0], "11.4.7") {
		t.Errorf("first query must bear the version: %q", q[0])
	}
	if strings.Contains(q[1], "11.4.7") {
		t.Errorf("second query must be version-free: %q", q[1])
	}
	for _, x := range q {
		if !strings.Contains(x, "GitLab") {
			t.Errorf("query missing product token: %q", x)
		}
		if !strings.Contains(x, "exploit") {
			t.Errorf("query missing technique terms: %q", x)
		}
	}
	// A versionless service yields a single, clean (no double-space) query.
	if q2 := buildExploitQueries(Service{Product: "nginx"}); len(q2) != 1 || strings.Contains(q2[0], "  ") {
		t.Fatalf("versionless service must yield one clean query, got %v", q2)
	}
}

func TestNoteLinesSkipsFencesAndBlanks(t *testing.T) {
	got := noteLines("### Heading\n```\n\nReal exploit body line.\nSecond line.\nThird.", 5)
	want := []string{"### Heading", "Real exploit body line.", "Second line.", "Third."}
	if len(got) != len(want) {
		t.Fatalf("noteLines = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("noteLines[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// The real product page is returned ONLY by the version-free (second) query; the
// version-bearing query returns an off-target page that does not mention the
// product, so acceptCitation skips it. A single-query selector issuing only
// "<product> <version> exploit" misses the real page entirely. The two-query union
// must find it, and the notes must carry its BODY (the CVE line), not just the
// heading, so the model can label it.
func TestComputeExploitSelectionUnionFeedsAcceptedBody(t *testing.T) {
	real := retrieval.Result{ID: "r1", Score: 1, Payload: retrieval.Payload{
		Source: "offensive-rce", Path: "es.md", Section: "9200 - Pentesting Elasticsearch",
		Text: "### Pentesting Elasticsearch\n```\n\nCVE-2015-1427 Groovy sandbox bypass yields RCE on Elasticsearch.",
	}}
	offTarget := retrieval.Result{ID: "r2", Score: 1, Payload: retrieval.Payload{
		Source: "hacktricks", Path: "logstash.md", Section: "Logstash Privilege Escalation",
		Text: "Logstash pipeline abuse; no product token here.",
	}}
	rc := &perQuerySearcher{byQuery: map[string][]retrieval.Result{
		"Elasticsearch 1.4.2 exploit vulnerability CVE": {offTarget},
		"Elasticsearch exploit vulnerability CVE":       {real},
	}}
	m := &fakeModel{queue: []*llms.ContentResponse{textResp(`{"technique":"CVE-2015-1427 Groovy RCE"}`)}}

	tech, cit := computeExploitSelection(context.Background(), m, rc, ragconfig.Config{TopK: 5},
		Service{Product: "Elasticsearch", Version: "1.4.2", Port: 9200})

	if tech == "" {
		t.Fatal("two-query union must ground the real page returned only by the version-free query")
	}
	if cit.Source != "offensive-rce" {
		t.Fatalf("citation must be the real ES page, got %+v", cit)
	}
	if len(m.seen) == 0 || len(m.seen[0]) == 0 {
		t.Fatal("model was not called")
	}
	if p := promptText(m.seen[0][0]); !strings.Contains(p, "CVE-2015-1427") {
		t.Errorf("model notes must carry the accepted hit BODY (the CVE line), got prompt:\n%s", p)
	}
}

func TestComputeExploitSelectionNotesRetainBreadth(t *testing.T) {
	overview := retrieval.Result{ID: "a", Score: 1, Payload: retrieval.Payload{
		Source: "offensive-skills", Path: "cicd.md", Section: "Jenkins Exploitation",
		Text: "## Jenkins Exploitation\nJenkins presents a broad attack surface through its script console and build steps.",
	}}
	technique := retrieval.Result{ID: "b", Score: 1, Payload: retrieval.Payload{
		Source: "offensive-skills", Path: "cicd.md", Section: "Jenkins Remoting Deserialization",
		Text: "### Jenkins Remoting Deserialization\nWhen the remoting port is exposed an attacker gains RCE.",
	}}
	rc := &perQuerySearcher{byQuery: map[string][]retrieval.Result{
		"Jenkins 2.138 exploit vulnerability CVE": {overview, technique},
		"Jenkins exploit vulnerability CVE":       {overview, technique},
	}}
	m := &fakeModel{queue: []*llms.ContentResponse{textResp(`{"technique":"Jenkins Remoting Deserialization"}`)}}
	if _, _ = computeExploitSelection(context.Background(), m, rc, ragconfig.Config{TopK: 5}, Service{Product: "Jenkins", Version: "2.138"}); len(m.seen) == 0 || len(m.seen[0]) == 0 {
		t.Fatal("model was not called")
	}
	p := promptText(m.seen[0][0])
	if !strings.Contains(p, "Jenkins Exploitation") {
		t.Errorf("notes should feature the accepted hit (depth), got:\n%s", p)
	}
	if !strings.Contains(p, "Remoting Deserialization") {
		t.Errorf("notes must retain the sibling technique heading (breadth), got:\n%s", p)
	}
}

// No top-K hit over the union mentions the product (fabricated product): the
// selector must abstain, preserving no-false-grounding.
func TestComputeExploitSelectionUnionFailsClosed(t *testing.T) {
	junk := retrieval.Result{ID: "x1", Score: 9, Payload: retrieval.Payload{
		Source: "misc", Path: "a.md", Section: "Generic", Text: "nothing about this product at all",
	}}
	rc := &perQuerySearcher{byQuery: map[string][]retrieval.Result{
		"Frobnicator 1.0 exploit vulnerability CVE": {junk},
		"Frobnicator exploit vulnerability CVE":     {junk},
	}}
	m := &fakeModel{queue: []*llms.ContentResponse{textResp(`{"technique":"should not be reached"}`)}}
	tech, cit := computeExploitSelection(context.Background(), m, rc, ragconfig.Config{TopK: 5},
		Service{Product: "Frobnicator", Version: "1.0"})
	if tech != "" || cit.Source != "" {
		t.Fatalf("fabricated product must abstain (no false grounding), got tech=%q cit=%+v", tech, cit)
	}
}

// A Citation names only source/path/section, so it cannot identify which
// retrieved chunk grounded a candidate; the accepted index is the only unambiguous
// handle, and the notes fed to the label prompt must follow it rather than the
// first result. The grounding chunk here is the second one: the first is a generic
// page whose locating metadata does not name the product, so citationNamesSubject
// skips it. (The discriminator is the metadata rather than the body text because
// the product path grounds on locating metadata; see citationNamesSubject.)
func TestComputeExploitSelectionNotesFollowTheGroundingChunk(t *testing.T) {
	decoy := retrieval.Result{ID: "d1", Score: 1, Payload: retrieval.Payload{
		Source: "offensive-rce", Path: "nosql.md", Section: "9200 - Pentesting NoSQL",
		Text: "## Pentesting NoSQL\nGeneric document-store enumeration notes.\nNo product token here.",
	}}
	grounding := retrieval.Result{ID: "g1", Score: 1, Payload: retrieval.Payload{
		Source: "offensive-rce", Path: "9200-pentesting-elasticsearch.md", Section: "Elasticsearch",
		Text: "### Groovy sandbox bypass\nCVE-2015-1427 yields RCE on Elasticsearch.",
	}}
	rc := &perQuerySearcher{byQuery: map[string][]retrieval.Result{
		"Elasticsearch 1.4.2 exploit vulnerability CVE": {decoy, grounding},
		"Elasticsearch exploit vulnerability CVE":       {decoy, grounding},
	}}
	m := &fakeModel{queue: []*llms.ContentResponse{textResp(`{"technique":"CVE-2015-1427"}`)}}
	if _, _ = computeExploitSelection(context.Background(), m, rc, ragconfig.Config{TopK: 5},
		Service{Product: "Elasticsearch", Version: "1.4.2", Port: 9200}); len(m.seen) == 0 {
		t.Fatal("model was not called")
	}
	if p := promptText(m.seen[0][0]); !strings.Contains(p, "CVE-2015-1427") {
		t.Errorf("notes must carry the GROUNDING chunk's body, got prompt:\n%s", p)
	}
}

// A corpus line is untrusted and unbounded; every notes line stays capped.
func TestNoteLinesCapsLineLength(t *testing.T) {
	for _, ln := range noteLines(strings.Repeat("A", 5000)+"\n"+strings.Repeat("B", 5000), 2) {
		if len(ln) > 200 {
			t.Fatalf("notes line not capped: %d chars", len(ln))
		}
	}
}

// Scores from two different queries are not comparable, so the union keeps
// query order: a product-specific hit from the version-bearing query grounds
// ahead of one from the version-free query.
func TestComputeExploitSelectionPrefersVersionBearingQuery(t *testing.T) {
	versioned := retrieval.Result{ID: "v1", Score: 0.1, Payload: retrieval.Payload{
		Source: "versioned-page", Path: "a.md", Section: "GitLab 11.4.7 RCE",
		Text: "### GitLab 11.4.7 RCE\nAuthenticated RCE via the Redis-backed job queue.",
	}}
	generic := retrieval.Result{ID: "g2", Score: 9, Payload: retrieval.Payload{
		Source: "generic-page", Path: "b.md", Section: "GitLab hardening",
		Text: "### GitLab hardening\nGeneral GitLab hardening guidance.",
	}}
	rc := &perQuerySearcher{byQuery: map[string][]retrieval.Result{
		"GitLab 11.4.7 exploit vulnerability CVE": {versioned},
		"GitLab exploit vulnerability CVE":        {generic},
	}}
	m := &fakeModel{queue: []*llms.ContentResponse{textResp(`{"technique":"GitLab 11.4.7 RCE"}`)}}
	_, cit := computeExploitSelection(context.Background(), m, rc, ragconfig.Config{TopK: 5},
		Service{Product: "GitLab", Version: "11.4.7"})
	if cit.Source != "versioned-page" {
		t.Fatalf("version-bearing query's hit must ground first, got %+v", cit)
	}
}
