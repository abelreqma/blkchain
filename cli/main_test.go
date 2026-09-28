package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/client"
)

// captureStdout runs fn with os.Stdout redirected, returning everything it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading captured stdout: %v", err)
	}
	return string(out)
}

// TestRunSearchRendersResults exercises the rendering surface runSearch calls
// after Task 8 rewired retrieval through the Go retrieval package (direct
// Qdrant + embed_server access, not an HTTP mock): it drives formatResults
// directly with hand-built results, rather than running the full retrieval
// path, which needs live services (see the `blk search` live smoke check in
// the Task 8 plan instead).
func TestRunSearchRendersResults(t *testing.T) {
	results := []client.SearchResult{
		{
			ID:    "doc-1",
			Score: 0.8765,
			Payload: client.Payload{
				Source:  "ledger-spec",
				Path:    "docs/ledger.md",
				Section: "Consensus",
				Type:    "markdown",
				Text:    "The consensus algorithm reaches finality after two rounds of voting.",
			},
		},
	}

	out := formatResults("how does consensus work", results, 0)

	if !strings.Contains(out, "0.8765") {
		t.Errorf("output missing score, got:\n%s", out)
	}
	if !strings.Contains(out, "ledger-spec") {
		t.Errorf("output missing source, got:\n%s", out)
	}
	if !strings.Contains(out, "Consensus") {
		t.Errorf("output missing section, got:\n%s", out)
	}
	if !strings.Contains(out, "consensus algorithm reaches finality") {
		t.Errorf("output missing text snippet, got:\n%s", out)
	}
}

// TestRunSearchJSON verifies the --json output shape runSearch prints (a
// client.SearchResponse envelope, same as before Task 8's rewiring) round-trips,
// using printJSON directly rather than the full retrieval path (see
// TestRunSearchRendersResults).
func TestRunSearchJSON(t *testing.T) {
	canned := client.SearchResponse{
		Results: []client.SearchResult{
			{ID: "doc-1", Score: 0.5, Payload: client.Payload{Source: "src", Path: "p", Section: "s", Type: "t", Text: "hello"}},
		},
	}

	out := captureStdout(t, func() {
		if err := printJSON(canned); err != nil {
			t.Fatalf("printJSON() error = %v", err)
		}
	})

	var parsed client.SearchResponse
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, out)
	}
	if len(parsed.Results) != 1 || parsed.Results[0].ID != "doc-1" {
		t.Errorf("parsed = %+v, unexpected", parsed)
	}
}

// TestPrintSourcesRendersCitationsAndWebNote exercises the SOURCES block
// runAsk prints after both the streaming and non-streaming AnswerLoop paths
// (Task 13 routed ask through the Go-native AnswerLoop, direct Qdrant +
// embed_server + oMLX access, not an HTTP mock): it drives printSources
// directly with hand-built citations, rather than running the full answer
// loop, which needs live services (see the `blk ask` live smoke check in the
// task plan instead).
func TestPrintSourcesRendersCitationsAndWebNote(t *testing.T) {
	citations := []client.Citation{
		{Source: "ledger-spec", Path: "docs/ledger.md", Section: "Consensus"},
	}

	out := captureStdout(t, func() {
		printSources(citations, true)
	})

	if !strings.Contains(out, "SOURCES") {
		t.Errorf("output missing SOURCES header, got:\n%s", out)
	}
	if !strings.Contains(out, "ledger-spec") || !strings.Contains(out, "docs/ledger.md") || !strings.Contains(out, "Consensus") {
		t.Errorf("output missing citation details, got:\n%s", out)
	}
	if !strings.Contains(out, "used a web search") {
		t.Errorf("output missing used_web note, got:\n%s", out)
	}
}

// TestRunAskJSONShape verifies the --json envelope runAsk's non-streaming
// path marshals (a client.AnswerResponse, per the cross-language JSON
// contract) round-trips, using printJSON directly rather than the full
// AnswerLoop path (see TestPrintSourcesRendersCitationsAndWebNote).
func TestRunAskJSONShape(t *testing.T) {
	canned := &client.AnswerResponse{
		Answer: "Finality is reached after two rounds of voting.",
		Citations: []client.Citation{
			{Source: "ledger-spec", Path: "docs/ledger.md", Section: "Consensus"},
		},
		UsedWeb: true,
		Results: []client.SearchResult{
			{ID: "doc-1", Score: 0.5, Payload: client.Payload{Source: "src", Path: "p", Section: "s", Type: "t", Text: "hello"}},
		},
	}

	out := captureStdout(t, func() {
		if err := printJSON(canned); err != nil {
			t.Fatalf("printJSON() error = %v", err)
		}
	})

	var parsed client.AnswerResponse
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, out)
	}
	if parsed.Answer != canned.Answer || !parsed.UsedWeb || len(parsed.Citations) != 1 || len(parsed.Results) != 1 {
		t.Errorf("parsed = %+v, unexpected", parsed)
	}
}

func TestRunHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(client.HealthResponse{Status: "ok"})
	}))
	defer srv.Close()

	t.Setenv("BLKCHAIN_API_URL", srv.URL)

	out := captureStdout(t, func() {
		if err := runHealth(nil); err != nil {
			t.Fatalf("runHealth() error = %v", err)
		}
	})

	if !strings.Contains(out, "ok") {
		t.Errorf("output missing status, got:\n%s", out)
	}
}

// TestRunHealthUnreachable covers the Task 16 contract change: `blk health`
// probes Qdrant and embed_server directly and never depends on the Python
// API, so a dead dependency is reported as a down row, not a hard error.
func TestRunHealthUnreachable(t *testing.T) {
	t.Setenv("QDRANT_GRPC_URL", "127.0.0.1:1")

	if err := runHealth(nil); err != nil {
		t.Fatalf("runHealth should never error on an unreachable dependency, got %v", err)
	}
}

func TestReorderFlagsAfterQuery(t *testing.T) {
	// search: --top-k takes a value, --json is boolean.
	got := reorder([]string{"how", "does", "consensus", "work", "--top-k", "3", "--json"},
		map[string]bool{"top-k": true})
	want := []string{"--top-k", "3", "--json", "how", "does", "consensus", "work"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("reorder = %v, want %v", got, want)
	}

	// "--flag=value" form and a -- terminator that protects a dash-leading term.
	got = reorder([]string{"query", "--top-k=5", "--", "-literal"}, map[string]bool{"top-k": true})
	want = []string{"--top-k=5", "query", "-literal"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("reorder = %v, want %v", got, want)
	}
}

func TestProjectRootViaBlkchainRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte("[project]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_ROOT", root)

	got, err := projectRoot()
	if err != nil {
		t.Fatalf("projectRoot() error = %v", err)
	}
	if got != root {
		t.Errorf("projectRoot() = %q, want %q", got, root)
	}
}
