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

func TestRunSearchRendersResults(t *testing.T) {
	canned := client.SearchResponse{
		Results: []client.SearchResult{
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
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(canned)
	}))
	defer srv.Close()

	t.Setenv("BLKCHAIN_API_URL", srv.URL)

	out := captureStdout(t, func() {
		if err := runSearch([]string{"--top-k", "3", "how", "does", "consensus", "work"}); err != nil {
			t.Fatalf("runSearch() error = %v", err)
		}
	})

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

func TestRunSearchJSON(t *testing.T) {
	canned := client.SearchResponse{
		Results: []client.SearchResult{
			{ID: "doc-1", Score: 0.5, Payload: client.Payload{Source: "src", Path: "p", Section: "s", Type: "t", Text: "hello"}},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(canned)
	}))
	defer srv.Close()
	t.Setenv("BLKCHAIN_API_URL", srv.URL)

	out := captureStdout(t, func() {
		if err := runSearch([]string{"--json", "hello"}); err != nil {
			t.Fatalf("runSearch() error = %v", err)
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

func TestRunAskRendersAnswerAndSources(t *testing.T) {
	canned := client.AnswerResponse{
		Answer: "Finality is reached after two rounds of voting.",
		Citations: []client.Citation{
			{Source: "ledger-spec", Path: "docs/ledger.md", Section: "Consensus"},
		},
		UsedWeb: true,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/answer" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(canned)
	}))
	defer srv.Close()

	t.Setenv("BLKCHAIN_API_URL", srv.URL)

	out := captureStdout(t, func() {
		if err := runAsk([]string{"how", "does", "consensus", "work"}); err != nil {
			t.Fatalf("runAsk() error = %v", err)
		}
	})

	if !strings.Contains(out, "Finality is reached after two rounds of voting.") {
		t.Errorf("output missing answer, got:\n%s", out)
	}
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

func TestRunHealthUnreachable(t *testing.T) {
	t.Setenv("BLKCHAIN_API_URL", "http://127.0.0.1:1")

	err := runHealth(nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not reachable") {
		t.Errorf("error = %v, want message containing 'not reachable'", err)
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

func TestSearchAcceptsTrailingFlags(t *testing.T) {
	var gotTopK int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req client.SearchRequest
		json.NewDecoder(r.Body).Decode(&req)
		gotTopK = req.TopK
		json.NewEncoder(w).Encode(client.SearchResponse{})
	}))
	defer srv.Close()
	t.Setenv("BLKCHAIN_API_URL", srv.URL)

	captureStdout(t, func() {
		if err := runSearch([]string{"consensus", "work", "--top-k", "7"}); err != nil {
			t.Fatalf("runSearch() error = %v", err)
		}
	})
	if gotTopK != 7 {
		t.Errorf("top_k = %d, want 7 (flag after query was not parsed)", gotTopK)
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
