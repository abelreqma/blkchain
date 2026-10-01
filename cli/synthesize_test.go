package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"blkchain/cli/internal/retrieval"
)

// SynthesizeFromResults is the /generate entry: synthesize a grounded, cited
// answer from caller-supplied results without retrieving or grading. Its
// signature takes no searcher, so it cannot retrieve by construction; these
// tests pin the rest of the contract.

func TestSynthesizeFromResultsAnswersAndCites(t *testing.T) {
	srv := fakeLLM(t, nil, "reflected XSS reflects user input [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "")

	results := []retrieval.Result{chunk("wstg", "xss.md", "reflected", "text about reflected xss")}
	var streamed []byte
	answer, cits, _, err := SynthesizeFromResults(context.Background(), answerCfg(2), "what is reflected xss", results, AnswerOpts{
		Stream: func(b []byte) { streamed = append(streamed, b...) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if answer != "reflected XSS reflects user input [1]" {
		t.Fatalf("answer = %q", answer)
	}
	if len(cits) != 1 || cits[0].Source != "wstg" || cits[0].Path != "xss.md" {
		t.Fatalf("cits = %+v, want one wstg/xss.md citation", cits)
	}
	if string(streamed) != answer {
		t.Fatalf("streamed = %q, want %q", streamed, answer)
	}
}

// Parity: over the same results and the same LLM output, SynthesizeFromResults
// yields the same citations (and untrusted tags) as AnswerLoop's synthesis tail.
func TestSynthesizeFromResultsMatchesAnswerLoopCitations(t *testing.T) {
	stream := "web says X [1]; corpus says Y [2]"
	results := []retrieval.Result{
		chunk("web", "https://example.com/a", "", "web text"),
		chunk("wstg", "b.md", "s", "corpus text"),
	}

	// AnswerLoop path: grade "sufficient" so it synthesizes once over `results`.
	srv1 := fakeLLM(t, []string{`{"sufficient":true,"rewrite":"","use_web":false}`}, stream)
	t.Setenv("OMLX_BASE_URL", srv1.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "")
	_, loopCits, _, _, _, err := AnswerLoop(context.Background(), fakeSearcher{results}, answerCfg(1), "q", AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}

	srv2 := fakeLLM(t, nil, stream)
	t.Setenv("OMLX_BASE_URL", srv2.URL)
	_, synthCits, _, err := SynthesizeFromResults(context.Background(), answerCfg(1), "q", results, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(loopCits, synthCits) {
		t.Fatalf("citations differ:\n AnswerLoop = %+v\n Synthesize = %+v", loopCits, synthCits)
	}
	// Sanity: the web citation is tagged untrusted, the corpus one is not.
	if len(synthCits) != 2 || !synthCits[0].Untrusted || synthCits[1].Untrusted {
		t.Fatalf("untrusted tags wrong: %+v", synthCits)
	}
}

// SynthesizeFromResults must never grade: a grade call is non-streaming, the
// synthesis is streaming, so exactly one streaming call and zero grade calls.
// It also carries the answer (not grade) token cap.
func TestSynthesizeFromResultsDoesNotGrade(t *testing.T) {
	srv, seen := recordingLLM(t)
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "")

	cfg := answerCfg(2)
	cfg.AnswerMaxTokens = 321
	results := []retrieval.Result{chunk("wstg", "a.md", "s", "text")}
	if _, _, _, err := SynthesizeFromResults(context.Background(), cfg, "q", results, AnswerOpts{}); err != nil {
		t.Fatal(err)
	}
	reqs := seen()
	if len(reqs) != 1 {
		t.Fatalf("made %d LLM calls, want exactly 1 (synthesis, no grade): %+v", len(reqs), reqs)
	}
	if !reqs[0].stream {
		t.Fatalf("the single call was non-stream (a grade); want the streaming synthesis")
	}
	if reqs[0].maxTokens != 321 {
		t.Errorf("synthesis max tokens = %d, want AnswerMaxTokens 321", reqs[0].maxTokens)
	}
}

// oMLX streams a keepalive first chunk (empty content) before real tokens, and
// a reasoning-only delta also arrives with empty content. The synthesis stream
// closure must drop empty chunks so a consumer (the live tokens/sec bar) does
// not record a false first token. Shared by /ask and /generate via synthesize.
func TestSynthesizeSkipsEmptyStreamChunks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"\"}}]}\n\n"+
			"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"real answer [1]\"}}]}\n\n"+
			"data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")

	results := []retrieval.Result{chunk("wstg", "a.md", "s", "text")}
	var forwarded [][]byte
	answer, _, _, err := SynthesizeFromResults(context.Background(), answerCfg(1), "q", results, AnswerOpts{
		Stream: func(b []byte) { forwarded = append(forwarded, append([]byte(nil), b...)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range forwarded {
		if len(c) == 0 {
			t.Fatalf("empty chunk forwarded to Stream at index %d (keepalive not skipped): %q", i, forwarded)
		}
	}
	if answer != "real answer [1]" {
		t.Fatalf("answer = %q, want %q", answer, "real answer [1]")
	}
}
