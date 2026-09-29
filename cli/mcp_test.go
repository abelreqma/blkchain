package main

import (
	"context"
	"encoding/json"
	"testing"

	"blkchain/cli/internal/retrieval"
)

func TestMCPSearchInputDecodes(t *testing.T) {
	var in mcpSearchIn
	if err := json.Unmarshal([]byte(`{"query":"ssrf","top_k":3}`), &in); err != nil || in.Query != "ssrf" || in.TopK == nil || *in.TopK != 3 {
		t.Fatalf("decode: %+v err=%v", in, err)
	}
}

func TestMCPSearchInputTopKOmitted(t *testing.T) {
	var in mcpSearchIn
	if err := json.Unmarshal([]byte(`{"query":"lfi to rce"}`), &in); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if in.TopK != nil {
		t.Fatalf("expected nil TopK when omitted, got %v", *in.TopK)
	}
}

func TestMCPAnswerInputDecodes(t *testing.T) {
	var in mcpAnswerIn
	if err := json.Unmarshal([]byte(`{"query":"how do I chain this SSRF to RCE?"}`), &in); err != nil || in.Query == "" {
		t.Fatalf("decode: %+v err=%v", in, err)
	}
}

// TestKBAnswerNoResultsIsNormalResult: an empty retrieval is a normal tool
// result whose answer states nothing was found, not an error.
func TestKBAnswerNoResultsIsNormalResult(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":false,"rewrite":"","use_web":false}`}, "unused")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")
	t.Setenv("TAVILY_SETUP_TOKEN", "")

	out, err := kbAnswer(context.Background(), fakeSearcher{}, answerCfg(1), "q", false)
	if err != nil {
		t.Fatalf("no results must not be a tool error, got %v", err)
	}
	if out["answer"] != noResultsAnswer {
		t.Errorf("answer = %v, want the no-results statement", out["answer"])
	}
	if cits, _ := out["citations"].([]citation); len(cits) != 0 {
		t.Errorf("citations = %v, want none", out["citations"])
	}
}

func TestKBAnswerReturnsAnswerAndCitations(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":true}`}, "see [1]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")

	rc := fakeSearcher{[]retrieval.Result{chunk("wstg", "a.md", "s", "text")}}
	out, err := kbAnswer(context.Background(), rc, answerCfg(1), "q", false)
	if err != nil {
		t.Fatal(err)
	}
	if out["answer"] != "see [1]" {
		t.Errorf("answer = %v", out["answer"])
	}
}
