package main

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/tooldef"
)

// recSearcher records the query and topK it was called with.
type recSearcher struct {
	results []retrieval.Result
	err     error
	query   string
	topK    int
}

func (r *recSearcher) Search(_ context.Context, q string, k int, _ map[string]any) ([]retrieval.Result, error) {
	r.query, r.topK = q, k
	return r.results, r.err
}

func kbTestCfg() ragconfig.Config {
	cfg := ragconfig.Config{}
	cfg.TopK = 5
	return cfg
}

func TestKBToolSearchFormatsResults(t *testing.T) {
	rs := &recSearcher{results: []retrieval.Result{
		chunk("wstg", "ssrf/intro.md", "Overview", "SSRF lets an attacker make the server fetch URLs."),
		chunk("hacktricks", "pentesting-web/ssrf.md", "", "Try 169.254.169.254."),
	}}
	tool := newKBSearchTool(rs, kbTestCfg())
	out, err := tool.Call(context.Background(), `{"query":"ssrf metadata"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"wstg", "ssrf/intro.md", "Overview", "SSRF lets an attacker", "hacktricks", "pentesting-web/ssrf.md"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if rs.query != "ssrf metadata" {
		t.Errorf("query = %q", rs.query)
	}
	if rs.topK != 5 {
		t.Errorf("topK = %d, want config default 5", rs.topK)
	}
}

func TestKBToolSearchRespectsTopK(t *testing.T) {
	rs := &recSearcher{results: []retrieval.Result{chunk("a", "b", "c", "d")}}
	tool := newKBSearchTool(rs, kbTestCfg())
	if _, err := tool.Call(context.Background(), `{"query":"x","top_k":3}`); err != nil {
		t.Fatal(err)
	}
	if rs.topK != 3 {
		t.Errorf("topK = %d, want 3", rs.topK)
	}
}

func TestKBToolSearchTrimsLongSnippet(t *testing.T) {
	long := strings.Repeat("word ", 500)
	rs := &recSearcher{results: []retrieval.Result{chunk("a", "b", "c", long)}}
	out, err := newKBSearchTool(rs, kbTestCfg()).Call(context.Background(), `{"query":"x"}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > 1000 {
		t.Errorf("output not trimmed, len %d", len(out))
	}
}

func TestKBToolSearchMalformedArgs(t *testing.T) {
	tool := newKBSearchTool(&recSearcher{}, kbTestCfg())
	out, err := tool.Call(context.Background(), `{not json`)
	if err != nil {
		t.Fatalf("want tool-error string, got Go error: %v", err)
	}
	if !strings.HasPrefix(out, "kb_search: invalid arguments:") {
		t.Errorf("out = %q", out)
	}
}

func TestKBToolSearchEmptyQuery(t *testing.T) {
	rs := &recSearcher{}
	out, err := newKBSearchTool(rs, kbTestCfg()).Call(context.Background(), `{"query":"  "}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "kb_search: invalid arguments:") {
		t.Errorf("out = %q", out)
	}
	if rs.query != "" {
		t.Error("searcher must not be called for an empty query")
	}
}

func TestKBToolSearchNoResults(t *testing.T) {
	out, err := newKBSearchTool(&recSearcher{}, kbTestCfg()).Call(context.Background(), `{"query":"zzz"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(out), "no results") {
		t.Errorf("out = %q", out)
	}
}

func TestKBToolSearchSearcherError(t *testing.T) {
	rs := &recSearcher{err: errors.New("qdrant down")}
	out, err := newKBSearchTool(rs, kbTestCfg()).Call(context.Background(), `{"query":"x"}`)
	if err != nil {
		t.Fatalf("want tool-error string, got Go error: %v", err)
	}
	if !strings.HasPrefix(out, "kb_search: ") || !strings.Contains(out, "qdrant down") {
		t.Errorf("out = %q", out)
	}
}

func TestKBToolAnswerReturnsAnswerAndCitations(t *testing.T) {
	old := kbAnswerFn
	defer func() { kbAnswerFn = old }()
	var gotQ string
	kbAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, q string, _ AnswerOpts) (string, []citation, bool, []retrieval.Result, int, error) {
		gotQ = q
		return "SSRF is server-side request forgery.", []citation{{Source: "wstg", Path: "ssrf.md", Section: "Intro"}}, false, nil, 10, nil
	}
	out, err := newKBAnswerTool(&recSearcher{}, kbTestCfg(), false).Call(context.Background(), `{"question":"what is ssrf"}`)
	if err != nil {
		t.Fatal(err)
	}
	if gotQ != "what is ssrf" {
		t.Errorf("question = %q", gotQ)
	}
	for _, want := range []string{"SSRF is server-side request forgery.", "wstg", "ssrf.md", "Intro"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestKBToolAnswerMalformedArgs(t *testing.T) {
	old := kbAnswerFn
	defer func() { kbAnswerFn = old }()
	kbAnswerFn = func(context.Context, searcher, ragconfig.Config, string, AnswerOpts) (string, []citation, bool, []retrieval.Result, int, error) {
		t.Error("answer loop must not run on malformed args")
		return "", nil, false, nil, 0, nil
	}
	out, err := newKBAnswerTool(&recSearcher{}, kbTestCfg(), false).Call(context.Background(), `nope`)
	if err != nil {
		t.Fatalf("want tool-error string, got Go error: %v", err)
	}
	if !strings.HasPrefix(out, "kb_answer: invalid arguments:") {
		t.Errorf("out = %q", out)
	}
}

func TestKBToolAnswerLoopError(t *testing.T) {
	old := kbAnswerFn
	defer func() { kbAnswerFn = old }()
	kbAnswerFn = func(context.Context, searcher, ragconfig.Config, string, AnswerOpts) (string, []citation, bool, []retrieval.Result, int, error) {
		return "", nil, false, nil, 0, errors.New("llm down")
	}
	out, err := newKBAnswerTool(&recSearcher{}, kbTestCfg(), false).Call(context.Background(), `{"question":"q"}`)
	if err != nil {
		t.Fatalf("want tool-error string, got Go error: %v", err)
	}
	if !strings.HasPrefix(out, "kb_answer: ") || !strings.Contains(out, "llm down") {
		t.Errorf("out = %q", out)
	}
}

func TestKBToolSchemas(t *testing.T) {
	cases := []struct {
		tool     tooldef.Tool
		name     string
		props    []string
		required []string
	}{
		{newKBSearchTool(&recSearcher{}, kbTestCfg()), "kb_search", []string{"query", "top_k"}, []string{"query"}},
		{newKBAnswerTool(&recSearcher{}, kbTestCfg(), false), "kb_answer", []string{"question"}, []string{"question"}},
	}
	for _, c := range cases {
		if c.tool.Name() != c.name {
			t.Errorf("name = %q, want %q", c.tool.Name(), c.name)
		}
		if c.tool.Description() == "" {
			t.Errorf("%s: empty description", c.name)
		}
		s := c.tool.Schema()
		props, _ := s["properties"].(map[string]any)
		var got []string
		for k := range props {
			got = append(got, k)
		}
		sort.Strings(got)
		if !reflect.DeepEqual(got, c.props) {
			t.Errorf("%s props = %v, want %v", c.name, got, c.props)
		}
		req, _ := s["required"].([]string)
		if !reflect.DeepEqual(req, c.required) {
			t.Errorf("%s required = %v, want %v", c.name, req, c.required)
		}
	}
	want, _ := tooldef.SchemaFor(kbSearchArgs{})
	if !reflect.DeepEqual(newKBSearchTool(&recSearcher{}, kbTestCfg()).Schema(), want) {
		t.Error("kb_search schema differs from SchemaFor(kbSearchArgs{})")
	}
}

func TestKBToolSearchClampsTopK(t *testing.T) {
	rs := &recSearcher{results: []retrieval.Result{chunk("a", "b", "c", "d")}}
	if _, err := newKBSearchTool(rs, kbTestCfg()).Call(context.Background(), `{"query":"x","top_k":100000}`); err != nil {
		t.Fatal(err)
	}
	if rs.topK != 20 {
		t.Errorf("topK = %d, want 20", rs.topK)
	}
}

func TestKBToolAnswerNoResultsIsNormalAnswer(t *testing.T) {
	old := kbAnswerFn
	defer func() { kbAnswerFn = old }()
	kbAnswerFn = func(context.Context, searcher, ragconfig.Config, string, AnswerOpts) (string, []citation, bool, []retrieval.Result, int, error) {
		return "", nil, false, nil, 0, ErrNoResults
	}
	out, err := newKBAnswerTool(&recSearcher{}, kbTestCfg(), false).Call(context.Background(), `{"question":"q"}`)
	if err != nil {
		t.Fatal(err)
	}
	if out != noResultsAnswer {
		t.Errorf("out = %q, want noResultsAnswer", out)
	}
	kbAnswerFn = func(context.Context, searcher, ragconfig.Config, string, AnswerOpts) (string, []citation, bool, []retrieval.Result, int, error) {
		return "", nil, false, nil, 0, errors.New("llm down")
	}
	out, _ = newKBAnswerTool(&recSearcher{}, kbTestCfg(), false).Call(context.Background(), `{"question":"q"}`)
	if !strings.HasPrefix(out, "kb_answer: ") {
		t.Errorf("genuine error out = %q", out)
	}
}
