package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/skillcat"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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

// kb_answer serializes the shared citation type, so a web citation carries
// untrusted and a local one omits it.
func TestKBAnswerMarksWebCitationsUntrusted(t *testing.T) {
	srv := fakeLLM(t, []string{`{"sufficient":true}`}, "see [1] and [2]")
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "test-key")

	rc := fakeSearcher{[]retrieval.Result{
		chunk("wstg", "a.md", "s", "text"),
		chunk(webSource, "https://example.test/x", "Page", "web text"),
	}}
	out, err := kbAnswer(context.Background(), rc, answerCfg(1), "q", false)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(out["citations"])
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(data, &got); err != nil || len(got) != 2 {
		t.Fatalf("citations = %s (%v)", data, err)
	}
	if _, present := got[0]["untrusted"]; present || got[1]["untrusted"] != true {
		t.Errorf("citations = %s, want untrusted only on the web one", data)
	}
}

func TestMCPRouteInputDecodes(t *testing.T) {
	var in mcpRouteIn
	if err := json.Unmarshal([]byte(`{"domain":"web"}`), &in); err != nil {
		t.Fatal(err)
	}
	if in.Domain != "web" {
		t.Errorf("domain = %q", in.Domain)
	}
}

// TestMCPRouteResultFoundAndNotFound: route_skill returns the routed skill as a
// structured map, and a clear not-found map (no error) for an empty bucket.
func TestMCPRouteResultFoundAndNotFound(t *testing.T) {
	dir := t.TempDir()
	writeTestSkill(t, dir, "aaa-web", "---\nname: aaa-web\ndescription: web http attacks\n---\nWEBBODY\n")
	cat, err := skillcat.Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	got := mcpRouteResult(cat, "web")
	if got["found"] != true || got["skill"] != "aaa-web" || got["domain"] != "web" {
		t.Fatalf("found result = %v", got)
	}
	if got["description"] != "web http attacks" {
		t.Errorf("description = %v", got["description"])
	}
	if body, _ := got["body"].(string); !strings.Contains(body, "WEBBODY") {
		t.Errorf("body = %q", got["body"])
	}
	if d, _ := got["digest"].(string); d == "" {
		t.Errorf("digest missing: %v", got)
	}
	if got["truncated"] != false {
		t.Errorf("short body should not be truncated: %v", got["truncated"])
	}

	nf := mcpRouteResult(cat, "cloud")
	if nf["found"] != false || nf["domain"] != "cloud" || len(nf) != 2 {
		t.Errorf("not-found result = %v", nf)
	}
}

func TestMCPRouteResultTruncatesBody(t *testing.T) {
	dir := t.TempDir()
	long := strings.Repeat("x", routeSkillBodyCap+500)
	writeTestSkill(t, dir, "aaa-web", "---\nname: aaa-web\ndescription: d\n---\n"+long+"\n")
	cat, err := skillcat.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	res := mcpRouteResult(cat, "web")
	body, _ := res["body"].(string)
	if n := len([]rune(body)); n != routeSkillBodyCap {
		t.Errorf("body runes = %d, want %d", n, routeSkillBodyCap)
	}
	if res["truncated"] != true {
		t.Errorf("cut body should be marked truncated: %v", res["truncated"])
	}
}

// TestMCPServerRoundTrip drives the real newMCPServer registration over an
// in-memory transport: all three tools are listed and route_skill returns the
// routed skill. The kb tools are listed but never called, so no service runs.
func TestMCPServerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	writeTestSkill(t, dir, "aaa-web", "---\nname: aaa-web\ndescription: web http attacks\n---\nWEBBODY\n")
	cat, err := skillcat.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := newMCPServer(&retrieval.Client{}, ragconfig.Config{}, cat)

	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, tl := range tools.Tools {
		have[tl.Name] = true
	}
	for _, want := range []string{"kb_search", "kb_answer", "route_skill"} {
		if !have[want] {
			t.Errorf("tool %q not listed; have %v", want, have)
		}
	}

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "route_skill", Arguments: map[string]any{"domain": "web"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("route_skill returned a tool error: %+v", res.Content)
	}
	got, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structured content = %T %v", res.StructuredContent, res.StructuredContent)
	}
	if got["found"] != true || got["skill"] != "aaa-web" {
		t.Errorf("route_skill result = %v", got)
	}
}
