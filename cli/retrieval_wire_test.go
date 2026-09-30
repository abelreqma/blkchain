package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/qdrant/go-client/qdrant"
	"google.golang.org/grpc"

	"blkchain/cli/internal/ragconfig"
)

// fakeQdrantService answers the liveness RPC.
type fakeQdrantService struct {
	qdrant.UnimplementedQdrantServer
}

func (fakeQdrantService) HealthCheck(context.Context, *qdrant.HealthCheckRequest) (*qdrant.HealthCheckReply, error) {
	return &qdrant.HealthCheckReply{Title: "qdrant"}, nil
}

// fakeQdrantPoints answers Query with fixed points.
type fakeQdrantPoints struct {
	qdrant.UnimplementedPointsServer
	points []*qdrant.ScoredPoint
}

func (f *fakeQdrantPoints) Query(context.Context, *qdrant.QueryPoints) (*qdrant.QueryResponse, error) {
	return &qdrant.QueryResponse{Result: f.points}, nil
}

// countingListener counts the connections it accepts.
type countingListener struct {
	net.Listener
	n atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

// useFakeRetrieval points loadConfig at a loopback fake Qdrant (gRPC) and a
// fake embed_server, and returns a count of Qdrant connections.
func useFakeRetrieval(t *testing.T, payload map[string]*qdrant.Value) *atomic.Int32 {
	t.Helper()
	return useFakeRetrievalPoints(t, payload)
}

// useFakeRetrievalPoints is useFakeRetrieval with one fake point per payload,
// ranked in the order given.
func useFakeRetrievalPoints(t *testing.T, payloads ...map[string]*qdrant.Value) *atomic.Int32 {
	t.Helper()
	points := make([]*qdrant.ScoredPoint, len(payloads))
	for i, pl := range payloads {
		points[i] = &qdrant.ScoredPoint{Id: qdrant.NewIDNum(uint64(i + 1)), Score: 0.5, Payload: pl}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countingListener{Listener: l}
	gs := grpc.NewServer()
	qdrant.RegisterPointsServer(gs, &fakeQdrantPoints{points: points})
	qdrant.RegisterQdrantServer(gs, fakeQdrantService{})
	go gs.Serve(cl)
	t.Cleanup(gs.Stop)

	embed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/embed":
			w.Write([]byte(`{"embeddings":[[0.1,0.2]],"dim":2}`))
		case "/rerank":
			var req struct{ Documents []string }
			json.NewDecoder(r.Body).Decode(&req)
			scores := make([]float64, len(req.Documents))
			json.NewEncoder(w).Encode(map[string]any{"scores": scores})
		}
	}))
	t.Cleanup(embed.Close)

	prev := loadConfig
	loadConfig = func() ragconfig.Config {
		cfg := prev()
		cfg.QdrantGRPCURL = cl.Addr().String()
		cfg.EmbedServerURL = embed.URL
		return cfg
	}
	t.Cleanup(func() { loadConfig = prev })
	return &cl.n
}

// TestNewRetrievalClientHonorsCollectionEnv verifies newRetrievalClient reads
// BLKCHAIN_COLLECTION: the Go retrieval client must target whatever collection
// the environment names.
func TestNewRetrievalClientHonorsCollectionEnv(t *testing.T) {
	t.Setenv("BLKCHAIN_COLLECTION", "blkchain_dwq")
	c, err := newRetrievalClient(loadConfig())
	if err != nil || c == nil {
		t.Fatalf("newRetrievalClient: %v", err)
	}
	c.Close()
}

// A TUI session keeps one retrieval client: search after search reuses one
// Qdrant connection instead of dialing a new pool per query.
func TestTUISearchesReuseOneQdrantConnection(t *testing.T) {
	isolateUserDirs(t)
	conns := useFakeRetrieval(t, map[string]*qdrant.Value{"text": qdrant.NewValueString("t"), "source": qdrant.NewValueString("wstg")})
	m := newKeyModel(t)
	for i := 0; i < 5; i++ {
		nm, cmd := m.dispatchInput("/search ssrf")
		var got bool
		for _, msg := range drain(cmd) {
			if sm, ok := msg.(searchMsg); ok && len(sm.results) == 1 {
				got = true
			}
			if em, ok := msg.(errMsg); ok {
				t.Fatalf("search %d: %v", i, em.err)
			}
		}
		if !got {
			t.Fatalf("search %d returned no results", i)
		}
		nm.(model).cancel()
	}
	if n := conns.Load(); n != 1 {
		t.Errorf("5 searches opened %d Qdrant connections, want 1", n)
	}
}

// Every Go retrieval path builds its client here, so the saved reranker switch
// reaches search, ask, both REPLs, and blk mcp.
func TestNewRetrievalClientFollowsTheRerankerSwitch(t *testing.T) {
	isolateUserDirs(t)
	c, err := newRetrievalClient(loadConfig())
	if err != nil || c.SkipRerank {
		t.Fatalf("default: SkipRerank=%v err=%v, want the reranker on", c != nil && c.SkipRerank, err)
	}
	if err := savePrefs(modelPrefs{Rerank: false, Web: true}); err != nil {
		t.Fatal(err)
	}
	if c, _ := newRetrievalClient(loadConfig()); !c.SkipRerank {
		t.Error("reranker off in the saved settings, but the client still reranks")
	}
	// followPrefs copies: the shared client a long-running server keeps is not changed.
	base, _ := newRetrievalClient(loadConfig())
	on := followPrefs(base, modelPrefs{Rerank: true})
	if on.SkipRerank || !base.SkipRerank {
		t.Errorf("followPrefs: copy SkipRerank=%v, original=%v", on.SkipRerank, base.SkipRerank)
	}
}

// blk search --json carries each payload's cwe_class, as an empty string when
// the point has none; the eval harness reads it.
func TestSearchJSONCarriesCWEClass(t *testing.T) {
	isolateUserDirs(t)
	for _, c := range []struct {
		payload map[string]*qdrant.Value
		want    string
	}{
		{map[string]*qdrant.Value{"text": qdrant.NewValueString("t"), "cwe_class": qdrant.NewValueString("sqli")}, "sqli"},
		{map[string]*qdrant.Value{"text": qdrant.NewValueString("t")}, ""},
	} {
		useFakeRetrieval(t, c.payload)
		out := captureStdout(t, func() {
			if err := runSearch([]string{"--json", "q"}); err != nil {
				t.Fatal(err)
			}
		})
		var got struct {
			Results []struct {
				Payload map[string]any `json:"payload"`
			} `json:"results"`
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil || len(got.Results) != 1 {
			t.Fatalf("output %q: %v", out, err)
		}
		v, ok := got.Results[0].Payload["cwe_class"]
		if !ok || v != c.want {
			t.Errorf("cwe_class = %v (present %v), want %q", v, ok, c.want)
		}
	}
}

// goldenPayload is one fake point with every payload field set.
func goldenPayload() map[string]*qdrant.Value {
	return map[string]*qdrant.Value{
		"source": qdrant.NewValueString("wstg"), "path": qdrant.NewValueString("a.md"),
		"section": qdrant.NewValueString("intro"), "type": qdrant.NewValueString("doc"),
		"text": qdrant.NewValueString("body"), "cwe_class": qdrant.NewValueString("ssrf"),
	}
}

// The exact JSON blk search --json prints: field names, order, and shape.
func TestSearchJSONGolden(t *testing.T) {
	isolateUserDirs(t)
	useFakeRetrieval(t, goldenPayload())
	out := captureStdout(t, func() {
		if err := runSearch([]string{"--json", "q"}); err != nil {
			t.Fatal(err)
		}
	})
	const want = `{
  "results": [
    {
      "id": "1",
      "score": 0,
      "payload": {
        "source": "wstg",
        "path": "a.md",
        "section": "intro",
        "type": "doc",
        "text": "body",
        "cwe_class": "ssrf"
      }
    }
  ]
}
`
	if out != want {
		t.Errorf("blk search --json =\n%s\nwant\n%s", out, want)
	}
}

// The exact JSON blk ask --json prints, and its no-results form.
func TestAskJSONGolden(t *testing.T) {
	isolateUserDirs(t)
	useFakeRetrieval(t, goldenPayload())
	srv, _ := recordingLLM(t)
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "m")
	t.Setenv("OMLX_API_KEY", "")
	t.Setenv("TAVILY_SETUP_TOKEN", "")
	out := captureStdout(t, func() {
		if err := runAsk([]string{"--json", "q"}); err != nil {
			t.Fatal(err)
		}
	})
	const want = `{
  "answer": "ok [1]",
  "citations": [
    {
      "source": "wstg",
      "path": "a.md",
      "section": "intro"
    }
  ],
  "used_web": false,
  "model": "m",
  "results": [
    {
      "id": "1",
      "score": 0,
      "payload": {
        "source": "wstg",
        "path": "a.md",
        "section": "intro",
        "type": "doc",
        "text": "body",
        "cwe_class": "ssrf"
      }
    }
  ],
  "route": "rag"
}
`
	if out != want {
		t.Errorf("blk ask --json =\n%s\nwant\n%s", out, want)
	}

	none := captureStdout(t, func() {
		if err := reportNoResults(io.Discard, true, "m"); err != nil {
			t.Fatal(err)
		}
	})
	wantNone := "{\n  \"answer\": " + strconv.Quote(noResultsAnswer) + ",\n  \"citations\": [],\n  \"used_web\": false,\n  \"model\": \"m\"\n}\n"
	if none != wantNone {
		t.Errorf("no-results JSON =\n%s\nwant\n%s", none, wantNone)
	}
}

// citedLLM answers every call: a sufficient grade, then a streamed answer that
// cites sources 1 and 2.
func citedLLM(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Stream bool `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"see [1] and [2]\"}}]}\n\ndata: [DONE]\n\n")
			return
		}
		io.WriteString(w, `{"choices":[{"index":0,"message":{"role":"assistant","content":"{\"sufficient\":true,\"rewrite\":\"\",\"use_web\":false}"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ask --json reports the model blk requested and marks only the web citation
// untrusted. The existing fields keep their names and values.
func TestAskJSONReportsModelAndUntrustedWebCitation(t *testing.T) {
	isolateUserDirs(t)
	web := map[string]*qdrant.Value{
		"source": qdrant.NewValueString(webSource), "path": qdrant.NewValueString("https://example.test/x"),
		"section": qdrant.NewValueString("Page"), "type": qdrant.NewValueString("web"),
		"text": qdrant.NewValueString("web body"),
	}
	useFakeRetrievalPoints(t, goldenPayload(), web)
	t.Setenv("OMLX_BASE_URL", citedLLM(t).URL)
	t.Setenv("OMLX_MODEL", "test-model")
	t.Setenv("OMLX_API_KEY", "")
	t.Setenv("TAVILY_SETUP_TOKEN", "")
	out := captureStdout(t, func() {
		if err := runAsk([]string{"--json", "q"}); err != nil {
			t.Fatal(err)
		}
	})

	var raw struct {
		Answer    string           `json:"answer"`
		Citations []map[string]any `json:"citations"`
		UsedWeb   bool             `json:"used_web"`
		Model     string           `json:"model"`
		Results   []any            `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if raw.Model != "test-model" {
		t.Errorf("model = %q, want test-model", raw.Model)
	}
	if raw.Answer != "see [1] and [2]" || raw.UsedWeb || len(raw.Results) != 2 {
		t.Errorf("existing fields changed: %+v", raw)
	}
	if len(raw.Citations) != 2 {
		t.Fatalf("citations = %v, want 2", raw.Citations)
	}
	local, webCit := raw.Citations[0], raw.Citations[1]
	if local["source"] != "wstg" || local["path"] != "a.md" || local["section"] != "intro" {
		t.Errorf("local citation fields changed: %v", local)
	}
	if _, present := local["untrusted"]; present {
		t.Errorf("local citation carries untrusted: %v", local)
	}
	if webCit["source"] != webSource || webCit["untrusted"] != true {
		t.Errorf("web citation = %v, want untrusted true", webCit)
	}
}

// The new fields survive a marshal and unmarshal round trip, and a local
// citation omits untrusted.
func TestAnswerResponseNewFieldsRoundTrip(t *testing.T) {
	in := answerResponse{
		Answer: "a", Model: "m1",
		Citations: []citation{{Source: "kb", Path: "p"}, {Source: webSource, Path: "u", Untrusted: true}},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out answerResponse
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Model != "m1" || out.Citations[0].Untrusted || !out.Citations[1].Untrusted {
		t.Errorf("round trip = %+v", out)
	}
	if strings.Count(string(data), `"untrusted"`) != 1 {
		t.Errorf("untrusted must appear only on the web citation: %s", data)
	}
}
