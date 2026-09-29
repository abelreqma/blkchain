package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countingListener{Listener: l}
	gs := grpc.NewServer()
	qdrant.RegisterPointsServer(gs, &fakeQdrantPoints{points: []*qdrant.ScoredPoint{
		{Id: qdrant.NewIDNum(1), Score: 0.5, Payload: payload},
	}})
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
		t.Errorf("blk ask --json =\n%s\nwant\n%s", out, want)
	}

	none := captureStdout(t, func() {
		if err := reportNoResults(io.Discard, true); err != nil {
			t.Fatal(err)
		}
	})
	wantNone := "{\n  \"answer\": " + strconv.Quote(noResultsAnswer) + ",\n  \"citations\": [],\n  \"used_web\": false\n}\n"
	if none != wantNone {
		t.Errorf("no-results JSON =\n%s\nwant\n%s", none, wantNone)
	}
}
