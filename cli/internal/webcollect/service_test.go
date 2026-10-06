package webcollect

import (
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/webacquire"
	"blkchain/cli/internal/webanalysis"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func fixtureStore(t *testing.T) *engagement.Store {
	t.Helper()
	s, e := engagement.Open(filepath.Join(t.TempDir(), "engagement.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func fixtureBroker(server *httptest.Server) *webacquire.Broker {
	return &webacquire.Broker{Policy: webacquire.Policy{IPAllowed: func(_ string, ip net.IP) bool { return ip.IsLoopback() }, Authorize: func(ctx context.Context, r webacquire.Request) error {
		if !strings.HasPrefix(r.URL, server.URL+"/") {
			return fmt.Errorf("outside fixture")
		}
		return nil
	}}}
}

func TestRoEArtifactBodyCapBeforeStorage(t *testing.T) {
	store := fixtureStore(t)
	svc := New(store, &webacquire.Broker{Policy: webacquire.Policy{MaxBodyBytes: 8}}, nil)
	_, err := svc.Accept(context.Background(), webanalysis.Artifact{Kind: "html", URL: "http://example.test/"}, []byte("123456789"), 0)
	if !errors.Is(err, webacquire.ErrLimit) {
		t.Fatalf("oversized artifact accepted: %v", err)
	}
	svc.AccountArtifactBytes = func(int) error { return webacquire.ErrLimit }
	_, err = svc.Accept(context.Background(), webanalysis.Artifact{Kind: "html", URL: "http://example.test/"}, []byte("12345678"), 0)
	if !errors.Is(err, webacquire.ErrLimit) {
		t.Fatalf("aggregate artifact cap accepted input: %v", err)
	}
	snapshot, err := store.WebSnapshot(context.Background())
	if err != nil || len(snapshot.Artifacts) != 0 {
		t.Fatalf("oversized artifact persisted: %+v %v", snapshot.Artifacts, err)
	}
}
func TestCompleteFixtureManifest(t *testing.T) {
	routes := map[string]string{
		"/":                "<base href='/app/'><script type='module' src='main.js'></script><script>fetch('/api/inline')</script><script type='application/json'>{\"state\":true}</script><button onclick=\"fetch('/api/event')\">Go</button><link rel='modulepreload' href='lazy.js'><iframe src='/frame'></iframe><a href='/profile'>Profile</a>",
		"/app/main.js":     "import './dep.js'; import('./lazy.js'); import(dynamicName); fetch('/api/main'); //# sourceMappingURL=main.js.map",
		"/app/dep.js":      "fetch('/api/dependency');import('./main.js')",
		"/app/lazy.js":     "fetch('/api/billing');const a=['/api/profile'];fetch(a[0]);",
		"/app/main.js.map": `{"version":3,"sources":["webpack:///../../src/recovered.ts"],"sourcesContent":["function report(id: string){return fetch('/api/reporting/'+id)}"],"mappings":"AAAA"}`,
		"/frame":           "<script src='/frame-code'></script>",
		"/frame-code":      "fetch('/api/frame')",
		"/profile":         "<script>fetch('/api/user')</script>",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/frame-code" || strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		} else if strings.HasSuffix(r.URL.Path, ".map") {
			w.Header().Set("Content-Type", "application/json")
		} else {
			w.Header().Set("Content-Type", "text/html")
		}
		fmt.Fprint(w, body)
	}))
	defer server.Close()
	store := fixtureStore(t)
	svc := New(store, fixtureBroker(server), nil)
	svc.DiscoveryAllowed = func(u string) bool { return strings.HasPrefix(u, server.URL+"/") }
	c, e := svc.Collect(context.Background(), []string{server.URL + "/"}, Options{Role: "reader", MaxDepth: 8})
	if e != nil {
		t.Fatal(e)
	}
	snap, e := store.WebSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	paths := []string{}
	for _, o := range snap.Operations {
		paths = append(paths, o.Path)
	}
	sort.Strings(paths)
	expected := []string{"/api/billing", "/api/dependency", "/api/event", "/api/frame", "/api/inline", "/api/main", "/api/profile", "/api/reporting/{id}", "/api/user"}
	sort.Strings(expected)
	if fmt.Sprint(paths) != fmt.Sprint(expected) {
		t.Fatalf("complete operation manifest:\n got %v\nwant %v", paths, expected)
	}
	if len(c.Routes) != 3 {
		t.Fatalf("routes %v", c.Routes)
	}
	counts := map[string]int{}
	for _, a := range snap.Artifacts {
		counts[a.Kind]++
		if a.Complete {
			b, e := store.WebBlob(a.Hash)
			if e != nil || webanalysis.Hash(b) != a.Hash {
				t.Fatal("exact artifact lost")
			}
		}
	}
	for _, k := range []string{"inline-script", "data-script", "event-handler", "original-source", "script", "sourcemap"} {
		if counts[k] == 0 {
			t.Fatalf("missing %s: %v", k, counts)
		}
	}
	mapped := false
	for _, u := range snap.Units {
		if len(u.Mappings) > 0 {
			mapped = true
			if u.Mappings[0].OriginalLine != 1 {
				t.Fatal(u.Mappings)
			}
		}
	}
	if !mapped {
		t.Fatal("locations not retained")
	}
	if e := svc.AnalyzeStored(context.Background()); e != nil {
		t.Fatal(e)
	}
	after, e := store.WebSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	for _, unit := range snap.Units {
		if len(unit.Mappings) == 0 {
			continue
		}
		retained := false
		for _, u := range after.Units {
			if u.ID == unit.ID && len(u.Mappings) == len(unit.Mappings) {
				retained = true
			}
		}
		if !retained {
			t.Fatal("reanalyzing discarded source map provenance")
		}
	}
	unresolved := false
	for _, g := range c.Gaps {
		if strings.Contains(g.Reason, "unresolved") {
			unresolved = true
		}
	}
	if !unresolved {
		t.Fatal("unresolved import silently dropped")
	}
}
func TestHTMLTypesAndOffsets(t *testing.T) {
	b := []byte(`<script>fetch('/a')</script><script type="application/json">{"a":1}</script><script type="importmap">{"imports":{"x":"./x.js"}}</script><i onclick="fetch('/b')"></i>`)
	p := parseHTML(b, "https://fixture.test/page")
	if len(p.Inline) != 4 {
		t.Fatalf("%+v", p.Inline)
	}
	if p.Inline[0].Offset != 8 || string(p.Inline[0].Body) != "fetch('/a')" {
		t.Fatal(p.Inline[0])
	}
	if len(p.Refs) != 1 || p.Refs[0].URL != "https://fixture.test/x.js" {
		t.Fatal(p.Refs)
	}
}
func TestMapsRejectTraversalAndExpansion(t *testing.T) {
	s := New(fixtureStore(t), nil, nil)
	s.DiscoveryAllowed = func(string) bool { return false }
	a := webanalysis.Artifact{Kind: "sourcemap", URL: "https://fixture.test/a.map", FinalURL: "https://fixture.test/a.map", Complete: true}
	for _, body := range []string{`{"version":2}`, `{"version":3,"sources":["file:///etc/passwd"],"mappings":"ACAA"}`, `{"version":3,"sources":[],"sections":[{"offset":{"line":-1,"column":0},"map":{"version":3}}]}`} {
		if s.sourceMap(context.Background(), a, []byte(body), 0) == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	body := `{"version":3,"sources":["file:///etc/passwd"],"mappings":"AAAA"}`
	if e := s.sourceMap(context.Background(), a, []byte(body), 0); e != nil {
		t.Fatal(e)
	}
	if len(s.pending) != 0 || len(s.coverage.Gaps) != 1 {
		t.Fatal("local-file fetch queued")
	}
	if _, e := vlq(strings.Repeat("/", 20)); e == nil {
		t.Fatal("VLQ overflow")
	}
}
func TestImportHARBodiesAndScope(t *testing.T) {
	s := New(fixtureStore(t), nil, nil)
	s.DiscoveryAllowed = func(u string) bool { return strings.HasPrefix(u, "https://fixture.test/") }
	body := `{"log":{"entries":[{"request":{"url":"https://fixture.test/api/admin","method":"GET","headers":[{"name":"Cookie","value":"session=private-value"}]},"response":{"status":403,"content":{"size":5}}},{"_resourceType":"script","request":{"url":"https://fixture.test/code","method":"GET"},"response":{"status":200,"content":{"mimeType":"application/javascript","text":"ZmV0Y2goJy9hcGkvaW1wb3J0ZWQnKQ==","encoding":"base64","size":22}}},{"request":{"url":"https://outside.test/","method":"GET"},"response":{"status":200,"content":{"size":0}}}]}}`
	if e := s.ImportHAR(context.Background(), strings.NewReader(body), "admin"); e != nil {
		t.Fatal(e)
	}
	snap, e := s.Store.WebSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, o := range snap.Operations {
		if o.Path == "/api/admin" {
			found = true
			if o.Validation != "access-response" {
				t.Fatal(o.Validation)
			}
		}
	}
	if !found {
		t.Fatal("403 lost")
	}
	redacted, _ := json.Marshal(webanalysis.Redacted(snap))
	if bytes.Contains(redacted, []byte("private-value")) {
		t.Fatal("credential leaked")
	}
	if len(snap.Coverage) == 0 || len(snap.Coverage[0].Gaps) < 2 {
		t.Fatal("missing coverage gaps")
	}
}
func TestArchiveVersionsAndInfrastructureBoundary(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/cdx/") {
			fmt.Fprint(w, `[["timestamp","original","statuscode","mimetype","digest"],["20200101000000","https://fixture.test/app.js","200","application/javascript","old"],["20250101000000","https://fixture.test/app.js","200","application/javascript","new"]]`)
			return
		}
		if strings.Contains(r.URL.Path, "20200101000000id_") {
			fmt.Fprint(w, "fetch('/api/old')")
			return
		}
		if strings.Contains(r.URL.Path, "20250101000000id_") {
			fmt.Fprint(w, "fetch('/api/new')")
			return
		}
		http.Redirect(w, r, "https://fixture.test/live", 302)
	}))
	defer server.Close()
	allowed := func(u string) bool { return strings.HasPrefix(u, "https://fixture.test/") }
	a := &Archive{Base: server.URL, Broker: fixtureBroker(server), Allowed: allowed}
	s := New(fixtureStore(t), fixtureBroker(server), nil)
	s.DiscoveryAllowed = allowed
	s.Archive = a
	c, e := s.Collect(context.Background(), []string{"https://fixture.test/app.js"}, Options{Historical: true})
	if e != nil {
		t.Fatal(e)
	}
	snap, e := s.Store.WebSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	paths := []string{}
	for _, o := range snap.Operations {
		paths = append(paths, o.Path)
		if o.Validation != "unvalidated" || o.Discoveries[0] != "historical" {
			t.Fatal(o)
		}
	}
	sort.Strings(paths)
	if fmt.Sprint(paths) != "[/api/new /api/old]" {
		t.Fatal(paths, c.Gaps)
	}
	hashes := map[string]bool{}
	for _, a := range snap.Artifacts {
		if a.Kind == "script" && a.Complete {
			hashes[a.Hash] = true
			if a.CapturedAt == "" || a.RetrievedAt == "" {
				t.Fatal("capture dates missing")
			}
		}
	}
	if len(hashes) != 2 {
		t.Fatal("versions collapsed")
	}
	if _, e = a.Fetch(context.Background(), Capture{Timestamp: "20210101000000", Original: "https://fixture.test/redirect.js"}); e == nil {
		t.Fatal("archive followed live redirect")
	}
	for _, u := range []string{"http://127.0.0.1/a.js", "https://fixture.test/a?token=private", "file:///etc/passwd"} {
		if a.original(u) == nil {
			t.Fatal("private archive original", u)
		}
	}
}

func TestIndexedSourceMapOffsets(t *testing.T) {
	store := fixtureStore(t)
	svc := New(store, nil, nil)
	body := []byte(`{"version":3,"sections":[{"offset":{"line":3,"column":7},"map":{"version":3,"sources":["webpack:///source.js"],"sourcesContent":["fetch('/api/mapped')"],"mappings":"AAAA;AACA"}}]}`)
	_, e := svc.Accept(context.Background(), webanalysis.Artifact{Kind: "sourcemap", URL: "https://fixture.test/app.js.map", Complete: true}, body, 0)
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := store.WebSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, unit := range snapshot.Units {
		if len(unit.Mappings) > 0 {
			found = true
			if unit.Mappings[0].GeneratedLine != 4 || unit.Mappings[0].GeneratedColumn != 7 || unit.Mappings[1].GeneratedLine != 5 || unit.Mappings[1].GeneratedColumn != 0 {
				t.Fatal(unit.Mappings)
			}
		}
	}
	if !found {
		t.Fatal("indexed mappings missing")
	}
}

func TestRelativeAPICallsUseDocumentBaseAndImportsUseModuleBase(t *testing.T) {
	routes := map[string]string{"/page/index.html": `<base href='/application/'><script src='/bundles/app.js'></script>`, "/bundles/app.js": `fetch('api/profile');import('./dep.js')`, "/bundles/dep.js": `fetch('api/child')`}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		} else {
			w.Header().Set("Content-Type", "text/html")
		}
		fmt.Fprint(w, body)
	}))
	defer server.Close()
	store := fixtureStore(t)
	svc := New(store, fixtureBroker(server), nil)
	svc.DiscoveryAllowed = func(s string) bool { return strings.HasPrefix(s, server.URL) }
	if _, e := svc.Collect(context.Background(), []string{server.URL + "/page/index.html"}, Options{}); e != nil {
		t.Fatal(e)
	}
	snapshot, e := store.WebSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	paths := []string{}
	for _, op := range snapshot.Operations {
		paths = append(paths, op.Path)
	}
	sort.Strings(paths)
	if fmt.Sprint(paths) != fmt.Sprint([]string{"/application/api/child", "/application/api/profile"}) {
		t.Fatal(paths)
	}
}
