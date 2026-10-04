package main

import (
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/webanalysis"
	"context"
	"encoding/json"
	tea "github.com/charmbracelet/bubbletea"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebTargetInputsPTRAndEngagementScope(t *testing.T) {
	old := webReverseLookup
	webReverseLookup = func(ctx context.Context, ip string) ([]string, error) { return []string{"ptr.fixture.test."}, nil }
	defer func() { webReverseLookup = old }()
	dir := t.TempDir()
	list := filepath.Join(dir, "domains.txt")
	if e := os.WriteFile(list, []byte("fixture.test\n# comment\n192.0.2.1\n"), 0600); e != nil {
		t.Fatal(e)
	}
	targets, e := webResolveTargets(context.Background(), []string{list}, true)
	if e != nil || len(targets.URLs) != 3 {
		t.Fatal(targets, e)
	}
	if targets.Scope != nil {
		t.Fatal("PTR expanded authority")
	}
	doc := filepath.Join(dir, "engagement.md")
	if e = os.WriteFile(doc, []byte("# Engagement\n## Targets\n- fixture.test\n## In Scope\n- fixture.test\n- 192.0.2.1\n## Out of Scope\n- ptr.fixture.test\n## Rate\n10/s\n"), 0600); e != nil {
		t.Fatal(e)
	}
	targets, e = webResolveTargets(context.Background(), []string{doc}, true)
	if e != nil || targets.Scope == nil || targets.Scope.InScope("ptr.fixture.test") || len(targets.URLs) != 1 {
		t.Fatal(targets, e)
	}
	targets, e = webResolveTargets(context.Background(), []string{"2001:db8::1"}, false)
	if e != nil || targets.URLs[0] != "https://[2001:db8::1]" {
		t.Fatal(targets, e)
	}
	if _, e = webResolveTargets(context.Background(), []string{"http://user:pass@fixture.test"}, false); e == nil {
		t.Fatal("accepted credentials")
	}
}
func TestWebSharedInspectAndInteractiveRendering(t *testing.T) {
	dir := t.TempDir()
	ws, e := engagement.OpenWorkspace(dir)
	if e != nil {
		t.Fatal(e)
	}
	o := webanalysis.Operation{ID: webanalysis.ID("op"), Origin: "https://fixture.test", Path: "/api/admin", Method: "GET", Protocol: "http", Validation: "access-response", Discoveries: []string{"historical", "observed"}, Features: []string{"admin"}, Parameters: []webanalysis.Parameter{{Name: "token", Field: "header.Authorization", Expression: "sensitive-value"}}}
	if e = ws.Store.PutWeb(context.Background(), "operation", o.ID, "", o); e != nil {
		t.Fatal(e)
	}
	ws.Close()
	args := []string{"inspect", "fixture.test", "--workspace", dir, "--no-rdns", "--view", "apis"}
	text, e := webExecute(context.Background(), args, secgate.Safe, nil, true, 90)
	if e != nil || !strings.Contains(text, "\U0001f310") || !strings.Contains(text, "API operations") || !strings.Contains(text, "sensitive-value") {
		t.Fatal(text, e)
	}
	args = append(args, "--json")
	out, e := webExecute(context.Background(), args, secgate.Safe, nil, false, 90)
	var snap webanalysis.Snapshot
	if e != nil || json.Unmarshal([]byte(out), &snap) != nil || len(snap.Operations) != 1 {
		t.Fatal(out, e)
	}
	out, e = webExecute(context.Background(), []string{"inspect", "outside.test", "--workspace", dir, "--json", "--no-rdns"}, secgate.Safe, nil, false, 90)
	if e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal([]byte(out), &snap) != nil || len(snap.Operations) != 0 {
		t.Fatal("target filter failed", out)
	}
}
func TestWebArgumentsQuotedPathsAndCancellation(t *testing.T) {
	v, e := webArguments(`inspect "/tmp/list of domains.txt" --workspace '/tmp/engagement one'`)
	if e != nil || len(v) != 4 || v[1] != "/tmp/list of domains.txt" {
		t.Fatal(v, e)
	}
	if _, e = webArguments(`inspect "unfinished`); e == nil {
		t.Fatal("open quote accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = webExecute(ctx, []string{"collect", "--workspace", t.TempDir(), "http://127.0.0.1"}, secgate.Safe, nil, false, 90)
	if e == nil {
		t.Fatal("cancel or missing scope ignored")
	}
}
func TestWebSessionEnvBoundariesAndExportConfinement(t *testing.T) {
	t.Setenv("WEB_TEST_HEADER", "test-value")
	h, e := webRoleHeaders(webSessionRole{HeadersEnv: map[string]string{"Authorization": "WEB_TEST_HEADER"}})
	if e != nil || h.Get("Authorization") != "test-value" {
		t.Fatal(h, e)
	}
	t.Setenv("WEB_TEST_HEADER", "bad\nheader")
	if _, e = webRoleHeaders(webSessionRole{HeadersEnv: map[string]string{"Authorization": "WEB_TEST_HEADER"}}); e == nil {
		t.Fatal("injected session header")
	}
	base := t.TempDir()
	outside := t.TempDir()
	if e = os.Symlink(outside, filepath.Join(base, "exports")); e != nil {
		t.Fatal(e)
	}
	if webExportDir(filepath.Join(base, "exports")) == nil {
		t.Fatal("export followed symlink")
	}
}

func TestWebStructuredReplayEncodingAndBodies(t *testing.T) {
	op := webanalysis.Operation{Origin: "https://fixture.test", Path: "/api/{id}", Query: "q={term}", Method: "POST", Protocol: "http", ContentType: "application/json", Parameters: []webanalysis.Parameter{{Name: "count", Field: "body.count", Type: "number", Expression: "5"}}}
	request, e := webReplayRequest(op, map[string]string{"id": "part/a?b", "term": "one&admin=true"})
	if e != nil || request.URL != "https://fixture.test/api/part%2Fa%3Fb?q=one%26admin%3Dtrue" || request.Body != `{"count":5}` {
		t.Fatal(request, e)
	}
	op.Query = ""
	op.Path = "/graphql"
	op.GraphQL = "query Read($id:ID!){user(id:$id){id}}"
	op.Variables = []string{"id"}
	op.Parameters = nil
	request, e = webReplayRequest(op, map[string]string{"id": "42"})
	var body map[string]any
	if e != nil || json.Unmarshal([]byte(request.Body), &body) != nil || body["query"] != op.GraphQL || body["variables"].(map[string]any)["id"] != float64(42) {
		t.Fatal(request, e)
	}
	op.GraphQL = ""
	op.Variables = nil
	op.ContentType = "application/x-www-form-urlencoded"
	op.Parameters = []webanalysis.Parameter{{Name: "note", Field: "body.note", Type: "string", Unresolved: true}}
	request, e = webReplayRequest(op, map[string]string{"note": "a&b=1"})
	if e != nil || request.Body != "note=a%26b%3D1" {
		t.Fatal(request, e)
	}
	op.Unresolved = []string{"body: unknown spread or computed field"}
	if _, e = webReplayRequest(op, map[string]string{"note": "x"}); e == nil {
		t.Fatal("unknown signature replayed")
	}
}

func TestWebModelPreviewRestrictsSourceAndResponse(t *testing.T) {
	raw := `<script>const password="private-value";fetch('/api/a')</script><input name="password" value="private-value"><button id="login">Sign in</button>`
	out := webModelPreview("browser-dom", raw, nil)
	if strings.Contains(out, "private-value") || strings.Contains(out, "fetch(") || !strings.Contains(out, `id="login"`) {
		t.Fatal(out)
	}
	out = webModelPreview("api-observation", "200\n\ncredential-value", nil)
	if strings.Contains(out, "credential-value") || !strings.Contains(out, "200") {
		t.Fatal(out)
	}
}

func TestWebTUICallsSharedServiceAndCompletes(t *testing.T) {
	dir := t.TempDir()
	workspace, e := engagement.OpenWorkspace(dir)
	if e != nil {
		t.Fatal(e)
	}
	op := webanalysis.Operation{ID: webanalysis.ID("tui-operation"), Origin: "https://fixture.test", Method: "GET", Path: "/api/profile", Protocol: "http", Parameters: []webanalysis.Parameter{{Name: "token", Field: "header.Authorization", Expression: "exact-operation-value"}}}
	if e = workspace.Store.PutWeb(context.Background(), "operation", op.ID, "", op); e != nil {
		t.Fatal(e)
	}
	workspace.Close()
	m := newKeyModel(t)
	updated, cmd := m.dispatchWeb("inspect fixture.test --workspace "+dir+" --view apis --no-rdns", "/web inspect")
	current := updated.(model)
	if !current.working || current.cancel == nil {
		t.Fatal("web job did not start")
	}
	batch, ok := cmd().(tea.BatchMsg)
	if !ok {
		t.Fatal("web job did not dispatch")
	}
	var done webDoneMsg
	found := false
	for _, command := range batch {
		if result, ok := command().(webDoneMsg); ok {
			done = result
			found = true
		}
	}
	if !found || done.Err != nil || !strings.Contains(done.Output, "exact-operation-value") || !strings.Contains(done.Output, "\U0001f310") {
		t.Fatal(done)
	}
	next, _ := current.Update(done)
	if next.(model).working || next.(model).cancel != nil {
		t.Fatal("web job did not complete")
	}
}

func TestWebCoverageFilterPreservesFailuresAndWorkspaceStages(t *testing.T) {
	s := webanalysis.Snapshot{Coverage: []webanalysis.Coverage{
		{ID: "libraries", Stages: []string{"libraries"}, Gaps: []webanalysis.Gap{{Stage: "libraries", Reason: "pinned local snapshot unavailable"}}},
		{ID: "failed-target", Targets: []string{"https://fixture.test"}, Gaps: []webanalysis.Gap{{Stage: "collection", Reason: "navigation failed"}}},
	}}
	filtered := webFilter(s, []string{"https://fixture.test"})
	if len(filtered.Coverage) != 2 {
		t.Fatal("coverage lost", filtered.Coverage)
	}
	outside := webFilter(s, []string{"https://outside.test"})
	if len(outside.Coverage) != 1 || outside.Coverage[0].ID != "libraries" {
		t.Fatal("coverage target filter failed", outside.Coverage)
	}
}

func TestReplayRejectsUnsupportedObservedBodies(t *testing.T) {
	for _, body := range []string{`[1,2]`, `"text"`, `true`, `null`, `{}`, `opaque-text`} {
		op, err := webanalysis.FromObserved(webanalysis.RequestExample{URL: "https://fixture.test/write", Method: "POST", Body: body, Headers: http.Header{"Content-Type": []string{"application/json"}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = webReplayRequest(op, nil); err == nil {
			t.Fatal("unsupported body replayed", body)
		}
		op.Unresolved = nil
		if _, err = webReplayRequest(op, nil); err == nil {
			t.Fatal("older unsupported record replayed", body)
		}
	}
}

func TestReplayPreservesMixedCaseFormBody(t *testing.T) {
	op, err := webanalysis.FromObserved(webanalysis.RequestExample{URL: "https://fixture.test/write", Method: "POST", Body: "a=1", Headers: http.Header{"Content-Type": []string{"APPLICATION/X-WWW-FORM-URLENCODED; charset=UTF-8"}}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := webReplayRequest(op, map[string]string{"a": "1"})
	if err != nil || request.Body != "a=1" {
		t.Fatal(request, err)
	}
}
