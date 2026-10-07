package main

import (
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/webacquire"
	"blkchain/cli/internal/webanalysis"
	"context"
	"encoding/json"
	"errors"
	tea "github.com/charmbracelet/bubbletea"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebTranscriptModesThroughDispatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer server.Close()
	roeDir := t.TempDir()
	roePath := filepath.Join(roeDir, "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"off", "full"} {
		t.Run(mode, func(t *testing.T) {
			workspace := t.TempDir()
			out, err := webExecute(context.Background(), []string{"collect", server.URL, "--workspace", workspace, "--roe", roePath, "--transcript", mode, "--no-rdns"}, secgate.Auto, nil, false, 90)
			if err != nil {
				t.Fatal(err)
			}
			_, reportErr := os.Stat(filepath.Join(workspace, "report.json"))
			transcript, transcriptErr := os.ReadFile(filepath.Join(workspace, "actions.jsonl"))
			if reportErr != nil || transcriptErr != nil || !strings.Contains(string(transcript), "web-policy") {
				t.Fatalf("web record missing: report=%v transcript=%v data=%q", reportErr, transcriptErr, transcript)
			}
			if mode == "off" && strings.Contains(out, "a-000001") {
				t.Fatalf("off displayed an action: %q", out)
			}
			if mode == "full" && !strings.Contains(out, "a-000001") {
				t.Fatalf("full hid an action: %q", out)
			}
		})
	}
}

func TestRoEWebBrokerDeniesRedirectHop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://198.51.100.2/denied", http.StatusFound)
	}))
	defer server.Close()
	roe, err := ParseRoE(strings.NewReader("## In Scope\n127.0.0.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	gate := &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, Policy: roe.Policy}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	_, err = newWebBroker(gate, nil).Fetch(context.Background(), webacquire.Request{URL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "out of scope") {
		t.Fatalf("out-of-scope redirect reached the broker: %v", err)
	}
}

func TestRoEWebSocketSendNeedsWriteAction(t *testing.T) {
	roe, err := ParseRoE(strings.NewReader("## In Scope\n127.0.0.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	gate := &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, Policy: roe.Policy}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	request := webacquire.Request{Method: "WEBSOCKET", URL: "http://127.0.0.1/socket"}
	if err := newWebBroker(gate, nil).Policy.Authorize(context.Background(), request); err == nil {
		t.Fatal("WebSocket message bypassed api-write RoE action")
	}
	allowed, err := ParseRoE(strings.NewReader("## In Scope\n127.0.0.1\n## Allowed Actions\napi-read\napi-write\n"))
	if err != nil {
		t.Fatal(err)
	}
	allowedGate := &secgate.Gate{Mode: secgate.Auto, Scope: allowed.Scope, Policy: allowed.Policy}
	if err := allowedGate.Start(); err != nil {
		t.Fatal(err)
	}
	if err := newWebBroker(allowedGate, nil).Policy.Authorize(context.Background(), request); err != nil {
		t.Fatalf("RoE-authorized WebSocket message denied: %v", err)
	}
}

func TestRoEWebByteCapCarriesAcrossBrokers(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("12345678"))
	}))
	defer server.Close()
	roe, err := ParseRoE(strings.NewReader("## In Scope\n127.0.0.1\n## Resource Caps\noutput_bytes: 8\ntotal_bytes: 8\n"))
	if err != nil {
		t.Fatal(err)
	}
	gate := &secgate.Gate{Mode: secgate.Auto, Scope: roe.Scope, Policy: roe.Policy}
	if err := gate.Start(); err != nil {
		t.Fatal(err)
	}
	response, err := newWebBroker(gate, nil).Fetch(context.Background(), webacquire.Request{URL: server.URL})
	if err != nil || string(response.Body) != "12345678" || gate.PolicyByteUsage() != 8 {
		t.Fatalf("first bounded fetch=%q bytes=%d err=%v", response.Body, gate.PolicyByteUsage(), err)
	}
	if _, err := newWebBroker(gate, nil).Fetch(context.Background(), webacquire.Request{URL: server.URL}); err == nil || requests.Load() != 1 {
		t.Fatalf("second broker bypassed RoE bytes: requests=%d err=%v", requests.Load(), err)
	}
}

func TestRoEBrowserArtifactCapBeforeStorage(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	roe, err := ParseRoE(strings.NewReader("## In Scope\n127.0.0.1\n## Resource Caps\noutput_bytes: 8\ntotal_bytes: 8\n"))
	if err != nil {
		t.Fatal(err)
	}
	driver := &capturedWebDriver{gate: &secgate.Gate{Policy: roe.Policy}, capture: webCapture{Store: ws.Store}}
	if _, err := driver.save(context.Background(), "browser-dom", "http://127.0.0.1/", "123456789"); err == nil || !strings.Contains(err.Error(), "output cap") {
		t.Fatalf("oversized browser artifact accepted: %v", err)
	}
	snapshot, err := ws.Store.WebSnapshot(context.Background())
	if err != nil || len(snapshot.Artifacts) != 0 {
		t.Fatalf("oversized browser artifact persisted: %+v %v", snapshot.Artifacts, err)
	}
}

func TestStandaloneWebContinuesEngagementPolicyAndTranscript(t *testing.T) {
	stubEngageRunner(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>fixture</body></html>"))
	}))
	defer server.Close()
	cwd, workspace := t.TempDir(), t.TempDir()
	roePath := filepath.Join(cwd, "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first := engageRunInput{Opts: engageOpts{workspace: workspace}, Cwd: cwd, Goal: "inspect the fixture", Run: func(ctx context.Context, d engageDeps, _ string) (string, error) {
		if decision := d.Gate.AuthorizeAPIRequest(ctx, secgate.APIRequest{Method: "GET", URL: server.URL}); !decision.Allowed {
			return "", errors.New(decision.Reason)
		}
		return "initial assessment", nil
	}}
	if _, err := runEngageSession(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	var before engageRunMetadata
	if err := readEngageMetadata(filepath.Join(workspace, "run.json"), &before); err != nil || before.CommandAttempts != 1 {
		t.Fatalf("initial usage=%+v err=%v", before, err)
	}
	_, err := webExecute(context.Background(), []string{"collect", server.URL, "--workspace", workspace, "--roe", roePath, "--no-rdns"}, secgate.Auto, nil, false, 90)
	if err != nil {
		t.Fatal(err)
	}
	var after engageRunMetadata
	if err := readEngageMetadata(filepath.Join(workspace, "run.json"), &after); err != nil || after.CommandAttempts <= before.CommandAttempts || after.ByteUsage <= before.ByteUsage || after.PolicyHash != before.PolicyHash || after.Started != before.Started {
		t.Fatalf("web usage or policy was reset: %+v %v", after, err)
	}
	transcript, err := os.ReadFile(filepath.Join(workspace, "actions.jsonl"))
	if err != nil || !strings.Contains(string(transcript), `"runner":"isolated-worker"`) || !strings.Contains(string(transcript), `"runner":"web-broker"`) {
		t.Fatalf("mixed action transcript was lost: %q %v", transcript, err)
	}
	beforeRun, _ := os.ReadFile(filepath.Join(workspace, "run.json"))
	beforePolicy, _ := os.ReadFile(filepath.Join(workspace, "policy.json"))
	if err := os.WriteFile(roePath, []byte("## In Scope\n127.0.0.2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := webExecute(context.Background(), []string{"collect", server.URL, "--workspace", workspace, "--roe", roePath, "--no-rdns"}, secgate.Auto, nil, false, 90); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("changed RoE continued web engagement: %v", err)
	}
	afterRun, _ := os.ReadFile(filepath.Join(workspace, "run.json"))
	afterPolicy, _ := os.ReadFile(filepath.Join(workspace, "policy.json"))
	if string(beforeRun) != string(afterRun) || string(beforePolicy) != string(afterPolicy) {
		t.Fatal("changed RoE overwrote the checkpoint")
	}
	if err := os.WriteFile(roePath, []byte("## In Scope\n127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	after.Started = time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339Nano)
	if err := writeEngageMetadata(workspace, after); err != nil {
		t.Fatal(err)
	}
	if _, err := webExecute(context.Background(), []string{"collect", server.URL, "--workspace", workspace, "--roe", roePath, "--no-rdns"}, secgate.Auto, nil, false, 90); err == nil || !strings.Contains(err.Error(), "deadline has expired") {
		t.Fatalf("expired web engagement continued: %v", err)
	}
}

func TestStandaloneWebStopWritesStoppedReport(t *testing.T) {
	started := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	cwd, workspace := t.TempDir(), t.TempDir()
	roePath := filepath.Join(cwd, "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := webExecute(context.Background(), []string{"collect", server.URL, "--workspace", workspace, "--roe", roePath, "--no-rdns"}, secgate.Auto, nil, false, 90)
		done <- err
	}()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("web action stopped before request: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("web request did not start")
	}
	if err := stopEngageWorkspace([]string{"--workspace", workspace}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stopped web action reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("web stop did not cancel the request")
	}
	var metadata engageRunMetadata
	if err := readEngageMetadata(filepath.Join(workspace, "run.json"), &metadata); err != nil || metadata.Status != "stopped" {
		t.Fatalf("stopped checkpoint=%+v err=%v", metadata, err)
	}
	report, err := os.ReadFile(filepath.Join(workspace, "report.json"))
	var saved struct {
		Status string `json:"status"`
	}
	if err == nil {
		err = json.Unmarshal(report, &saved)
	}
	if err != nil || saved.Status != "stopped" {
		t.Fatalf("stopped report=%q err=%v", report, err)
	}
}

func TestStandaloneWebCannotBroadenSafeWorkspaceToAuto(t *testing.T) {
	stubEngageRunner(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	cwd, workspace := t.TempDir(), t.TempDir()
	roePath := filepath.Join(cwd, "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first := engageRunInput{Opts: engageOpts{workspace: workspace, safe: true}, Cwd: cwd, Goal: "inspect", Confirm: &countingConfirmer{ok: true}, Run: func(context.Context, engageDeps, string) (string, error) { return "done", nil }}
	if _, err := runEngageSession(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	_, err := webExecute(context.Background(), []string{"collect", server.URL, "--workspace", workspace, "--roe", roePath, "--no-rdns"}, secgate.Auto, nil, false, 90)
	if err == nil || !strings.Contains(err.Error(), "interactive approval") || requests.Load() != 0 {
		t.Fatalf("Safe workspace broadened: requests=%d err=%v", requests.Load(), err)
	}
	var metadata engageRunMetadata
	if err := readEngageMetadata(filepath.Join(workspace, "run.json"), &metadata); err != nil || metadata.Mode != "safe" {
		t.Fatalf("Safe checkpoint changed: %+v %v", metadata, err)
	}
}

func TestStandaloneWebRetainsByteCapAcrossCalls(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("12345678"))
	}))
	defer server.Close()
	cwd, workspace := t.TempDir(), t.TempDir()
	roePath := filepath.Join(cwd, "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n127.0.0.1\n## Resource Caps\noutput_bytes: 8\ntotal_bytes: 8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"collect", server.URL, "--workspace", workspace, "--roe", roePath, "--no-rdns"}
	if _, err := webExecute(context.Background(), args, secgate.Auto, nil, false, 90); err != nil {
		t.Fatal(err)
	}
	var before engageRunMetadata
	if err := readEngageMetadata(filepath.Join(workspace, "run.json"), &before); err != nil || before.ByteUsage != 8 {
		t.Fatalf("first web bytes=%+v err=%v", before, err)
	}
	second := []string{"collect", server.URL + "/second", "--workspace", workspace, "--roe", roePath, "--no-rdns"}
	if _, err := webExecute(context.Background(), second, secgate.Auto, nil, false, 90); err == nil || requests.Load() != 1 {
		t.Fatalf("resumed web byte cap was reset: requests=%d err=%v", requests.Load(), err)
	}
}

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
	// webExecute below resolves its policy from the working directory and, finding no
	// ROE.md, writes the template there. An empty temp directory keeps that out of the
	// package, the same reason the engage entry tests change directory.
	t.Chdir(t.TempDir())
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
	updated, cmd := m.dispatchWeb("inspect fixture.test --workspace "+dir+" --view apis --no-rdns", "/engage web inspect")
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
