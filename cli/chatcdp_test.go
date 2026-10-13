package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/tooldef"
	"blkchain/cli/internal/webanalysis"
	"github.com/gorilla/websocket"
)

func TestChatCDPRejectsNonLoopbackAndUnpinnedNode(t *testing.T) {
	if _, err := chatCDPStorageState(context.Background(), "http://192.0.2.5:9222"); err == nil {
		t.Fatal("non-loopback CDP endpoint accepted")
	}
	node := filepath.Join(t.TempDir(), "node")
	if err := os.WriteFile(node, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_BROWSER_NODE_PATH", node)
	t.Setenv("BLKCHAIN_BROWSER_NODE_SHA256", strings.Repeat("0", 64))
	if _, err := chatVerifiedLocalNode(); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("unverified Node binary accepted: %v", err)
	}
}

func TestChatCDPReadsIsolatedFixtureWithoutClosingIt(t *testing.T) {
	if os.Getenv("BLKCHAIN_CHAT_CDP_E2E") != "1" {
		t.Skip("set BLKCHAIN_CHAT_CDP_E2E=1 with the provisioned browser")
	}
	path, err := exec.LookPath("node")
	if err != nil {
		t.Fatal(err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	t.Setenv("BLKCHAIN_BROWSER_NODE_PATH", path)
	t.Setenv("BLKCHAIN_BROWSER_NODE_SHA256", hex.EncodeToString(hash.Sum(nil)))
	duration := 90 * time.Second
	if os.Getenv("BLKCHAIN_ENGAGE_LLM_E2E") == "1" {
		duration = 6 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	profile := t.TempDir()
	chrome := exec.CommandContext(ctx, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"--headless=new", "--no-first-run", "--no-default-browser-check", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0",
		"--user-data-dir="+profile, "about:blank")
	chrome.Stdout, chrome.Stderr = io.Discard, io.Discard
	if err := chrome.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = chrome.Process.Kill(); _ = chrome.Wait() })
	var port int
	for i := 0; i < 100; i++ {
		data, err := os.ReadFile(filepath.Join(profile, "DevToolsActivePort"))
		if err == nil {
			port, _ = strconv.Atoi(strings.SplitN(string(data), "\n", 2)[0])
			if port > 0 {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if port == 0 {
		t.Fatal("temporary Chrome CDP endpoint did not start")
	}
	endpoint := "http://127.0.0.1:" + strconv.Itoa(port)
	var authenticated atomic.Int32
	var redirectTarget atomic.Value
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			if target, ok := redirectTarget.Load().(string); ok {
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
			http.Error(w, "redirect target unavailable", http.StatusServiceUnavailable)
			return
		}
		cookie, _ := r.Cookie("blk_fixture")
		if cookie != nil && cookie.Value == "signed-in" {
			authenticated.Add(1)
			_, _ = w.Write([]byte("signed-in receipt"))
			return
		}
		_, _ = w.Write([]byte("anonymous receipt"))
	}))
	defer fixture.Close()
	var leaked atomic.Bool
	var otherRequests atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherRequests.Add(1)
		if strings.Contains(r.Header.Get("Cookie"), "blk_fixture=") {
			leaked.Store(true)
		}
		_, _ = w.Write([]byte("other origin receipt"))
	}))
	defer other.Close()
	redirectTarget.Store(other.URL)
	versionRequest, err := http.NewRequestWithContext(ctx, "GET", endpoint+"/json/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	versionResponse, err := http.DefaultClient.Do(versionRequest)
	if err != nil {
		t.Fatal(err)
	}
	var version struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(versionResponse.Body).Decode(&version); err != nil {
		versionResponse.Body.Close()
		t.Fatal(err)
	}
	versionResponse.Body.Close()
	connection, _, err := websocket.DefaultDialer.Dial(version.WebSocketDebuggerURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.WriteJSON(map[string]any{"id": 1, "method": "Storage.setCookies", "params": map[string]any{
		"cookies": []map[string]any{{"name": "blk_fixture", "value": "signed-in", "url": fixture.URL}},
	}}); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	var result struct {
		ID    int            `json:"id"`
		Error map[string]any `json:"error"`
	}
	for {
		if err := connection.ReadJSON(&result); err != nil {
			connection.Close()
			t.Fatal(err)
		}
		if result.ID == 1 {
			break
		}
	}
	connection.Close()
	if result.Error != nil {
		t.Fatalf("fixture cookie setup failed: %v", result.Error)
	}
	state, err := chatCDPStorageState(ctx, endpoint)
	if err != nil || state == nil {
		t.Fatalf("CDP storage clone failed: state=%v err=%v", state, err)
	}
	found := false
	for _, cookie := range state.Cookies {
		found = found || cookie.Name == "blk_fixture" && cookie.Value == "signed-in"
	}
	if !found {
		t.Fatal("CDP storage clone omitted the fixture cookie")
	}
	browserState := &chatBrowserState{}
	defer browserState.Close()
	registry, closeTools, err := newChatToolRegistry(ctx, nil, ragconfig.Config{}, nil, "Open "+fixture.URL,
		nil, AnswerOpts{Browser: browserState, BrowserCDP: endpoint, requiredAction: "browser_control"})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, ok := registry.Get("browser_control")
	if !ok {
		t.Fatal("browser_control was not registered")
	}
	out, err := tool.Call(ctx, `{"op":"navigate","url":"`+fixture.URL+`"}`)
	if err != nil || !strings.Contains(out, "signed-in receipt") {
		t.Fatalf("isolated browser did not use cloned state: out=%q err=%v", out, err)
	}
	request, err := http.NewRequestWithContext(ctx, "GET", endpoint+"/json/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("source browser stopped after storage clone: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("source browser status = %d", response.StatusCode)
	}
	root := t.TempDir()
	roePath := filepath.Join(root, "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n127.0.0.1\n\n## Allowed Actions\n- browser-read\n- api-read\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sessions := filepath.Join(root, "sessions.json")
	roles, err := json.Marshal(map[string]any{"roles": []map[string]string{{"name": "reader", "origin": fixture.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sessions, roles, 0o600); err != nil {
		t.Fatal(err)
	}
	before := authenticated.Load()
	_, err = webExecute(ctx, []string{"collect", fixture.URL, "--workspace", filepath.Join(root, "collection"), "--roe", roePath,
		"--session", sessions, "--role", "reader", "--session-cdp", endpoint, "--browser", "--auto", "--no-rdns", "--json"}, 0, nil, false, 100)
	if err != nil || authenticated.Load() <= before {
		t.Fatalf("web collection did not reuse the origin-bound Chrome session: requests=%d err=%v", authenticated.Load()-before, err)
	}
	replayDir := filepath.Join(root, "replay")
	ws, err := engagement.OpenWorkspace(replayDir)
	if err != nil {
		t.Fatal(err)
	}
	replayTask := engagement.Task{ID: "replay-task", Surface: engagement.SurfaceWeb, Status: engagement.StatusTodo}
	if _, err := ws.Store.Apply(engagement.Delta{Kind: "fixture", Upserts: []engagement.Task{replayTask}}); err != nil {
		t.Fatal(err)
	}
	operation, err := webanalysis.FromObserved(webanalysis.RequestExample{URL: fixture.URL, Method: "GET", Role: "reader"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.Store.PutWeb(ctx, "operation", operation.ID, replayTask.ID, operation); err != nil {
		t.Fatal(err)
	}
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	before = authenticated.Load()
	_, err = webExecute(ctx, []string{"replay", "--workspace", replayDir, "--roe", roePath, "--operation", operation.ID,
		"--example", "1", "--session", sessions, "--role", "reader", "--session-cdp", endpoint, "--task", replayTask.ID,
		"--auto", "--no-rdns", "--json"}, 0, nil, false, 100)
	if err != nil || authenticated.Load() <= before {
		t.Fatalf("web replay did not reuse the origin-bound Chrome session: requests=%d err=%v", authenticated.Load()-before, err)
	}
	stubEngageRunner(t)
	before = authenticated.Load()
	autonomousDir := filepath.Join(root, "autonomous")
	_, err = runEngageSession(ctx, engageRunInput{
		Opts: engageOpts{roe: roePath, workspace: autonomousDir, session: sessions, role: "reader", sessionCDP: endpoint},
		Cwd:  root, Goal: "assess the fixture",
		Run: func(ctx context.Context, d engageDeps, _ string) (string, error) {
			if d.WebSession == nil || d.WebSession.AuthState == nil || d.WebSession.Origin != fixture.URL {
				return "", fmt.Errorf("autonomous web session was not attached")
			}
			task := engagement.Task{ID: "web-fixture", Surface: engagement.SurfaceWeb, Status: engagement.StatusTodo}
			if _, err := d.Store.Apply(engagement.Delta{Kind: "fixture", Upserts: []engagement.Task{task}}); err != nil {
				return "", err
			}
			tools, closeTools := webToolsForTask(d.Gate, task, webCapture{Store: d.Store, Session: d.WebSession, Runs: d.Runs})
			defer closeTools()
			var browserTool, apiTool, collectTool tooldef.Tool
			for _, tool := range tools {
				switch tool.Name() {
				case "web_browser":
					browserTool = tool
				case "web_api":
					apiTool = tool
				case "web_collect":
					collectTool = tool
				}
			}
			if browserTool == nil || apiTool == nil || collectTool == nil {
				return "", fmt.Errorf("autonomous web tools were unavailable")
			}
			out, err := browserTool.Call(ctx, `{"op":"navigate","url":"`+fixture.URL+`"}`)
			if err != nil || !strings.Contains(out, "signed-in receipt") {
				return "", fmt.Errorf("autonomous browser did not use the signed-in role: %s: %v", out, err)
			}
			beforeCollect := authenticated.Load()
			out, err = collectTool.Call(ctx, `{"targets":["`+fixture.URL+`"]}`)
			if err != nil || !strings.Contains(out, "web collect") || !strings.Contains(out, "signed-in receipt") || authenticated.Load() <= beforeCollect {
				return "", fmt.Errorf("autonomous web collect did not use the signed-in role: %s: %v", out, err)
			}
			out, err = browserTool.Call(ctx, `{"op":"navigate","url":"`+other.URL+`"}`)
			if err != nil || !strings.Contains(out, "other origin receipt") || leaked.Load() {
				return "", fmt.Errorf("browser leaked credentials to another origin: %s: %v", out, err)
			}
			beforeAPI := otherRequests.Load()
			out, err = apiTool.Call(ctx, `{"method":"GET","url":"`+other.URL+`"}`)
			if err != nil || otherRequests.Load() <= beforeAPI || leaked.Load() {
				return "", fmt.Errorf("API leaked credentials to another origin: %s: %v", out, err)
			}
			beforeRedirect := otherRequests.Load()
			out, err = browserTool.Call(ctx, `{"op":"navigate","url":"`+fixture.URL+`/redirect"}`)
			if err != nil || otherRequests.Load() <= beforeRedirect || leaked.Load() || !strings.Contains(out, "other origin receipt") {
				return "", fmt.Errorf("browser redirect retained credentials: %s: %v", out, err)
			}
			beforeRedirect = otherRequests.Load()
			out, err = apiTool.Call(ctx, `{"method":"GET","url":"`+fixture.URL+`/redirect"}`)
			if err != nil || otherRequests.Load() <= beforeRedirect || leaked.Load() {
				return "", fmt.Errorf("API redirect retained credentials: %s: %v", out, err)
			}
			beforeRedirect = otherRequests.Load()
			out, err = collectTool.Call(ctx, `{"targets":["`+fixture.URL+`/redirect"]}`)
			if err != nil || otherRequests.Load() <= beforeRedirect || leaked.Load() || strings.Contains(out, "signed-in receipt") {
				return "", fmt.Errorf("collection redirect retained credentials: %s: %v", out, err)
			}
			snapshot, err := d.Store.WebSnapshot(ctx)
			if err != nil {
				return "", err
			}
			for _, artifact := range snapshot.Artifacts {
				if (artifact.URL == other.URL || artifact.FinalURL == other.URL) && artifact.Role != "anonymous" {
					return "", fmt.Errorf("cross-origin evidence retained the authenticated role")
				}
				if artifact.Kind == "browser-dom" || artifact.Kind == "api-observation" || artifact.Kind == "api-response" {
					body, err := d.Store.WebBlob(artifact.Hash)
					if err != nil {
						return "", err
					}
					if strings.Contains(string(body), "other origin receipt") && artifact.Role != "anonymous" {
						return "", fmt.Errorf("cross-origin response content retained the authenticated role")
					}
				}
			}
			return "done", nil
		},
	})
	if err != nil || authenticated.Load() <= before {
		t.Fatalf("autonomous web task did not reuse the origin-bound Chrome session: requests=%d err=%v", authenticated.Load()-before, err)
	}
	if _, err := runEngageSession(ctx, engageRunInput{Opts: engageOpts{resume: autonomousDir}, Run: func(context.Context, engageDeps, string) (string, error) {
		return "done", nil
	}}); err == nil || !strings.Contains(err.Error(), "web CDP role differs") {
		t.Fatalf("resume silently dropped the authenticated web role: %v", err)
	}
	if _, err := runEngageSession(ctx, engageRunInput{
		Opts: engageOpts{resume: autonomousDir, session: sessions, role: "reader", sessionCDP: endpoint},
		Run: func(_ context.Context, d engageDeps, _ string) (string, error) {
			if d.WebSession == nil || d.WebSession.AuthState == nil {
				return "", fmt.Errorf("resumed web role state was unavailable")
			}
			return "done", nil
		},
	}); err != nil {
		t.Fatalf("resume with the original authenticated role failed: %v", err)
	}
	if os.Getenv("BLKCHAIN_ENGAGE_LLM_E2E") != "1" {
		return
	}
	adoptProjectEnv(t)
	t.Setenv("BLK_ENABLE_THINKING", "0")
	t.Setenv("BLKCHAIN_ENGAGE_MAX_ROUNDS", "3")
	t.Setenv("BLKCHAIN_ENGAGE_MAX_CALLS", "64")
	cfg := ragconfig.Load()
	modelID := resolveModel(cfg)
	base, err := newOMLX(cfg, modelID)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := newRetrievalClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	live := &convergenceLiveModel{model: base}
	before = authenticated.Load()
	modelWorkspace := filepath.Join(root, "model-autonomous")
	goal := "Create one web task for " + fixture.URL + ". Dispatch it. Use web_browser to navigate to the target and web_collect to collect it through the signed-in role. Record the observed response and report it. Do not run commands or add other tasks."
	final, err := runEngageSession(ctx, engageRunInput{
		Opts: engageOpts{roe: roePath, workspace: modelWorkspace, session: sessions, role: "reader", sessionCDP: endpoint},
		Cwd:  root, Goal: goal, Model: live, RC: rc, Cfg: cfg,
	})
	if err != nil || authenticated.Load() <= before {
		t.Fatalf("model-driven authenticated engagement: requests=%d tools=%v stages=%v final=%q err=%v", authenticated.Load()-before, live.tools, live.stages, capRunes(final, 2000), err)
	}
	ws, err = engagement.OpenWorkspace(modelWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	snapshot, err := ws.Store.WebSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stored := false
	for _, artifact := range snapshot.Artifacts {
		if artifact.Kind != "browser-dom" || artifact.Role != "reader" || !webSameOrigin(artifact.URL, fixture.URL) {
			continue
		}
		body, err := ws.Store.WebBlob(artifact.Hash)
		if err == nil && strings.Contains(string(body), "signed-in receipt") {
			stored = true
		}
	}
	if !stored {
		t.Fatalf("model-driven engagement did not retain the signed-in response: tools=%v artifacts=%d", live.tools, len(snapshot.Artifacts))
	}
	for _, tool := range live.tools {
		if tool == "run_command" {
			t.Fatalf("browser-only web task ran an anonymous command: tools=%v", live.tools)
		}
	}
	t.Logf("model-driven authenticated engagement: requests=%d tools=%v", authenticated.Load()-before, live.tools)
}
