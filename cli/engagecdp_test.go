package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/webanalysis"
	"blkchain/cli/internal/webcollect"
	"github.com/mxschmitt/playwright-go"
)

func TestEngageCDPStateKeepsOnlyTheSelectedOrigin(t *testing.T) {
	state := &playwright.StorageState{
		Cookies: []playwright.Cookie{
			{Name: "host", Value: "one", Domain: "app.example.test", Path: "/"},
			{Name: "parent", Value: "two", Domain: ".example.test", Path: "/private"},
			{Name: "sibling", Value: "three", Domain: "other.example.test", Path: "/"},
			{Name: "suffix", Value: "four", Domain: ".badexample.test", Path: "/"},
		},
		Origins: []playwright.Origin{
			{Origin: "https://app.example.test", LocalStorage: []playwright.NameValue{{Name: "auth", Value: "current"}}},
			{Origin: "https://other.example.test", LocalStorage: []playwright.NameValue{{Name: "auth", Value: "other"}}},
		},
	}
	filtered, err := chatCDPFilterOrigin(state, "https://app.example.test")
	if err != nil || len(filtered.Cookies) != 2 || len(filtered.Origins) != 1 {
		t.Fatalf("filtered state has cookies=%d origins=%d err=%v", len(filtered.Cookies), len(filtered.Origins), err)
	}
	for _, cookie := range filtered.Cookies {
		if cookie.Domain != "app.example.test" || cookie.Name == "sibling" || cookie.Name == "suffix" {
			t.Fatalf("cookie escaped origin boundary: %s %s", cookie.Name, cookie.Domain)
		}
	}
	if filtered.Origins[0].Origin != "https://app.example.test" || filtered.Origins[0].LocalStorage[0].Value != "current" {
		t.Fatal("local storage did not match the selected origin")
	}
	if _, err := chatCDPFilterOrigin(state, "https://outside.test"); err == nil {
		t.Fatal("missing origin state was accepted")
	}
	if _, err := chatCDPFilterOrigin(state, "https://other.example.test/path"); err == nil {
		t.Fatal("origin with a path was accepted")
	}
}

func TestEngageCDPRequiresExplicitRoleAndLoopback(t *testing.T) {
	for _, args := range [][]string{
		{"--session-cdp", "http://127.0.0.1:9223", "assess fixture"},
		{"--session", "roles.json", "--role", "reader", "--session-cdp", "http://192.0.2.4:9223", "assess fixture"},
	} {
		if _, _, err := parseEngageArgs(args); err == nil || !strings.Contains(err.Error(), "session-cdp") {
			t.Fatalf("invalid autonomous CDP options accepted: %v", err)
		}
	}
	if _, _, err := parseEngageArgs([]string{"--session", "roles.json", "--role", "reader", "--session-cdp", "http://127.0.0.1:9223", "assess fixture"}); err != nil {
		t.Fatalf("valid autonomous CDP options rejected: %v", err)
	}
	for _, args := range [][]string{
		{"collect", "http://127.0.0.1:8787", "--session-cdp", "http://127.0.0.1:9223"},
		{"collect", "http://127.0.0.1:8787", "--session", "roles.json", "--role", "reader", "--session-cdp", "http://127.0.0.1:9223"},
		{"inspect", "--session", "roles.json", "--role", "reader", "--session-cdp", "http://127.0.0.1:9223"},
	} {
		if _, err := webExecute(context.Background(), args, 0, nil, false, 100); err == nil || !strings.Contains(err.Error(), "session-cdp") {
			t.Fatalf("invalid web CDP options accepted: %v", err)
		}
	}
}

func TestEngageCDPRejectsMixedCredentialSourcesAndDeniedOrigin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roles.json")
	if err := os.WriteFile(path, []byte(`{"roles":[{"name":"reader","origin":"http://127.0.0.1:8787","cookies_env":{"session":"TEST_SESSION"}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := webSelectCDPRole(path, "reader"); err == nil || !strings.Contains(err.Error(), "only a name and exact origin") {
		t.Fatalf("mixed credential sources accepted: %v", err)
	}
	role := webSessionRole{Name: "reader", Origin: "http://127.0.0.1:8787"}
	gate := loopbackGate(t, loopbackRoE(t, "10.0.0.0/24"))
	if _, err := webImportCDPRole(context.Background(), gate, role, "http://127.0.0.1:9223"); err == nil || !strings.Contains(err.Error(), "denied by the engagement policy") {
		t.Fatalf("out-of-scope CDP role reached the source browser: %v", err)
	}
}

func TestEngageCDPCollectionKeepsRoleOnItsOrigin(t *testing.T) {
	roe := loopbackRoE(t, "127.0.0.1")
	gate := loopbackGate(t, roe)
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	role := webSessionRole{Name: "reader", Origin: "http://127.0.0.1:8787"}
	if got := webCapturedRole(&role, "http://127.0.0.1:8788", "task"); got != "anonymous" {
		t.Fatalf("cross-origin observation kept the authenticated role: %s", got)
	}
	if got := webCapturedRole(&role, role.Origin+"/private", "task"); got != "reader" {
		t.Fatalf("same-origin observation lost the authenticated role: %s", got)
	}
	tools := webJobTools(gate, engagement.Task{ID: "web-fixture", Surface: engagement.SurfaceWeb},
		webCapture{Store: ws.Store, Session: &role}, newWebBroker(gate, nil))
	for _, tool := range tools {
		if tool.Name() != "web_collect" {
			continue
		}
		out, err := tool.Call(context.Background(), `{"targets":["http://127.0.0.1:8788/"],"browser":true}`)
		if err != nil || !strings.Contains(out, "must match the role origin") {
			t.Fatalf("cross-origin authenticated collection was accepted: out=%q err=%v", out, err)
		}
		return
	}
	t.Fatal("web_collect tool was unavailable")
}

func TestEngageCDPDirectCollectionRejectsMixedOrigins(t *testing.T) {
	root := t.TempDir()
	roePath := filepath.Join(root, "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n127.0.0.1\n\n## Allowed Actions\n- browser-read\n- api-read\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sessions := filepath.Join(root, "sessions.json")
	if err := os.WriteFile(sessions, []byte(`{"roles":[{"name":"reader","origin":"http://127.0.0.1:8787"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := webExecute(context.Background(), []string{"collect", "http://127.0.0.1:8787", "http://127.0.0.1:8788",
		"--workspace", filepath.Join(root, "workspace"), "--roe", roePath, "--session", sessions, "--role", "reader",
		"--session-cdp", "http://127.0.0.1:9223", "--browser", "--auto", "--no-rdns"}, secgate.Auto, nil, false, 100)
	if err == nil || !strings.Contains(err.Error(), "targets must match the role origin") {
		t.Fatalf("mixed-origin CDP collection was accepted: %v", err)
	}
}

func TestEngageCDPReplayRejectsUnsupportedProtocol(t *testing.T) {
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	operation := webanalysis.Operation{ID: webanalysis.Hash([]byte("ws-fixture")), Protocol: "websocket"}
	if err := ws.Store.PutWeb(context.Background(), "operation", operation.ID, "", operation); err != nil {
		t.Fatal(err)
	}
	svc := webcollect.New(ws.Store, nil, webParseWorker)
	err = webReplay(context.Background(), svc, nil, nil, webOpts{operation: operation.ID, sessionCDP: "http://127.0.0.1:9223"})
	if err == nil || !strings.Contains(err.Error(), "HTTP operations only") {
		t.Fatalf("CDP-backed websocket replay did not fail clearly: %v", err)
	}
}
