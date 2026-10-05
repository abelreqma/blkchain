package main

import (
	"context"
	"encoding/json"
	tea "github.com/charmbracelet/bubbletea"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/webanalysis"
)

func TestExactReplayThroughSharedWebCommand(t *testing.T) {
	bodies := []string{"exact\r\ntext\x00", " [1,{\"a\":true}] \n", "\x00\xff\xfe", "--x\r\nContent-Disposition: form-data; name=\"f\"; filename=\"fixture\"\r\n\r\n\x00\xff\r\n--x--\r\n"}
	types := []string{"text/plain", "application/json", "application/octet-stream", "multipart/form-data; boundary=x"}
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/upload/"))
		if err != nil || index < 0 || index >= len(bodies) {
			t.Error("unexpected request")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != bodies[index] || r.Header.Get("Content-Type") != types[index] {
			t.Errorf("wire bytes changed for %d", index)
		}
		if r.Header.Get("Authorization") != "Bearer refreshed-fixture" {
			t.Error("current role credential missing")
		}
		received.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"accepted":true}`)
	}))
	defer server.Close()
	dir := t.TempDir()
	scopeFile := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopeFile, []byte("127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLK_FIXTURE_REPLAY_AUTH", "Bearer refreshed-fixture")
	sessions := filepath.Join(dir, "sessions.json")
	roleData, _ := json.Marshal(map[string]any{"roles": []webSessionRole{{Name: "writer", Origin: server.URL, HeadersEnv: map[string]string{"Authorization": "BLK_FIXTURE_REPLAY_AUTH"}}}})
	if err := os.WriteFile(sessions, roleData, 0600); err != nil {
		t.Fatal(err)
	}
	ws, err := engagement.OpenWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ws.Store.Apply(engagement.Delta{Kind: "fixture", Upserts: []engagement.Task{{ID: "replay-task", Surface: engagement.SurfaceWeb, Status: engagement.StatusTodo, Armed: true}}}); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for i, body := range bodies {
		example := webanalysis.RequestExample{URL: server.URL + "/upload/" + strconv.Itoa(i), Method: "POST", Role: "writer", Headers: http.Header{"Content-Type": []string{types[i]}, "Authorization": []string{"stale-fixture"}}}
		webanalysis.SetRequestBody(&example, []byte(body))
		op, err := webanalysis.FromObserved(example)
		if err != nil {
			t.Fatal(err)
		}
		if err = ws.Store.PutWeb(context.Background(), "operation", op.ID, "replay-task", op); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, op.ID)
	}
	ws.Close()
	for i, id := range ids {
		args := []string{"replay", "--workspace", dir, "--scope", scopeFile, "--operation", id, "--example", "1", "--session", sessions, "--task", "replay-task", "--no-rdns", "--json"}
		if i%2 == 1 {
			var command strings.Builder
			for _, arg := range args {
				command.WriteString(strconv.Quote(arg))
				command.WriteByte(' ')
			}
			args, err = webArguments(command.String())
			if err != nil {
				t.Fatal(err)
			}
		}
		output, err := webExecute(context.Background(), args, secgate.Safe, webOKConfirmer{}, i%2 == 1, 90)
		if err != nil {
			t.Fatal(err)
		}
		var snap webanalysis.Snapshot
		if err = json.Unmarshal([]byte(output), &snap); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, op := range snap.Operations {
			if op.ID == id && op.Evidence.Grade == "response-observed" {
				found = true
			}
		}
		if !found {
			t.Fatal("replay response evidence missing")
		}
	}
	if received.Load() != int32(len(bodies)) {
		t.Fatal("replay did not reach fixture", received.Load())
	}
}

func TestUnavailableRolePersistsCoverageGap(t *testing.T) {
	dir := t.TempDir()
	scopeFile := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopeFile, []byte("127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := webExecute(context.Background(), []string{"collect", "http://127.0.0.1", "--workspace", dir, "--scope", scopeFile, "--role", "admin", "--no-rdns"}, secgate.Safe, webOKConfirmer{}, false, 90)
	if err == nil {
		t.Fatal("unsupplied role accepted")
	}
	ws, err := engagement.OpenWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	snap, err := ws.Store.WebSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	filtered := webFilter(snap, []string{"http://127.0.0.1"})
	if len(filtered.Coverage) != 1 {
		t.Fatal("unavailable role disappeared from target-filtered coverage")
	}
	if len(snap.Coverage) != 1 || snap.Coverage[0].Role != "admin" || snap.Coverage[0].State != "blocked" || len(snap.Artifacts) != 0 {
		t.Fatal("role gap lost", snap)
	}
}

func TestEvidenceJSONThroughTUIDispatch(t *testing.T) {
	dir := t.TempDir()
	ws, err := engagement.OpenWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	op := webanalysis.Operation{ID: webanalysis.ID("tui-socket"), Origin: "wss://fixture.test", Path: "/socket", Method: "GET", Protocol: "websocket", Validation: "response-observed", Examples: []webanalysis.RequestExample{{Status: 101}}}
	if err = ws.Store.PutWeb(context.Background(), "operation", op.ID, "", op); err != nil {
		t.Fatal(err)
	}
	ws.Close()
	m := newKeyModel(t)
	updated, cmd := m.dispatchWeb("inspect --workspace "+strconv.Quote(dir)+" --json --no-rdns", "/web inspect")
	batch, ok := cmd().(tea.BatchMsg)
	if !ok {
		t.Fatal("TUI dispatch missing")
	}
	found := false
	for _, command := range batch {
		if done, ok := command().(webDoneMsg); ok {
			found = true
			var snap webanalysis.Snapshot
			if done.Err != nil || json.Unmarshal([]byte(done.Output), &snap) != nil || len(snap.Operations) != 1 || snap.Operations[0].Evidence.Grade != "handshake-observed" || snap.Operations[0].Evidence.Explanation == "" {
				t.Fatal("TUI evidence grade missing", done.Err)
			}
			next, _ := updated.(model).Update(done)
			if next.(model).working {
				t.Fatal("TUI web job did not finish")
			}
		}
	}
	if !found {
		t.Fatal("TUI completion missing")
	}
}

func TestAssistedBrowserRejectsOversizedWindow(t *testing.T) {
	b := webJobBrowser{Assist: 121 * time.Second}
	if err := b.Visit(context.Background(), "https://fixture.test/", "anonymous"); err == nil {
		t.Fatal("assistance limit accepted")
	}
}
