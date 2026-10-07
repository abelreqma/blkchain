package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/histstore"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

func TestPlainREPLCommandsAndContext(t *testing.T) {
	useDeadServices(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	if err := os.Mkdir(".blk", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(initContextPath, []byte("project context"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := adaptiveAnswerFn
	defer func() { adaptiveAnswerFn = old }()
	calls := 0
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, q string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		calls++
		if q != "hello" || !strings.Contains(opts.Preface, "project context") {
			t.Errorf("answer received q=%q, context=%q", q, opts.Preface)
		}
		opts.Stream([]byte("saved answer"))
		return "saved answer", nil, false, nil, 2, "skip", nil
	}
	p := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(p, []byte("/agent auto\n/unknown\n/model\n/engage\n/init\nhello\n/history\n/quit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stdin := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = stdin }()
	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			if err := plainREPL(); err != nil {
				t.Fatal(err)
			}
		})
	})
	if calls != 1 {
		t.Fatalf("slash commands reached the answer loop: %d calls", calls)
	}
	for _, want := range []string{"unknown command /unknown", "/model requires the interactive TUI", "missing goal"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("missing command error %q: %q", want, stderr)
		}
	}
	if !strings.Contains(stdout, "loaded .blk/context.md") || !strings.Contains(stdout, "2 messages") {
		t.Fatalf("context or persistent history missing: %q", stdout)
	}
	h := histstore.OpenDefault()
	if h == nil {
		t.Fatal("history unavailable")
	}
	defer h.Close()
	hs, err := h.Sessions(context.Background())
	if err != nil || len(hs) != 1 {
		t.Fatalf("history sessions: %v, %v", hs, err)
	}
	m := model{hist: h}
	var turns []priorTurn
	captureStdout(t, func() { turns, err = plainHistory(&m, "1", nil) })
	if err != nil || len(turns) != 2 || turns[0].Content != "hello" || m.lastAnswer != "saved answer" || m.sess.id != hs[0].ID {
		t.Fatalf("history resume: %+v, %v", turns, err)
	}
}

func TestPlainEditorRetainsEditableDraftAndRemovesFile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir := t.TempDir()
	editor := filepath.Join(dir, "editor")
	if err := os.WriteFile(editor, []byte("#!/bin/sh\nprintf 'edited draft\\nsecond line' > \"$1\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", editor)
	var draft string
	var err error
	out := captureStdout(t, func() { draft, err = plainEditor("before") })
	if err != nil || draft != "edited draft\nsecond line" || !strings.Contains(out, "Enter submits") {
		t.Fatalf("editor draft = %q, %v, output %q", draft, err, out)
	}
	private, err := draftDir()
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(private, "blk-draft-*.md"))
	if err != nil || len(files) != 0 {
		t.Fatalf("editor left private drafts: %v, %v", files, err)
	}
}

func TestPlainPendingContextIsUsedOnlyByNextQuestion(t *testing.T) {
	useDeadServices(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	old := adaptiveAnswerFn
	defer func() { adaptiveAnswerFn = old }()
	var prefaces []string
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		prefaces = append(prefaces, opts.Preface)
		opts.Stream([]byte("answer"))
		return "answer", nil, false, nil, 1, "skip", nil
	}
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("/agent auto\n/attach https://example.test/reference\nfirst question\nsecond question\n/clear\n/quit\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	previous := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = previous }()
	captureStdout(t, func() {
		if err := plainREPL(); err != nil {
			t.Fatal(err)
		}
	})
	if len(prefaces) != 2 || !strings.Contains(prefaces[0], "URL reference") || prefaces[1] != "" {
		t.Fatalf("pending context was not one-shot: %v", prefaces)
	}
}

func TestPlainUndoWithoutSQLitePreservesEarlierExchange(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	t.Chdir(t.TempDir())
	dbPath, err := histstore.DBPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dbPath, 0700); err != nil {
		t.Fatal(err)
	}
	if store := histstore.OpenDefault(); store != nil {
		store.Close()
		t.Fatal("fixture unexpectedly opened SQLite")
	}
	previousAnswer := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = previousAnswer })
	var histories [][]priorTurn
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		histories = append(histories, append([]priorTurn(nil), opts.History...))
		opts.Stream([]byte("fixture answer"))
		return "fixture answer", nil, false, nil, 1, "skip", nil
	}
	input := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(input, []byte("/agent auto\nfirst question\nsecond question\n/undo\nthird question\n/quit\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	previousInput := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = previousInput })
	captureStdout(t, func() {
		if err := plainREPL(); err != nil {
			t.Fatal(err)
		}
	})
	if len(histories) != 3 || len(histories[2]) != 2 || histories[2][0].Content != "first question" {
		t.Fatalf("undo discarded earlier memory without SQLite: %+v", histories)
	}
	metas, err := listSessions()
	if err != nil || len(metas) != 1 {
		t.Fatalf("saved sessions: %v, %v", metas, err)
	}
	replay, err := loadMessages(metas[0].ID)
	if err != nil || len(replay) != 4 || replay[0].Content != "first question" || replay[2].Content != "third question" {
		t.Fatalf("replay differs from surviving memory: %v, %v", replay, err)
	}
}

// fakeGateway serves the three endpoints an agent turn uses: the health probe
// that selects the transport, session creation, and the SSE chat stream.
func fakeGateway(t *testing.T, answer string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/health":
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/api/sessions":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"gw-1"}`)
		case strings.HasSuffix(r.URL.Path, "/chat/stream"):
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: tool.started\ndata: {\"tool\":\"kb_search\"}\n\n")
			fmt.Fprintf(w, "event: assistant.delta\ndata: {\"delta\":%q}\n\n", answer)
			fmt.Fprint(w, "event: run.completed\ndata: {}\n\n")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("HERMES_API_URL", server.URL)
}

// A plain-REPL agent turn runs through the same transport wiring the TUI uses,
// so its answer is captured rather than streamed straight past: the turn
// reaches the JSONL transcript and the history store, and the gateway
// conversation handle it created is kept for the next turn.
func TestPlainAgentTurnPersistsAndKeepsTheConversation(t *testing.T) {
	useDeadServices(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	fakeGateway(t, "SSRF reaches internal services.")

	m := model{cfg: loadConfig(), mode: "agent", hist: histstore.OpenDefault()}
	if m.hist == nil {
		t.Fatal("history store unavailable")
	}
	defer m.hist.Close()
	var err error
	if m.sess, err = newSession(); err != nil {
		t.Fatal(err)
	}

	var answer string
	var rc replClient
	defer rc.close()
	out := captureStdout(t, func() {
		answer, err = plainAsk(&m, "agent", "summarize the SSRF notes", &rc, nil, "", false)
	})
	if err != nil {
		t.Fatalf("plain agent turn: %v", err)
	}
	if !strings.Contains(answer, "SSRF reaches internal services") {
		t.Fatalf("answer not captured, got %q", answer)
	}
	// The approved rendering: the tool line as it arrives, then the answered-in
	// header, the answer, and the cost footer, the same shape the TUI prints.
	rendered := stripANSI(out)
	for _, want := range []string{
		Glyph(GlyphBullet) + " kb_search running",
		Glyph(GlyphOK) + " Agent answered in",
		"SSRF reaches internal services",
		Glyph(GlyphBullet) + " 0s",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendering is missing %q, got:\n%s", want, rendered)
		}
	}
	if m.agentSession != "gw-1" {
		t.Errorf("gateway conversation handle = %q, want gw-1", m.agentSession)
	}

	m.pendingQ = "summarize the SSRF notes"
	if err := m.recordTurn(answer); err != nil {
		t.Fatalf("recordTurn: %v", err)
	}
	turns, err := m.hist.Messages(context.Background(), m.sess.id)
	if err != nil || len(turns) != 2 || turns[1].Content != answer {
		t.Fatalf("agent turn not in the history store: %v, %v", turns, err)
	}
	replay, err := loadMessages(m.sess.id)
	if err != nil || len(replay) != 2 || replay[1].Content != answer {
		t.Fatalf("agent turn not in the transcript: %v, %v", replay, err)
	}
}
