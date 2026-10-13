package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"blkchain/cli/internal/retrieval"
)

func TestChatToolsLocalLLME2E(t *testing.T) {
	if os.Getenv("BLKCHAIN_CHAT_TOOLS_E2E") != "1" {
		t.Skip("set BLKCHAIN_CHAT_TOOLS_E2E=1 with the local stack running")
	}
	var hits atomic.Int32
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 128))
		if r.Method == http.MethodPost && strings.TrimSpace(string(body)) == "fixture-check" {
			hits.Add(1)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("fixture receipt"))
	}))
	defer srv.Close()
	cfg := loadConfig()
	rc, err := newRetrievalClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	question := "Send a POST request to " + srv.URL + " with body fixture-check. Report the observed HTTP status and response."
	answer, _, _, _, _, route, err := adaptiveAnswer(ctx, rc, cfg, question, enabledRoutes{Local: true, Web: true}, false, AnswerOpts{Agent: "auto", WebFirst: true})
	t.Logf("route=%s hits=%d answer=%q", route, hits.Load(), answer)
	if err != nil || hits.Load() == 0 || !strings.Contains(answer, "201") {
		t.Fatalf("live native chat did not use the local API fixture: route=%s hits=%d err=%v", route, hits.Load(), err)
	}
	before := hits.Load()
	captureStdout(t, func() { answer, err = askWith(nil, nil, []string{question}) })
	if err != nil || hits.Load() <= before || !strings.Contains(answer, "201") {
		t.Fatalf("default one-shot ask did not use the native API tool: hits=%d answer=%q err=%v", hits.Load(), answer, err)
	}
	plain := &replClient{agent: "auto"}
	defer plain.close()
	before = hits.Load()
	answer, err = plainAsk(&model{}, question, plain, nil, "", false)
	if err != nil || hits.Load() <= before || !strings.Contains(answer, "201") {
		t.Fatalf("plain REPL did not run the API action: hits=%d answer=%q err=%v", hits.Load(), answer, err)
	}
	before = hits.Load()
	ui := model{cfg: cfg, rc: rc, mode: "rag", answerAgent: "auto"}
	message := ui.streamCmd(ctx, question, "", time.Now(), false)()
	done, ok := message.(streamDoneMsg)
	if !ok || done.err != nil || hits.Load() <= before || !strings.Contains(done.full, "201") {
		t.Fatalf("TUI did not run the API action: message=%T hits=%d", message, hits.Load())
	}
	before = requests.Load()
	answer, _, _, _, _, route, err = adaptiveAnswer(ctx, rc, cfg, "Investigate the endpoint at "+srv.URL+" and tell me what you observe.", enabledRoutes{Local: true, Web: true}, false, AnswerOpts{Agent: "auto", WebFirst: true})
	t.Logf("inferred route=%s requests=%d answer=%q", route, requests.Load()-before, answer)
	if err != nil || requests.Load() <= before {
		t.Fatalf("native chat did not infer an API action: route=%s requests=%d err=%v", route, requests.Load()-before, err)
	}
	before = requests.Load()
	answer, _, _, _, _, route, err = adaptiveAnswer(ctx, rc, cfg, "What does the endpoint at "+srv.URL+" return right now?", enabledRoutes{Local: true, Web: true}, false, AnswerOpts{Agent: "auto", WebFirst: true})
	t.Logf("question route=%s requests=%d answer=%q", route, requests.Load()-before, answer)
	if err != nil || requests.Load() <= before {
		t.Fatalf("native chat answered a live-target question without inspecting it: route=%s requests=%d err=%v", route, requests.Load()-before, err)
	}
	for _, phrasing := range []string{
		"Would you mind checking what " + srv.URL + " serves?",
		"I'd like you to inspect " + srv.URL + " and report its status.",
		"What response comes back from " + srv.URL + "?",
	} {
		before = requests.Load()
		answer, _, _, _, _, route, err = adaptiveAnswer(ctx, rc, cfg, phrasing, enabledRoutes{Local: true, Web: true}, false, AnswerOpts{Agent: "auto", WebFirst: true})
		if err != nil || requests.Load() <= before || !strings.Contains(answer, "201") {
			t.Fatalf("native chat did not inspect the target for %q: route=%s requests=%d answer=%q err=%v", phrasing, route, requests.Load()-before, answer, err)
		}
	}
	reg, closeTools, err := newChatToolRegistry(ctx, rc, cfg, nil, "Navigate to "+srv.URL, nil, AnswerOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	browser, _ := reg.Get("web_browser")
	before = requests.Load()
	page, err := browser.Call(ctx, `{"op":"navigate","url":"`+srv.URL+`"}`)
	if err != nil || requests.Load() <= before || !strings.Contains(page, "fixture receipt") {
		t.Fatalf("native browser did not use the fixture: requests=%d page=%q err=%v", requests.Load()-before, page, err)
	}
	before = requests.Load()
	var stages []string
	answer, _, _, _, _, route, err = adaptiveAnswer(ctx, rc, cfg, "Use web_browser to navigate to "+srv.URL+" and report the page text.", enabledRoutes{Local: true, Web: true}, false, AnswerOpts{Agent: "auto", WebFirst: true, Stage: func(stage string) { stages = append(stages, stage) }})
	if err != nil || requests.Load() <= before || (!slices.Contains(stages, "tool web_browser") && !slices.Contains(stages, "tool browser_control")) || !strings.Contains(answer, "fixture receipt") {
		t.Fatalf("local model did not use the native browser: route=%s requests=%d stages=%v answer=%q err=%v", route, requests.Load()-before, stages, answer, err)
	}
	stages = nil
	answer, _, _, _, _, route, err = adaptiveAnswer(ctx, rc, cfg, "Read go.mod from the current working directory and tell me its module path.", enabledRoutes{Local: true, Web: true}, false, AnswerOpts{Agent: "auto", ToolHost: chatToolHostLocal, WebFirst: true, Stage: func(stage string) { stages = append(stages, stage) }})
	if err != nil || !slices.Contains(stages, "tool file_read") || !strings.Contains(answer, "blkchain/cli") {
		t.Fatalf("local model did not use file_read: route=%s stages=%v answer=%q err=%v", route, stages, answer, err)
	}
	stages = nil
	answer, _, _, _, _, route, err = adaptiveAnswer(ctx, rc, cfg, "Use route_skill to select a web assessment playbook.", enabledRoutes{Local: true, Web: true}, false, AnswerOpts{Agent: "auto", WebFirst: true, Stage: func(stage string) { stages = append(stages, stage) }})
	if err != nil || !slices.Contains(stages, "tool route_skill") {
		t.Fatalf("local model did not use route_skill: route=%s stages=%v answer=%q err=%v", route, stages, answer, err)
	}
	stages = nil
	answer, _, _, _, _, route, err = adaptiveAnswer(ctx, rc, cfg, "Use kb_search to find local SSRF guidance.", enabledRoutes{Local: true, Web: true}, false, AnswerOpts{Agent: "auto", WebFirst: true, Stage: func(stage string) { stages = append(stages, stage) }})
	if err != nil || !slices.Contains(stages, "tool kb_search") {
		t.Fatalf("local model did not use kb_search: route=%s stages=%v answer=%q err=%v", route, stages, answer, err)
	}
}

func TestChatSandboxLocalLLME2E(t *testing.T) {
	if os.Getenv("BLKCHAIN_CHAT_TOOLS_E2E") != "1" {
		t.Skip("set BLKCHAIN_CHAT_TOOLS_E2E=1 with the local stack running")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	root, err := chatWorkspaceRoot("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_, _ = chatDocker(cleanup, nil, "rm", "-f", chatContainerName(root))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cfg := loadConfig()
	var stages []string
	_, _, _, _, _, _, err = adaptiveAnswer(ctx, nil, cfg, "Create notes.txt in the sandbox containing exactly alpha.",
		enabledRoutes{}, false, AnswerOpts{Agent: "auto", Stage: func(stage string) { stages = append(stages, stage) }})
	if err != nil || !slices.Contains(stages, "tool file_write") {
		t.Fatalf("local model did not write the sandbox file: stages=%v err=%v", stages, err)
	}
	data, err := os.ReadFile(filepath.Join(root, "notes.txt"))
	if err != nil || strings.TrimSpace(string(data)) != "alpha" {
		t.Fatalf("sandbox file=%q err=%v", data, err)
	}
	if _, err := os.Stat("notes.txt"); !os.IsNotExist(err) {
		t.Fatalf("sandbox write reached the local directory: %v", err)
	}
	stages = nil
	answer, _, _, _, _, _, err := adaptiveAnswer(ctx, nil, cfg, "Run pwd in the sandbox terminal and report the result.",
		enabledRoutes{}, false, AnswerOpts{Agent: "auto", Stage: func(stage string) { stages = append(stages, stage) }})
	if err != nil || !slices.Contains(stages, "tool terminal") || !strings.Contains(answer, "/work") {
		t.Fatalf("local model did not use the sandbox terminal: stages=%v answer=%q err=%v", stages, answer, err)
	}
}

func TestChatWebSearchLocalLLME2E(t *testing.T) {
	if os.Getenv("BLKCHAIN_CHAT_TOOLS_E2E") != "1" {
		t.Skip("set BLKCHAIN_CHAT_TOOLS_E2E=1 with the local stack running")
	}
	authorizeWebTest(t)
	old := webSearch
	t.Cleanup(func() { webSearch = old })
	query := ""
	webSearch = func(_ context.Context, _, q string, _ int, _ []string) ([]retrieval.Result, error) {
		query = q
		return []retrieval.Result{chunk(webSource, "https://owasp.org/current", "Current guidance", "public fixture guidance marker")}, nil
	}
	var stages []string
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	answer, _, _, _, _, _, err := adaptiveAnswer(ctx, nil, loadConfig(),
		"Use web_search to find current public OWASP guidance and report what the tool finds.", enabledRoutes{Web: true}, false,
		AnswerOpts{Agent: "auto", Stage: func(stage string) { stages = append(stages, stage) }})
	if err != nil || query == "" || !slices.Contains(stages, "tool web_search") || !strings.Contains(answer, "fixture guidance marker") {
		t.Fatalf("local model did not use public search: query=%q stages=%v answer=%q err=%v", query, stages, answer, err)
	}
}
