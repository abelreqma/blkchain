package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
	plain := &replClient{agent: "auto"}
	defer plain.close()
	before := hits.Load()
	answer, err = plainAsk(&model{}, "rag", question, plain, nil, "", false)
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
	if err != nil || requests.Load() <= before || !slices.Contains(stages, "tool web_browser") || !strings.Contains(answer, "fixture receipt") {
		t.Fatalf("local model did not use the native browser: route=%s requests=%d stages=%v answer=%q err=%v", route, requests.Load()-before, stages, answer, err)
	}
	stages = nil
	answer, _, _, _, _, route, err = adaptiveAnswer(ctx, rc, cfg, "Read go.mod from the current working directory and tell me its module path.", enabledRoutes{Local: true, Web: true}, false, AnswerOpts{Agent: "auto", WebFirst: true, Stage: func(stage string) { stages = append(stages, stage) }})
	if err != nil || !slices.Contains(stages, "tool file_read") || !strings.Contains(answer, "blkchain/cli") {
		t.Fatalf("local model did not use file_read: route=%s stages=%v answer=%q err=%v", route, stages, answer, err)
	}
}
