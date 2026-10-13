package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

func TestChatToolHostSelectionReachesCLIAndTUI(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	old := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = old })
	got := ""
	cdp := ""
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		got = opts.ToolHost
		cdp = opts.BrowserCDP
		if opts.Stream != nil {
			opts.Stream([]byte("fixture"))
		}
		return "fixture", nil, false, nil, 0, "skip", nil
	}
	captureStdout(t, func() {
		if _, err := askWith(nil, nil, []string{"--tool-host", "local", "question"}); err != nil {
			t.Fatal(err)
		}
	})
	if got != chatToolHostLocal {
		t.Fatalf("CLI host = %q", got)
	}
	if _, err := askWith(nil, nil, []string{"--tool-host", "other", "question"}); err == nil {
		t.Fatal("invalid CLI tool host accepted")
	}
	captureStdout(t, func() {
		if _, err := askWith(nil, nil, []string{"--browser-cdp", "http://127.0.0.1:9222", "question"}); err != nil {
			t.Fatal(err)
		}
	})
	if cdp != "http://127.0.0.1:9222" {
		t.Fatalf("CLI CDP endpoint = %q", cdp)
	}
	if _, err := askWith(nil, nil, []string{"--browser-cdp", "http://192.0.2.5:9222", "question"}); err == nil {
		t.Fatal("non-loopback CDP endpoint accepted")
	}
	m := model{}
	updated, _ := m.dispatchInput("/tool-host local")
	m = updated.(model)
	if m.toolHost != chatToolHostLocal {
		t.Fatalf("TUI host = %q", m.toolHost)
	}
	updated, _ = m.dispatchInput("/tool-host other")
	if updated.(model).toolHost != chatToolHostLocal {
		t.Fatal("invalid TUI tool host changed the selection")
	}
	if _, ok := slashCommand("tool-host"); !ok {
		t.Fatal("tool-host is missing from interactive command discovery")
	}
	updated, _ = m.dispatchInput("/browser-cdp http://127.0.0.1:9222")
	m = updated.(model)
	if m.browserCDP != "http://127.0.0.1:9222" {
		t.Fatalf("TUI CDP endpoint = %q", m.browserCDP)
	}
	if _, ok := slashCommand("browser-cdp"); !ok {
		t.Fatal("browser-cdp is missing from interactive command discovery")
	}
	client := &replClient{toolHost: chatToolHostLocal, browserCDP: "http://127.0.0.1:9222"}
	defer client.close()
	if _, err := plainAsk(&m, "question", client, nil, "", false); err != nil || got != chatToolHostLocal || cdp != client.browserCDP {
		t.Fatalf("plain host = %q CDP=%q err=%v", got, cdp, err)
	}
	if !strings.Contains(helpResponse("tool-host", 100), "tool-host") {
		t.Fatal("tool-host is missing from interactive help")
	}
}

func TestPlainAskCarriesBrowserCDPToTheTurn(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	old := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = old })
	cdp := "unset"
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		cdp = opts.BrowserCDP
		if opts.Stream != nil {
			opts.Stream([]byte("fixture"))
		}
		return "fixture", nil, false, nil, 0, "skip", nil
	}
	m := model{}
	for _, endpoint := range []string{"http://127.0.0.1:9333", ""} {
		client := &replClient{browserCDP: endpoint}
		cdp = "unset"
		if _, err := plainAsk(&m, "question", client, nil, "", false); err != nil {
			t.Fatal(err)
		}
		client.close()
		if cdp != endpoint {
			t.Fatalf("plain REPL CDP endpoint = %q, want %q", cdp, endpoint)
		}
	}
}
