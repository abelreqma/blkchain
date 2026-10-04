package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

func TestWebCommandPermissionAndProvider(t *testing.T) {
	isolateUserDirs(t)
	t.Setenv(webProviderEnv, "")
	if defaultPrefs().Web || loadPrefs().Web {
		t.Fatal("fresh install authorizes web")
	}
	var err error
	out := captureStdout(t, func() { err = runWeb([]string{"on"}) })
	if err != nil || !loadPrefs().Web || !strings.Contains(out, "web on") {
		t.Fatalf("on: %q %v %+v", out, err, loadPrefs())
	}
	captureStdout(t, func() { err = runWeb([]string{"provider", "duckduckgo"}) })
	if err != nil || loadPrefs().WebProvider != webProviderDuckDuckGo {
		t.Fatalf("provider: %v %+v", err, loadPrefs())
	}
	captureStdout(t, func() { err = runWeb([]string{"off"}) })
	if err != nil || loadPrefs().Web {
		t.Fatal("off did not revoke permission")
	}
	if err = runWeb([]string{"provider", "bogus"}); err == nil {
		t.Fatal("unknown provider accepted")
	}
}

func TestExplicitWebSearchDoesNotPersistPermission(t *testing.T) {
	isolateUserDirs(t)
	t.Setenv(webProviderEnv, "duckduckgo")
	p := defaultPrefs()
	p.Web = true
	if err := savePrefs(p); err != nil {
		t.Fatal(err)
	}
	original := webSearch
	webSearch = func(_ context.Context, _, query string, limit int, _ []string) ([]retrieval.Result, error) {
		if query != "query" || limit != 2 {
			t.Fatalf("query %q limit %d", query, limit)
		}
		return []retrieval.Result{searchResult("title", "https://example.com/x", "body", 0)}, nil
	}
	defer func() { webSearch = original }()
	var err error
	out := captureStdout(t, func() { err = runWeb([]string{"search", "--json", "--top-k", "2", "query"}) })
	if err != nil || !strings.Contains(out, `"source": "web"`) || !loadPrefs().Web {
		t.Fatalf("search: %q %v web=%v", out, err, loadPrefs().Web)
	}
}

func TestWebOnlyAnswerSkipsLocalAndGrading(t *testing.T) {
	authorizeWebTest(t)
	t.Setenv(webProviderEnv, "duckduckgo")
	srv := fakeLLM(t, []string{"not a grade"}, "Answer [1].")
	defer srv.Close()
	t.Setenv("OMLX_BASE_URL", srv.URL+"/v1")
	original := webSearch
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		return []retrieval.Result{searchResult("source", "https://example.com/x", "evidence", 0)}, nil
	}
	defer func() { webSearch = original }()
	ans, cits, used, _, _, route, err := adaptiveAnswer(context.Background(), nil, answerCfg(2), "query", enabledRoutes{}, false, AnswerOpts{WebOnly: true})
	if err != nil || ans != "Answer [1]." || !used || route != "web" || len(cits) != 1 || !cits[0].Untrusted {
		t.Fatalf("answer %q cits %+v used %v route %s err %v", ans, cits, used, route, err)
	}
}

func TestWebControlsInTUI(t *testing.T) {
	m := newKeyModel(t)
	t.Setenv(webProviderEnv, "duckduckgo")
	var out string
	m, out = tuiSlash(t, m, "/web on")
	if !m.prefs.Web || !loadPrefs().Web || !strings.Contains(out, "web on") {
		t.Fatalf("on: %q %+v", out, m.prefs)
	}
	m, out = tuiSlash(t, m, "/web provider auto")
	if m.prefs.WebProvider != "auto" || !strings.Contains(out, "web provider auto") {
		t.Fatalf("provider: %q %+v", out, m.prefs)
	}
	m, out = tuiSlash(t, m, "/web off")
	if m.prefs.Web || loadPrefs().Web || !strings.Contains(out, "web off") {
		t.Fatalf("off: %q %+v", out, m.prefs)
	}
}

func TestWebSearchTUIDispatchAndQueue(t *testing.T) {
	m := newKeyModel(t)
	p := defaultPrefs()
	p.Web = true
	if err := savePrefs(p); err != nil {
		t.Fatal(err)
	}
	srv := fakeLLM(t, []string{`{"sufficient":true}`}, "Reasoned web answer [1].")
	defer srv.Close()
	t.Setenv("OMLX_BASE_URL", srv.URL+"/v1")
	t.Setenv(webProviderEnv, "duckduckgo")
	original := webSearch
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		return []retrieval.Result{searchResult("source", "https://example.com/x", "evidence", 0)}, nil
	}
	defer func() { webSearch = original }()
	m.ta.SetValue("/web search query")
	nm, cmd := m.submit()
	m = nm.(model)
	if !m.working {
		t.Fatal("web search did not start a turn")
	}
	found := false
	for _, msg := range drain(cmd) {
		if result, ok := msg.(webAnswerMsg); ok {
			found = true
			if len(result.results) != 1 || result.results[0].Payload.Source != webSource {
				t.Fatalf("result %+v", result)
			}
			updated, synthesis := m.Update(msg)
			m = updated.(model)
			done, ok := synthesis().(streamDoneMsg)
			if !ok || done.full != "Reasoned web answer [1]." || !done.usedWeb {
				t.Fatalf("web search did not synthesize: %+v", done)
			}
			updated, _ = m.Update(done)
			m = updated.(model)
		}
	}
	if !found || len(m.lastResults) != 1 || !loadPrefs().Web {
		t.Fatalf("found %v results %+v prefs %+v", found, m.lastResults, loadPrefs())
	}
	m.working = true
	m.ta.SetValue("/web search second query")
	updated, _ := m.submit()
	if len(updated.(model).queue) != 1 {
		t.Fatal("web search did not queue while busy")
	}
}

func TestAskWebFlagUsesSavedPermission(t *testing.T) {
	authorizeWebTest(t)
	t.Setenv(webProviderEnv, "duckduckgo")
	original := adaptiveAnswerFn
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		if !opts.WebOnly || opts.NoWeb {
			t.Fatalf("opts = %+v", opts)
		}
		return "answer", []citation{}, true, nil, 0, "web", nil
	}
	defer func() { adaptiveAnswerFn = original }()
	var err error
	captureStdout(t, func() { err = runAsk([]string{"--web", "--json", "query"}) })
	if err != nil || !loadPrefs().Web {
		t.Fatalf("err %v prefs %+v", err, loadPrefs())
	}
	m := newKeyModel(t)
	p := defaultPrefs()
	p.Web = true
	if err := savePrefs(p); err != nil {
		t.Fatal(err)
	}
	m, _ = tuiSlash(t, m, "/ask --web query")
	if !loadPrefs().Web {
		t.Fatal("interactive answer persisted permission")
	}
}

func TestAutomaticWebRequiresPermissionEvenWithKey(t *testing.T) {
	isolateUserDirs(t)
	t.Setenv(webProviderEnv, "tavily")
	t.Setenv("TAVILY_API_KEY", "test-key")
	srv := fakeLLM(t, []string{`{"sufficient":false,"use_web":true}`}, "Local answer [1].")
	defer srv.Close()
	t.Setenv("OMLX_BASE_URL", srv.URL+"/v1")
	original := webSearch
	called := false
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		called = true
		return nil, nil
	}
	defer func() { webSearch = original }()
	_, _, used, _, _, err := AnswerLoop(context.Background(), fakeSearcher{[]retrieval.Result{chunk("local", "local.md", "Local", "evidence")}}, answerCfg(1), "query", AnswerOpts{})
	if err != nil || called || used {
		t.Fatalf("err %v called %v used %v", err, called, used)
	}
}

func TestWebSearchQueuesWhenFlagsPrecedeAction(t *testing.T) {
	m := newKeyModel(t)
	m.working = true
	m.ta.SetValue("/web --top-k 2 search query")
	updated, _ := m.submit()
	if len(updated.(model).queue) != 1 {
		t.Fatal("web search with leading flags did not queue")
	}
}

func TestWebSearchJSONInTUI(t *testing.T) {
	m := newKeyModel(t)
	p := defaultPrefs()
	p.Web = true
	if err := savePrefs(p); err != nil {
		t.Fatal(err)
	}
	original := webSearch
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		return []retrieval.Result{searchResult("source", "https://example.com/x", "evidence", 0)}, nil
	}
	defer func() { webSearch = original }()
	updated, cmd := m.dispatchInput("/web search --json query")
	m = updated.(model)
	found := false
	for _, msg := range drain(cmd) {
		if _, ok := msg.(searchMsg); ok {
			_, output := m.Update(msg)
			for _, printed := range drain(output) {
				if strings.Contains(fmt.Sprint(printed), `"source": "web"`) {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("TUI ignored JSON output flag")
	}
}

func TestWebOffBlocksExplicitSearchAndWebAnswer(t *testing.T) {
	isolateUserDirs(t)
	original := webSearch
	defer func() { webSearch = original }()
	called := false
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		called = true
		return []retrieval.Result{searchResult("s", "https://example.com", "body", 0)}, nil
	}
	if _, err := webSearchResults(context.Background(), webCommand{action: "search", value: "q", topK: 5}); err == nil {
		t.Error("explicit search bypassed web off")
	}
	if _, _, _, _, _, err := AnswerLoop(context.Background(), nil, answerCfg(1), "q", AnswerOpts{WebOnly: true}); err == nil {
		t.Error("web-only answer bypassed web off")
	}
	if called {
		t.Error("web off made a provider request")
	}
}

func TestCombinedWebCommandsKeepBothSurfaces(t *testing.T) {
	isolateUserDirs(t)
	workspace, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := workspace.Dir
	if err := workspace.Close(); err != nil {
		t.Fatal(err)
	}
	var commandErr error
	output := captureStdout(t, func() { commandErr = runWeb([]string{"inspect", "--workspace", directory, "--no-rdns", "--json"}) })
	if commandErr != nil || !strings.Contains(output, `"operations"`) {
		t.Fatalf("analysis dispatch: %q %v", output, commandErr)
	}
	output = captureStdout(t, func() { commandErr = runWeb([]string{"status", "--json"}) })
	if commandErr != nil || !strings.Contains(output, `"enabled": false`) {
		t.Fatalf("search status: %q %v", output, commandErr)
	}
	m := newKeyModel(t)
	_, command := m.dispatchInput("/web inspect --workspace " + directory + " --no-rdns --json")
	found := false
	for _, message := range drain(command) {
		if done, ok := message.(webDoneMsg); ok {
			found = done.Err == nil && strings.Contains(done.Output, `"operations"`)
		}
	}
	if !found {
		t.Fatal("TUI did not dispatch the analysis command")
	}
	for _, test := range []struct {
		args   []string
		search bool
	}{
		{[]string{"--top-k", "2", "search", "query"}, true},
		{[]string{"--workspace", directory, "--no-rdns"}, false},
		{[]string{"collect", "fixture.test"}, false},
		{[]string{"provider", "duckduckgo"}, true},
	} {
		if got := webIsSearchCommand(test.args); got != test.search {
			t.Fatalf("dispatch %v = %v", test.args, got)
		}
	}
}
