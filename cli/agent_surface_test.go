package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

func TestCLIAgentFlagReachesAllAskOutputModes(t *testing.T) {
	useDeadServices(t)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HERMES_HOME", t.TempDir())
	isolateUserDirs(t)
	previous := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = previous })
	var choices []string
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		choices = append(choices, opts.Agent)
		if opts.Persona != nil {
			opts.Persona("cloud")
		}
		if opts.Stream != nil {
			opts.Stream([]byte("fixture answer"))
		}
		return "fixture answer", nil, false, nil, 1, "skip", nil
	}
	for _, args := range [][]string{{"--agent", "cloud", "a question"}, {"a question", "--agent", "cloud", "--json"}, {"--sources", "--agent", "cloud", "a question"}} {
		out := captureStdout(t, func() {
			if _, err := askWith(nil, nil, args); err != nil {
				t.Fatal(err)
			}
		})
		if strings.Contains(strings.Join(args, " "), "--json") && !strings.Contains(out, `"agent": "cloud"`) && !strings.Contains(out, `"agent":"cloud"`) {
			t.Fatalf("JSON omits actual specialist: %s", out)
		}
	}
	if len(choices) != 3 {
		t.Fatal("missing output path")
	}
	for _, choice := range choices {
		if choice != "cloud" {
			t.Fatalf("CLI lost choice: %q", choice)
		}
	}
}

func TestPlainAgentSelectionAndAutoReachNativeAnswers(t *testing.T) {
	useDeadServices(t)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HERMES_HOME", t.TempDir())
	isolateUserDirs(t)
	t.Chdir(t.TempDir())
	previous := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = previous })
	var choices []string
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		choices = append(choices, opts.Agent)
		if opts.Stream != nil {
			opts.Stream([]byte("fixture answer"))
		}
		return "fixture answer", nil, false, nil, 1, "skip", nil
	}
	input := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(input, []byte("/agent cloud\nfirst question\n/agent invalid\nsecond question\n/agent auto\nthird question\n/quit\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	previousInput := os.Stdin
	os.Stdin = file
	t.Cleanup(func() { os.Stdin = previousInput })
	captureStdout(t, func() {
		captureStderr(t, func() {
			if err := plainREPL(); err != nil {
				t.Fatal(err)
			}
		})
	})
	if len(choices) != 3 || choices[0] != "cloud" || choices[1] != "cloud" || choices[2] != "" {
		t.Fatalf("plain selection differs from CLI: %v", choices)
	}
}

func TestTUIAgentChoiceCapturedByAnswerCommand(t *testing.T) {
	useDeadServices(t)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HERMES_HOME", t.TempDir())
	m := newKeyModel(t)
	m.answerAgent = "cloud"
	m.ragModel = "sample-model"
	previous := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = previous })
	var choice string
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		choice = opts.Agent
		return "fixture answer", nil, false, nil, 1, "skip", nil
	}
	cmd := m.streamCmd(context.Background(), "a question", "", m.turnStart, false)
	m.answerAgent = "api"
	cmd()
	if choice != "cloud" {
		t.Fatalf("active command lost its captured specialist: %q", choice)
	}
}

func TestInvalidCLIAgentDoesNotReachAnyBackend(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HERMES_HOME", t.TempDir())
	previous := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = previous })
	calls := 0
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, _ AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		calls++
		return "", nil, false, nil, 0, "", nil
	}
	for _, args := range [][]string{{"--agent", "invalid", "question"}, {"--agent", "auto", "--hermes", "question"}, {"--agent", "cloud", "--hermes", "question"}} {
		_, err := askWith(nil, nil, args)
		if _, ok := err.(*usageError); !ok {
			t.Fatalf("expected usage error before backend: %v", err)
		}
	}
	if calls != 0 {
		t.Fatal("invalid choice started a backend")
	}
}

func TestTUIGenerateCapturesSelectedAnswerAgent(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.answerAgent = "api"
	m.ragModel = "sample-model"
	previous := synthFromResultsFn
	t.Cleanup(func() { synthFromResultsFn = previous })
	var choice string
	synthFromResultsFn = func(_ context.Context, _ ragconfig.Config, _ string, _ []retrieval.Result, opts AnswerOpts) (string, []citation, int, error) {
		choice = opts.Agent
		return "fixture", nil, 1, nil
	}
	cmd := m.generateCmd(context.Background(), "question", nil, m.turnStart)
	m.answerAgent = "cloud"
	cmd()
	if choice != "api" {
		t.Fatalf("generate lost captured specialist: %q", choice)
	}
}

func TestIncompatibleBackendsFailBeforeContextRead(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HERMES_HOME", t.TempDir())
	for _, flags := range [][]string{{"--hermes", "--rag"}, {"--hermes", "--web"}, {"--rag", "--web"}} {
		args := append(append([]string(nil), flags...), "--context", "missing-context-file", "question")
		_, err := askWith(nil, nil, args)
		if _, ok := err.(*usageError); !ok {
			t.Fatalf("mixed backends touched context or dispatched: %v", err)
		}
	}
}

func TestPlainWebSearchCarriesSelectedSpecialist(t *testing.T) {
	useDeadServices(t)
	authorizeWebTest(t)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HERMES_HOME", t.TempDir())
	t.Setenv("OMLX_MODEL", "fixture-model")
	t.Setenv("OMLX_API_KEY", "fixture-key")
	t.Setenv(webProviderEnv, "duckduckgo")
	t.Chdir(t.TempDir())
	previousSearch := webSearch
	t.Cleanup(func() { webSearch = previousSearch })
	webSearch = func(context.Context, string, string, int, []string) ([]retrieval.Result, error) {
		return []retrieval.Result{searchResult("fixture", "https://example.test/settings", "documented configuration", 0)}, nil
	}
	systems := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct{ Role, Content string }
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		for _, message := range body.Messages {
			if message.Role == "system" {
				systems <- message.Content
			}
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"fixture [1]\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()
	t.Setenv("OMLX_BASE_URL", srv.URL)
	input := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(input, []byte("/agent cloud\n/web search explain settings\n/quit\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	previousInput := os.Stdin
	os.Stdin = file
	t.Cleanup(func() { os.Stdin = previousInput })
	out := captureStdout(t, func() {
		if err := plainREPL(); err != nil {
			t.Fatal(err)
		}
	})
	hasPrompt := strings.Contains(<-systems, "AWS, Azure, and GCP")
	hasCue := strings.Contains(out, "answering as cloud security expert")
	if !hasPrompt || !hasCue {
		t.Fatalf("plain web ignored specialist: prompt=%v cue=%v", hasPrompt, hasCue)
	}
}
