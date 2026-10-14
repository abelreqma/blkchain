package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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

func TestPlainAskAlwaysUsesTheNativeTurn(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	var opts AnswerOpts
	stubAdaptiveAnswer(t, "native plain answer", &opts)

	m := model{cfg: loadConfig(), prefs: loadInteractivePrefs()}
	m.sess, _ = newSession()
	var rc replClient
	defer rc.close()

	ans, err := plainAsk(&m, "what is SSRF?", &rc, nil, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if ans != "native plain answer" {
		t.Fatalf("answer = %q", ans)
	}
	if opts.ToolHost != chatToolHostSandbox {
		t.Fatalf("tool host = %q", opts.ToolHost)
	}
}

// A plain-REPL turn returns its answer so the caller can persist it: the turn
// reaches the JSONL transcript and the history store through recordTurn.
func TestPlainAskTurnPersistsThroughRecordTurn(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "SSRF reaches internal services.", nil)

	m := model{cfg: loadConfig(), hist: histstore.OpenDefault()}
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
	captureStdout(t, func() {
		answer, err = plainAsk(&m, "summarize the SSRF notes", &rc, nil, "", false)
	})
	if err != nil {
		t.Fatalf("plain turn: %v", err)
	}
	if !strings.Contains(answer, "SSRF reaches internal services") {
		t.Fatalf("answer not captured, got %q", answer)
	}

	m.pendingQ = "summarize the SSRF notes"
	if err := m.recordTurn(answer); err != nil {
		t.Fatalf("recordTurn: %v", err)
	}
	turns, err := m.hist.Messages(context.Background(), m.sess.id)
	if err != nil || len(turns) != 2 || turns[1].Content != answer {
		t.Fatalf("turn not in the history store: %v, %v", turns, err)
	}
	replay, err := loadMessages(m.sess.id)
	if err != nil || len(replay) != 2 || replay[1].Content != answer {
		t.Fatalf("turn not in the transcript: %v, %v", replay, err)
	}
}

// The plain REPL records a completed exchange and not a failed one, matching
// the other surfaces: the transcript it writes is read back as memory by a
// later turn in that session.
func TestPlainREPLDoesNotRecordAnErroredTurn(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	t.Chdir(t.TempDir())
	prev := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = prev })
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		if opts.Stream != nil {
			opts.Stream([]byte("partial answer"))
		}
		return "partial answer", nil, false, nil, 1, "rag", errors.New("router exploded")
	}

	input := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(input, []byte("/agent auto\nfailing question\n/quit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	previous := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = previous })
	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			if err := plainREPL(); err != nil {
				t.Fatal(err)
			}
		})
	})
	if !strings.Contains(stdout, "partial answer") {
		t.Fatalf("the partial answer did not reach the operator: %q", stdout)
	}
	if !strings.Contains(stderr, "router exploded") {
		t.Fatalf("the failure was not reported: %q", stderr)
	}
	metas, err := listSessions()
	if err != nil {
		t.Fatal(err)
	}
	for _, meta := range metas {
		if sessionExists(meta.ID) {
			recs, _ := loadMessages(meta.ID)
			t.Fatalf("an errored turn reached the transcript of %s: %+v", meta.ID, recs)
		}
	}
}

// A failed turn's partial answer is not carried into the next turn's memory
// either. It reached the operator's screen, but a later turn that read it back
// would treat a truncated answer as something the model said.
func TestPlainREPLDoesNotRememberAFailedAnswer(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	t.Chdir(t.TempDir())
	prev := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = prev })
	var histories [][]priorTurn
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, question string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		histories = append(histories, slices.Clone(opts.History))
		answer, err := "later answer", error(nil)
		switch question {
		case "failing question":
			answer, err = "partial answer", errors.New("router exploded")
		case "first question":
			answer = "first answer"
		}
		// The plain REPL keeps what streamed, so the stub streams its answer.
		if opts.Stream != nil {
			opts.Stream([]byte(answer))
		}
		return answer, nil, false, nil, 1, "rag", err
	}

	input := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(input, []byte("/agent auto\nfirst question\nfailing question\nnext question\n/quit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	previous := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = previous })
	captureStdout(t, func() {
		captureStderr(t, func() {
			if err := plainREPL(); err != nil {
				t.Fatal(err)
			}
		})
	})
	if len(histories) != 3 {
		t.Fatalf("the router ran %d turns, want 3", len(histories))
	}
	next := histories[2]
	for _, turn := range next {
		if strings.Contains(turn.Content, "partial answer") || strings.Contains(turn.Content, "failing question") {
			t.Fatalf("the next turn's memory carries the failed exchange: %+v", next)
		}
	}
	// The memory is still carried, so the absence above is the failed turn's
	// and not every turn's.
	if !slices.ContainsFunc(next, func(turn priorTurn) bool { return turn.Content == "first answer" }) {
		t.Errorf("the next turn's memory lost the successful exchange: %+v", next)
	}
}

// plainAsk reads the saved /models settings on every turn, so toggling the
// reranker mid-session reaches the cached retrieval client.
func TestPlainAskFollowsTheCurrentRerankPreference(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	prev := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = prev })
	var skips []bool
	adaptiveAnswerFn = func(_ context.Context, rc searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		client, ok := rc.(*retrieval.Client)
		if !ok {
			t.Errorf("the turn received %T, want a retrieval client", rc)
		} else {
			skips = append(skips, client.SkipRerank)
		}
		opts.Stream([]byte("answer"))
		return "answer", nil, false, nil, 1, "rag", nil
	}

	prefs := loadPrefs()
	prefs.Rerank = true
	if err := savePrefs(prefs); err != nil {
		t.Fatal(err)
	}
	m := model{cfg: loadConfig()}
	var err error
	if m.sess, err = newSession(); err != nil {
		t.Fatal(err)
	}
	var rc replClient
	defer rc.close()
	captureStdout(t, func() {
		if _, err := plainAsk(&m, "first question", &rc, nil, "", false); err != nil {
			t.Fatal(err)
		}
	})

	prefs.Rerank = false
	if err := savePrefs(prefs); err != nil {
		t.Fatal(err)
	}
	captureStdout(t, func() {
		if _, err := plainAsk(&m, "second question", &rc, nil, "", false); err != nil {
			t.Fatal(err)
		}
	})
	if len(skips) != 2 || skips[0] || !skips[1] {
		t.Fatalf("rerank skipped per turn = %v, want the second turn to follow the toggle", skips)
	}
}

// The plain turn is bounded like the TUI's: the answer path runs under the
// configured request timeout.
func TestPlainAskBoundsTheTurnByTheRequestTimeout(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	t.Setenv("BLKCHAIN_TIMEOUT_SECONDS", "7")
	prev := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = prev })
	var deadline time.Time
	var bounded bool
	adaptiveAnswerFn = func(ctx context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		deadline, bounded = ctx.Deadline()
		opts.Stream([]byte("answer"))
		return "answer", nil, false, nil, 1, "rag", nil
	}

	m := model{cfg: loadConfig()}
	var rc replClient
	defer rc.close()
	captureStdout(t, func() {
		if _, err := plainAsk(&m, "a question", &rc, nil, "", false); err != nil {
			t.Fatal(err)
		}
	})
	if !bounded {
		t.Fatal("the plain turn ran with no deadline")
	}
	if left := time.Until(deadline); left <= 0 || left > 7*time.Second {
		t.Fatalf("the turn's deadline is %s away, want at most the configured 7s", left)
	}
}

// Finding nothing is not a turn error: the plain turn prints the shared warning
// on stderr and returns no answer.
func TestPlainAskReportsNoResults(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	prev := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = prev })
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, _ AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		return "", nil, false, nil, 0, "", ErrNoResults
	}

	m := model{cfg: loadConfig()}
	var rc replClient
	defer rc.close()
	var answer string
	var err error
	stderr := captureStderr(t, func() {
		captureStdout(t, func() { answer, err = plainAsk(&m, "unanswerable", &rc, nil, "", false) })
	})
	if err != nil {
		t.Fatalf("no results was reported as a turn error: %v", err)
	}
	if answer != "" {
		t.Fatalf("answer = %q, want none", answer)
	}
	if !strings.Contains(stderr, "No relevant sources were found") {
		t.Fatalf("the no-results warning did not reach stderr: %q", stderr)
	}
}

// A bare deadline becomes the one-line timeout error with its advice, rather
// than a raw context message.
func TestPlainAskMapsABareDeadlineToTheTimeoutError(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	prev := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = prev })
	adaptiveAnswerFn = func(_ context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, _ AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		return "", nil, false, nil, 0, "", fmt.Errorf("synthesis: %w", context.DeadlineExceeded)
	}

	m := model{cfg: loadConfig()}
	var rc replClient
	defer rc.close()
	var err error
	captureStdout(t, func() { _, err = plainAsk(&m, "slow question", &rc, nil, "", false) })
	if !errors.Is(err, errRequestTimeout) {
		t.Fatalf("error = %v, want the request-timeout error", err)
	}
}

func TestPlainAskCollectsCallMetricsOnTheClient(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	prev := adaptiveAnswerFn
	adaptiveAnswerFn = func(ctx context.Context, rc searcher, cfg ragconfig.Config, question string, enabled enabledRoutes, force bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		if m, _ := ctx.Value(metricsKey{}).(*callMetrics); m != nil {
			m.mu.Lock()
			m.calls = append(m.calls, llmCallStats{Stage: "synthesis", Status: "ok", UsageReported: true, CompletionTokens: 5})
			m.mu.Unlock()
		}
		return "answer", []citation{}, false, []retrieval.Result{}, 5, "rag", nil
	}
	t.Cleanup(func() { adaptiveAnswerFn = prev })

	m := model{cfg: loadConfig(), prefs: loadInteractivePrefs()}
	m.sess, _ = newSession()
	var rc replClient
	defer rc.close()
	captureStdout(t, func() {
		if _, err := plainAsk(&m, "what is SSRF?", &rc, nil, "", false); err != nil {
			t.Fatal(err)
		}
	})
	calls, _ := rc.metrics.snapshot()
	if len(calls) != 1 || calls[0].CompletionTokens != 5 {
		t.Fatalf("client metrics = %+v, want the turn's synthesis call", calls)
	}
}
