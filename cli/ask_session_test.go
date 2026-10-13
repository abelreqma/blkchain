package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

func TestAskWithoutSessionPersistsNothing(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "stateless answer", nil)

	if _, err := askWith(nil, nil, []string{"what is SSRF?"}); err != nil {
		t.Fatal(err)
	}
	metas, err := listSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 0 {
		t.Fatalf("a bare ask created %d sessions", len(metas))
	}
}

func TestAskSessionFlagPersistsAndContinues(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "first", nil)

	if _, err := askWith(nil, nil, []string{"--session", "new", "q1"}); err != nil {
		t.Fatal(err)
	}
	metas, err := listSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 1 {
		t.Fatalf("ask --session created %d sessions, want 1", len(metas))
	}

	var opts AnswerOpts
	stubAdaptiveAnswer(t, "second", &opts)
	if _, err := askWith(nil, nil, []string{"--session", "last", "q2"}); err != nil {
		t.Fatal(err)
	}
	if len(opts.History) != 2 {
		t.Fatalf("second ask --session carried %d history turns, want 2", len(opts.History))
	}
	after, err := listSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 {
		t.Fatalf("a second ask --session created a new session: %d total", len(after))
	}
}

func TestAskSessionFlagForms(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "first", nil)
	if _, err := askWith(nil, nil, []string{"--session", "new", "q1"}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		args        []string
		wantHistory int
	}{
		{"empty value is the most recent", []string{"--session=", "q2"}, 2},
		{"flag after the question", []string{"q3", "--session", "last"}, 4},
	}
	for _, tc := range cases {
		var opts AnswerOpts
		stubAdaptiveAnswer(t, "answer", &opts)
		if _, err := askWith(nil, nil, tc.args); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(opts.History) != tc.wantHistory {
			t.Fatalf("%s: carried %d history turns, want %d", tc.name, len(opts.History), tc.wantHistory)
		}
	}
	metas, err := listSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 1 {
		t.Fatalf("%d sessions, want 1", len(metas))
	}
}

func TestAskSessionJSONReportsID(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "json answer", nil)

	out := captureStdout(t, func() {
		if _, err := askWith(nil, nil, []string{"--json", "--session", "new", "q"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, `"session_id"`) {
		t.Fatalf("session_id missing from --json output: %s", out)
	}
	out = captureStdout(t, func() {
		if _, err := askWith(nil, nil, []string{"--json", "q"}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "session_id") {
		t.Fatalf("a stateless ask reported a session id: %s", out)
	}
}

func TestAskSessionWithUnknownIDFails(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "unused", nil)

	_, err := askWith(nil, nil, []string{"--session", "20260101T000000-aaaaaa", "q"})
	if err == nil {
		t.Fatal("ask --session with an unknown id was accepted")
	}
	if !errors.Is(err, errSessionNotFound) {
		t.Fatalf("error is not errSessionNotFound: %v", err)
	}
}

func TestAskJSONNoResultsKeepsModel(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	prev := adaptiveAnswerFn
	adaptiveAnswerFn = func(ctx context.Context, rc searcher, cfg ragconfig.Config, question string, enabled enabledRoutes, force bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		return "", nil, false, nil, 0, "", ErrNoResults
	}
	t.Cleanup(func() { adaptiveAnswerFn = prev })

	out := captureStdout(t, func() {
		if _, err := askWith(nil, nil, []string{"--json", "q"}); err != nil {
			t.Fatal(err)
		}
	})
	want := resolveModel(loadConfig())
	if want == "" || !strings.Contains(out, `"model": "`+want+`"`) {
		t.Fatalf("no-results JSON lacks model %q: %s", want, out)
	}
}

func TestAskHermesRejectsSession(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)

	_, err := askWith(nil, nil, []string{"--hermes", "--session", "q"})
	if err == nil {
		t.Fatal("--hermes with --session was accepted")
	}
	if !strings.Contains(err.Error(), "--session") {
		t.Fatalf("error does not name --session: %v", err)
	}
}
