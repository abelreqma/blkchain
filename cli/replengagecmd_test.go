package main

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"blkchain/cli/internal/askuser"
	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/skillcat"
)

// engageReadyModel is a model whose engage dependencies build cleanly: a real
// config, a retrieval client (retrieval.New does not dial), and an empty skills
// dir. It mirrors the fields initialModel sets that buildReplEngageRun needs.
func engageReadyModel(t *testing.T) model {
	t.Helper()
	t.Setenv("BLKCHAIN_SKILLS_DIR", t.TempDir())
	m := newTestModel(t)
	m.cfg = loadConfig()
	rc, err := newRetrievalClient(m.cfg)
	if err != nil {
		t.Fatalf("retrieval client: %v", err)
	}
	m.rc = rc
	return m
}

// stubRunReplEngage swaps the injectable engage entry for a test and restores it.
func stubRunReplEngage(t *testing.T, fn func(ctx context.Context, wsDir, cwd string, mode secgate.Mode, override bool, model toolLoopModel, rc searcher, cfg ragconfig.Config, prefs modelPrefs, cat *skillcat.Catalog, confirm secgate.Confirmer, asker askuser.Asker, roeDB *sql.DB, goal string, progress func(int64, eng.Engagement)) (string, error)) {
	t.Helper()
	orig := runReplEngageFn
	t.Cleanup(func() { runReplEngageFn = orig })
	runReplEngageFn = fn
}

// A blank goal is rejected without starting a turn; a real goal starts a turn and
// wires a live engagement view for the DAG + bar.
func TestEngageDispatchStartsTurn(t *testing.T) {
	stubRunReplEngage(t, func(ctx context.Context, wsDir, cwd string, mode secgate.Mode, override bool, model toolLoopModel, rc searcher, cfg ragconfig.Config, prefs modelPrefs, cat *skillcat.Catalog, confirm secgate.Confirmer, asker askuser.Asker, roeDB *sql.DB, goal string, progress func(int64, eng.Engagement)) (string, error) {
		return "", nil
	})
	m := engageReadyModel(t)

	nm, _ := m.dispatchInput("/engage")
	if nm.(model).working {
		t.Fatalf("a blank goal must not start a turn")
	}

	nm, _ = m.dispatchInput("/engage enumerate 10.0.0.5")
	m = nm.(model)
	if !m.working {
		t.Fatalf("a goal should start a turn")
	}
	if _, ok := m.engagement.(*stubEngagement); !ok {
		t.Fatalf("/engage should wire a live engagement view, got %T", m.engagement)
	}
	if m.cancel == nil {
		t.Fatalf("/engage should set a cancel for the turn")
	}
	if !strings.Contains(m.workingVerb, "engag") {
		t.Fatalf("working verb = %q; want an engage label", m.workingVerb)
	}
}

// buildReplEngageRun captures the goal and the session autonomy mode and builds
// the deps without error.
func TestBuildReplEngageRun(t *testing.T) {
	m := engageReadyModel(t)
	m.engageMode, m.engageOverride = secgate.Auto, true

	run, err := m.buildReplEngageRun("assess the host")
	if err != nil {
		t.Fatalf("buildReplEngageRun: %v", err)
	}
	if run.goal != "assess the host" || run.mode != secgate.Auto || !run.override {
		t.Fatalf("run = {goal:%q mode:%v override:%v}", run.goal, run.mode, run.override)
	}
	if run.cwd == "" {
		t.Fatalf("run.cwd should be set")
	}
	if _, ok := run.confirm.(widgetConfirmer); !ok {
		t.Fatalf("run.confirm should be the widget confirmer, got %T", run.confirm)
	}
}

// A retrieval-client error aborts /engage before a turn starts (mirrors blk engage).
func TestEngageDispatchReportsRetrievalError(t *testing.T) {
	m := newTestModel(t)
	m.rcErr = context.DeadlineExceeded
	nm, _ := m.dispatchInput("/engage do a thing")
	if nm.(model).working {
		t.Fatalf("a retrieval error must not start a turn")
	}
}

// engageCmd invokes the injected engage entry and bridges its progress snapshots
// to the live view; the result comes back as an engageDoneMsg.
func TestEngageCmdInvokesRunAndBridgesProgress(t *testing.T) {
	var gotGoal string
	stubRunReplEngage(t, func(ctx context.Context, wsDir, cwd string, mode secgate.Mode, override bool, model toolLoopModel, rc searcher, cfg ragconfig.Config, prefs modelPrefs, cat *skillcat.Catalog, confirm secgate.Confirmer, asker askuser.Asker, roeDB *sql.DB, goal string, progress func(int64, eng.Engagement)) (string, error) {
		gotGoal = goal
		progress(1, eng.Engagement{Name: "e", ActiveID: "t1"})
		return "engagement summary", nil
	})
	stub := newStubEngagement("e")
	run := replEngageRun{ctx: context.Background(), goal: "recon the scope", stub: stub, asker: askuser.AutoAsker{}}
	msg := engageCmd(run)()
	done, ok := msg.(engageDoneMsg)
	if !ok {
		t.Fatalf("engageCmd should return an engageDoneMsg, got %T", msg)
	}
	if done.err != nil || done.final != "engagement summary" {
		t.Fatalf("done = %+v", done)
	}
	if gotGoal != "recon the scope" {
		t.Fatalf("engage entry got goal %q", gotGoal)
	}
	if rev, _ := stub.Revision(context.Background()); rev == 0 {
		t.Fatalf("the progress callback should have advanced the live view")
	}
}

// engageDoneMsg ends the turn: it clears working and the turn cancel, and prints
// the final summary.
func TestEngageDoneMsgEndsTurn(t *testing.T) {
	m := newTestModel(t)
	m.working = true
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	nm, cmd := m.Update(engageDoneMsg{final: "all enumerated"})
	m = nm.(model)
	if m.working {
		t.Fatalf("engageDoneMsg should end the turn")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatalf("engageDoneMsg should cancel the turn context")
	}
	if cmd == nil {
		t.Fatalf("engageDoneMsg should print the result")
	}
}

// formatEngageDone shows a done marker and the final summary.
func TestFormatEngageDone(t *testing.T) {
	noColor(t)
	out := formatEngageDone("found an open SSH port", 0, 80)
	if !strings.Contains(out, "found an open SSH port") {
		t.Fatalf("formatEngageDone dropped the summary: %q", out)
	}
}
