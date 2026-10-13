package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/askuser"
	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/skillcat"
	tea "github.com/charmbracelet/bubbletea"
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

func TestFormatEngagePaused(t *testing.T) {
	out := formatEngagePaused("Engagement paused: work budget reached.\n\nReport: /tmp/ws/report.md", 2*time.Second, 80)
	if !strings.Contains(out, Glyph(GlyphWarn)) || !strings.Contains(out, "Engagement paused after 2s") || !strings.Contains(out, "work budget reached") || !strings.Contains(out, "/tmp/ws/report.md") || strings.Contains(out, "Engagement complete") {
		t.Fatalf("paused rendering=%q", out)
	}
}

func TestTUIAnomalyDisplaysPausedReport(t *testing.T) {
	noColor(t)
	m := newTestModel(t)
	m.working = true
	_, cmd := m.Update(engageDoneMsg{final: "Report: /tmp/workspace/report.md", err: errEngageDenialBurst, paused: true})
	if cmd == nil {
		t.Fatal("missing TUI result")
	}
	out := fmt.Sprint(cmd())
	if !strings.Contains(out, "Engagement paused") || !strings.Contains(out, "eight gate denials") || !strings.Contains(out, "/tmp/workspace/report.md") {
		t.Fatalf("TUI anomaly output=%q", out)
	}
}

func TestFormatEngageErrorKeepsFinalAssessment(t *testing.T) {
	out := formatEngageError("validated finding", errors.New("report write failed"), 80)
	if !strings.Contains(out, "validated finding") || !strings.Contains(out, "report write failed") || strings.Contains(out, "Report:") {
		t.Fatalf("error rendering=%q", out)
	}
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

func TestEngageCmdCarriesArmRequester(t *testing.T) {
	req := &testArmRequester{decision: ArmSkip}
	stubRunReplEngage(t, func(ctx context.Context, _ string, _ string, _ secgate.Mode, _ bool, _ toolLoopModel, _ searcher, _ ragconfig.Config, _ modelPrefs, _ *skillcat.Catalog, _ secgate.Confirmer, _ askuser.Asker, _ *sql.DB, _ string, _ func(int64, eng.Engagement)) (string, error) {
		if got, _ := ctx.Value(replArmReqKey{}).(ArmRequester); got != req {
			return "", errors.New("arm requester did not reach the engagement")
		}
		return "done", nil
	})
	msg := engageCmd(replEngageRun{ctx: context.Background(), armReq: req})()
	if done, ok := msg.(engageDoneMsg); !ok || done.err != nil {
		t.Fatalf("engagement command=%+v", msg)
	}
}

func TestTUIEngageDispatchWiresArmRequester(t *testing.T) {
	m := engageReadyModel(t)
	m.prog = &tea.Program{}
	stubRunReplEngage(t, func(ctx context.Context, _ string, _ string, _ secgate.Mode, _ bool, _ toolLoopModel, _ searcher, _ ragconfig.Config, _ modelPrefs, _ *skillcat.Catalog, _ secgate.Confirmer, _ askuser.Asker, _ *sql.DB, _ string, _ func(int64, eng.Engagement)) (string, error) {
		req, ok := ctx.Value(replArmReqKey{}).(releaseArmRequester)
		if !ok || req.prog != m.prog {
			return "", errors.New("TUI arm requester did not reach the engagement")
		}
		return "done", nil
	})
	_, cmd := m.dispatchInput("/engage inspect 192.0.2.1")
	if cmd == nil {
		t.Fatal("engagement command was not dispatched")
	}
	var msg tea.Msg = cmd()
	for i := 0; i < 4; i++ {
		batch, ok := msg.(tea.BatchMsg)
		if !ok {
			break
		}
		if len(batch) == 0 {
			t.Fatal("engagement command batch is empty")
		}
		msg = batch[len(batch)-1]()
	}
	if done, ok := msg.(engageDoneMsg); !ok || done.err != nil {
		t.Fatalf("engagement result=%+v", msg)
	}
}

func TestInteractiveEngageCDPFlagsReachTheTUIRun(t *testing.T) {
	input := `--session "roles one.json" --role reader --session-cdp http://127.0.0.1:9223 "assess 127.0.0.1"`
	opts, goal, err := parseInteractiveEngageCDP(input)
	if err != nil || opts.session != "roles one.json" || opts.role != "reader" || opts.sessionCDP != "http://127.0.0.1:9223" || goal != "assess 127.0.0.1" {
		t.Fatalf("interactive CDP flags were lost: opts=%+v goal=%q err=%v", opts, goal, err)
	}
	if _, _, err := parseInteractiveEngageCDP(`resume /tmp/assessment --session roles.json --role reader --session-cdp http://127.0.0.1:9223`); err == nil || !strings.Contains(err.Error(), "use --resume") {
		t.Fatalf("ambiguous TUI resume syntax was accepted: %v", err)
	}
	if _, _, err := parseInteractiveEngageCDP(`--resume /tmp/assessment --session roles.json --role reader --session-cdp http://127.0.0.1:9223`); err != nil {
		t.Fatalf("TUI CDP resume syntax was rejected: %v", err)
	}
	m := engageReadyModel(t)
	next, _ := m.dispatchInput("/engage " + input)
	if !next.(model).working {
		t.Fatal("TUI did not dispatch the signed-in engagement")
	}
	stubRunReplEngage(t, func(ctx context.Context, _ string, _ string, _ secgate.Mode, _ bool, _ toolLoopModel, _ searcher, _ ragconfig.Config, _ modelPrefs, _ *skillcat.Catalog, _ secgate.Confirmer, _ askuser.Asker, _ *sql.DB, _ string, _ func(int64, eng.Engagement)) (string, error) {
		selected, ok := ctx.Value(replCDPKey{}).(engageOpts)
		if !ok || selected.session != opts.session || selected.role != opts.role || selected.sessionCDP != opts.sessionCDP {
			t.Fatalf("TUI engagement context lost CDP role: %+v", selected)
		}
		return "done", nil
	})
	message := engageCmd(replEngageRun{ctx: context.Background(), cdp: &opts})()
	if done, ok := message.(engageDoneMsg); !ok || done.err != nil {
		t.Fatalf("CDP engagement command failed: %+v", message)
	}
}

func TestTUIEngageApprovalUsesOperatorCommandPath(t *testing.T) {
	m := newTestModel(t)
	next, cmd := m.dispatchInput("/engage approve-network")
	m = next.(model)
	if !m.working || m.engageIntake != nil || cmd == nil {
		t.Fatal("network approval entered the model engagement path")
	}
	msg, ok := engageApprovalCmd([]string{"approve-network"})().(engageApprovalDoneMsg)
	if !ok || msg.err == nil {
		t.Fatalf("approval command did not validate its arguments: %+v", msg)
	}
	next, cmd = m.Update(engageApprovalDoneMsg{kind: "approve-network"})
	if next.(model).working || cmd == nil || !strings.Contains(fmt.Sprint(cmd()), "approve-network saved") {
		t.Fatal("approval completion did not return to the TUI")
	}
}

func TestEngageApprovalArgsPreserveQuotedPaths(t *testing.T) {
	args, err := engageApprovalArgs(`approve-cloud-identity --workspace "/tmp/assessment one" --file '/srv/credential files/gcp.json'`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"approve-cloud-identity", "--workspace", "/tmp/assessment one", "--file", "/srv/credential files/gcp.json"}
	if len(args) != len(want) {
		t.Fatalf("args = %v", args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}
	if _, err := engageApprovalArgs(`approve-network --workspace "/tmp/incomplete`); err == nil {
		t.Fatal("unfinished quote was accepted")
	}
}

func TestAttachFootholdUsesOperatorCommandPath(t *testing.T) {
	m := newTestModel(t)
	next, cmd := m.dispatchInput(`/engage attach-foothold --entry '10.7.0.7 transport=command surfaces=local,network,web,ad,container,cloud-aws,cloud-gcp exec=kubectl exec -i fixture --'`)
	if !next.(model).working || next.(model).engageIntake != nil || cmd == nil {
		t.Fatal("foothold attachment entered the model engagement path")
	}
	args, err := engageApprovalArgs(`attach-foothold --entry '10.7.0.7 transport=command surfaces=local,network,web,ad,container,cloud-aws,cloud-gcp exec=kubectl exec -i fixture --'`)
	if err != nil || len(args) != 3 || args[0] != "attach-foothold" || args[1] != "--entry" || !strings.HasSuffix(args[2], "exec -i fixture --") {
		t.Fatalf("attachment args = %v, err=%v", args, err)
	}
}

// buildReplEngageRun captures the goal and the session autonomy mode and builds
// the deps without error.
func TestBuildReplEngageRun(t *testing.T) {
	m := engageReadyModel(t)
	m.engageMode = secgate.Auto

	run, err := m.buildReplEngageRun("assess the host")
	if err != nil {
		t.Fatalf("buildReplEngageRun: %v", err)
	}
	if run.goal != "assess the host" || run.mode != secgate.Auto || run.override {
		t.Fatalf("run = {goal:%q mode:%v override:%v}", run.goal, run.mode, run.override)
	}
	if run.cwd == "" {
		t.Fatalf("run.cwd should be set")
	}
	if run.confirm != nil {
		t.Fatalf("auto must not construct a confirmer, got %T", run.confirm)
	}
}

// An engagement runs on blk's own LLM, so it selects the native model the way a
// grounded turn does. The agent-mode status model names a Hermes gateway model
// and reads "unknown" before one is discovered; neither is a model the oMLX
// server serves, so neither may reach the engagement client.
func TestBuildReplEngageRunSelectsTheNativeModel(t *testing.T) {
	t.Setenv("OMLX_MODEL", "native-model")
	m := engageReadyModel(t)
	m.mode = "agent"
	m.agentModel = "hermes-gateway-model"

	run, err := m.buildReplEngageRun("assess the host")
	if err != nil {
		t.Fatalf("buildReplEngageRun: %v", err)
	}
	client, ok := run.model.(*llmClient)
	if !ok {
		t.Fatalf("run.model = %T, want *llmClient", run.model)
	}
	if client.model != "native-model" {
		t.Errorf("engagement model = %q, want native-model", client.model)
	}

	m.ragModel = "picked-model"
	run, err = m.buildReplEngageRun("assess the host")
	if err != nil {
		t.Fatalf("buildReplEngageRun: %v", err)
	}
	if client, _ := run.model.(*llmClient); client == nil || client.model != "picked-model" {
		t.Errorf("engagement model = %+v, want the model /model picked", client)
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
	var gotGoal, gotWorkspace, gotCwd string
	stubRunReplEngage(t, func(ctx context.Context, wsDir, cwd string, mode secgate.Mode, override bool, model toolLoopModel, rc searcher, cfg ragconfig.Config, prefs modelPrefs, cat *skillcat.Catalog, confirm secgate.Confirmer, asker askuser.Asker, roeDB *sql.DB, goal string, progress func(int64, eng.Engagement)) (string, error) {
		gotGoal = goal
		gotWorkspace, gotCwd = wsDir, cwd
		progress(1, eng.Engagement{Name: "e", ActiveID: "t1"})
		return "engagement summary", nil
	})
	stub := newStubEngagement("e")
	run := replEngageRun{ctx: context.Background(), wsDir: "/tmp/engagement", cwd: "/tmp/project", goal: "recon the scope", stub: stub, asker: askuser.AutoAsker{}}
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
	if gotWorkspace != "/tmp/engagement" || gotCwd != "/tmp/project" {
		t.Fatalf("engage entry got workspace=%q cwd=%q", gotWorkspace, gotCwd)
	}
	if rev, _ := stub.Revision(context.Background()); rev == 0 {
		t.Fatalf("the progress callback should have advanced the live view")
	}
}

func TestTUIResumeDisplaysCheckpointMode(t *testing.T) {
	project, ws := t.TempDir(), t.TempDir()
	roe := filepath.Join(project, "ROE.md")
	if err := os.WriteFile(roe, []byte("## In Scope\n192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRoE(strings.NewReader("## In Scope\n192.0.2.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	c := engageRunMetadata{Goal: "inspect 192.0.2.1", ProjectDir: project, RoE: roe, Mode: "auto", Status: "interrupted", PolicyHash: parsed.Policy.Hash, Started: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := writeEngageMetadata(ws, c); err != nil {
		t.Fatal(err)
	}
	m := engageReadyModel(t)
	m.engageMode = secgate.Safe
	next, _ := m.dispatchInput("/engage resume " + ws)
	got := next.(model)
	if got.engageMode != secgate.Auto || !got.working {
		t.Fatalf("mode=%v working=%t", got.engageMode, got.working)
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

func TestEngageCmdBridgesDiscoveredCredentialOutput(t *testing.T) {
	data := []byte(`{"finding":{"value":"fixture-password"}}`)
	stubRunReplEngage(t, func(ctx context.Context, wsDir, cwd string, mode secgate.Mode, override bool, model toolLoopModel, rc searcher, cfg ragconfig.Config, prefs modelPrefs, cat *skillcat.Catalog, confirm secgate.Confirmer, asker askuser.Asker, roeDB *sql.DB, goal string, progress func(int64, eng.Engagement)) (string, error) {
		sink, ok := ctx.Value(webFindingSinkKey{}).(func([]byte) error)
		if !ok {
			t.Fatal("TUI finding sink missing")
		}
		if err := sink(data); err != nil {
			t.Fatal(err)
		}
		return "complete", nil
	})
	received := ""
	run := replEngageRun{ctx: context.Background(), finding: func(data []byte) error { received = string(data); return nil }}
	done, ok := engageCmd(run)().(engageDoneMsg)
	if !ok || done.err != nil || received != string(data) {
		t.Fatal("credential was lost at TUI engagement boundary")
	}
}
