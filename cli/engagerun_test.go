package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

func testEngageRoE(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ROE.md"), []byte("## In Scope\n192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func stubEngageRunner(t *testing.T) {
	t.Helper()
	previous := newEngageRunnerForRun
	newEngageRunnerForRun = func(context.Context, *RoE) (*engageRunner, error) {
		return &engageRunner{workers: map[string]string{}}, nil
	}
	t.Cleanup(func() { newEngageRunnerForRun = previous })
}

func TestEngageSafeAutoConflict(t *testing.T) {
	err := runEngage([]string{"--safe", "--auto", "assess lab"})
	if err == nil || !strings.Contains(err.Error(), "cannot combine") {
		t.Fatalf("mode conflict not explicit: %v", err)
	}
}

func TestEngageSingleRoERejectsActiveLegacyConfig(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".blkchain"), 0700)
	os.WriteFile(filepath.Join(dir, ".blkchain", "config.yaml"), []byte("denied_binaries: [rm]\n"), 0600)
	os.WriteFile(filepath.Join(dir, "ROE.md"), []byte("## In Scope\n10.20.0.5\n"), 0600)
	_, _, err := loadEngageRoE(engageOpts{}, dir, nil)
	if err == nil || !strings.Contains(err.Error(), "migrate") {
		t.Fatalf("legacy policy was silently discarded: %v", err)
	}
}

func TestEngageSingleRoERejectsEmptyScope(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ROE.md"), []byte("## Summary\nLab\n"), 0600)
	if _, _, err := loadEngageRoE(engageOpts{}, dir, nil); err == nil {
		t.Fatal("empty-scope policy accepted")
	}
}

func TestEngageResumeRetainsUsageEvidenceAndSequence(t *testing.T) {
	previous := newEngageRunnerForRun
	count := 0
	newEngageRunnerForRun = func(context.Context, *RoE) (*engageRunner, error) {
		return &engageRunner{workers: map[string]string{}, runFn: func(context.Context, []pipelineStage, string, int, time.Duration) (runResult, []isolatedStageResult) {
			count++
			quote := fmt.Sprintf("evidence-%d", count)
			return runResult{Output: quote}, []isolatedStageResult{{Stdout: quote}}
		}}, nil
	}
	t.Cleanup(func() { newEngageRunnerForRun = previous })
	workspace, cwd := t.TempDir(), testEngageRoE(t)
	runAction := func(ctx context.Context, d engageDeps, _ string) (string, error) {
		if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Surface: engagement.SurfaceNetwork, Status: engagement.StatusTodo}}}); err != nil {
			return "", err
		}
		tool := newRunCommandTool(d.Gate, 65536, time.Second, t.TempDir(), func() string { return "t1" }, func(id, out string) {
			_, _ = d.Store.RecordEvidence(id, out)
		})
		result, err := tool.Call(ctx, `{"binary":"curl","args":["http://192.0.2.1"]}`)
		if err != nil || !strings.Contains(result, "evidence-") {
			return "", fmt.Errorf("action result=%q err=%v", result, err)
		}
		return "done", nil
	}
	first := engageRunInput{Opts: engageOpts{workspace: workspace}, Cwd: cwd, Goal: "inspect the lab", Run: func(ctx context.Context, d engageDeps, goal string) (string, error) {
		_, err := runAction(ctx, d, goal)
		if err != nil {
			return "", err
		}
		return "paused", errors.New("fixture interruption")
	}}
	if _, err := runEngageSession(context.Background(), first); err == nil || !strings.Contains(err.Error(), "fixture interruption") {
		t.Fatalf("first run did not interrupt: %v", err)
	}
	var before engageRunMetadata
	if err := readEngageMetadata(filepath.Join(workspace, "run.json"), &before); err != nil || before.CommandAttempts != 1 {
		t.Fatalf("first checkpoint=%+v err=%v", before, err)
	}
	if err := stopEngageWorkspace([]string{"--workspace", workspace}); err != nil {
		t.Fatal(err)
	}
	second := engageRunInput{Opts: engageOpts{resume: workspace}, Run: runAction}
	final, err := runEngageSession(context.Background(), second)
	if err != nil || !strings.Contains(final, "Report:") {
		t.Fatalf("resume failed: %q %v", final, err)
	}
	var after engageRunMetadata
	if err := readEngageMetadata(filepath.Join(workspace, "run.json"), &after); err != nil || after.CommandAttempts != 2 || after.PolicyHash != before.PolicyHash || after.Started != before.Started {
		t.Fatalf("resume checkpoint=%+v err=%v", after, err)
	}
	transcript, err := os.ReadFile(filepath.Join(workspace, "actions.jsonl"))
	if err != nil || !strings.Contains(string(transcript), "a-000002") || !strings.Contains(string(transcript), "evidence-1") || !strings.Contains(string(transcript), "evidence-2") {
		t.Fatalf("transcript sequence or bytes lost: %q %v", transcript, err)
	}
	report, err := os.ReadFile(filepath.Join(workspace, "report.json"))
	if err != nil || !strings.Contains(string(report), "evidence-1") || !strings.Contains(string(report), "evidence-2") {
		t.Fatalf("evidence missing from report: %q %v", report, err)
	}
	if _, err := os.Stat(filepath.Join(workspace, "STOP")); !os.IsNotExist(err) {
		t.Fatal("resume did not clear the stop marker")
	}
}

func TestEngageResumeRetainsByteCap(t *testing.T) {
	previous := newEngageRunnerForRun
	runnerCalls := 0
	newEngageRunnerForRun = func(context.Context, *RoE) (*engageRunner, error) {
		return &engageRunner{workers: map[string]string{}, runFn: func(context.Context, []pipelineStage, string, int, time.Duration) (runResult, []isolatedStageResult) {
			runnerCalls++
			return runResult{Output: "12345678"}, []isolatedStageResult{{Stdout: "12345678"}}
		}}, nil
	}
	t.Cleanup(func() { newEngageRunnerForRun = previous })
	cwd, workspace := t.TempDir(), t.TempDir()
	roe := "## In Scope\n192.0.2.1\n## Resource Caps\noutput_bytes: 8\ntotal_bytes: 8\n"
	if err := os.WriteFile(filepath.Join(cwd, "ROE.md"), []byte(roe), 0600); err != nil {
		t.Fatal(err)
	}
	actionCalls := 0
	action := func(ctx context.Context, d engageDeps, _ string) (string, error) {
		actionCalls++
		tool := newRunCommandTool(d.Gate, 65536, time.Second, t.TempDir(), func() string { return "t1" }, nil)
		result, err := tool.Call(ctx, `{"binary":"curl","args":["http://192.0.2.1"]}`)
		if err != nil {
			return "", err
		}
		if actionCalls == 1 && !strings.Contains(result, "12345678") {
			return "", fmt.Errorf("first capture missing: %q", result)
		}
		return result, nil
	}
	if _, err := runEngageSession(context.Background(), engageRunInput{Opts: engageOpts{workspace: workspace}, Cwd: cwd, Goal: "inspect", Run: action}); err != nil {
		t.Fatal(err)
	}
	if runnerCalls != 1 {
		t.Fatalf("first runner calls=%d", runnerCalls)
	}
	final, err := runEngageSession(context.Background(), engageRunInput{Opts: engageOpts{resume: workspace}, Run: action})
	if !errors.Is(err, context.Canceled) || runnerCalls != 1 || !strings.Contains(final, "byte cap reached") {
		t.Fatalf("resumed byte cap lost: calls=%d final=%q err=%v", runnerCalls, final, err)
	}
	var checkpoint engageRunMetadata
	if err := readEngageMetadata(filepath.Join(workspace, "run.json"), &checkpoint); err != nil || checkpoint.Status != "interrupted" || checkpoint.CommandAttempts != 2 {
		t.Fatalf("budget checkpoint=%+v err=%v", checkpoint, err)
	}
}

func TestEngageCorruptResumeDoesNotOverwriteCheckpoint(t *testing.T) {
	stubEngageRunner(t)
	workspace, cwd := t.TempDir(), testEngageRoE(t)
	first := engageRunInput{Opts: engageOpts{workspace: workspace}, Cwd: cwd, Goal: "inspect the lab", Run: func(context.Context, engageDeps, string) (string, error) { return "done", nil }}
	if _, err := runEngageSession(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	runPath := filepath.Join(workspace, "run.json")
	policyPath := filepath.Join(workspace, "policy.json")
	beforeRun, _ := os.ReadFile(runPath)
	beforePolicy, _ := os.ReadFile(policyPath)
	if err := os.WriteFile(filepath.Join(workspace, "actions.jsonl"), []byte("{broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stopEngageWorkspace([]string{"--workspace", workspace}); err != nil {
		t.Fatal(err)
	}
	_, err := runEngageSession(context.Background(), engageRunInput{Opts: engageOpts{resume: workspace}, Run: first.Run})
	if err == nil || !strings.Contains(err.Error(), "transcript checkpoint") {
		t.Fatalf("corrupt checkpoint accepted: %v", err)
	}
	afterRun, _ := os.ReadFile(runPath)
	afterPolicy, _ := os.ReadFile(policyPath)
	if string(beforeRun) != string(afterRun) || string(beforePolicy) != string(afterPolicy) {
		t.Fatal("corrupt resume overwrote policy or run metadata")
	}
	if _, err := os.Stat(filepath.Join(workspace, "STOP")); err != nil {
		t.Fatal("corrupt resume cleared the stop marker")
	}
}

func TestEngageCheckpointRejectsDuplicateJSONFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.json")
	if err := os.WriteFile(path, []byte(`{"goal":"first","goal":"second"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var metadata engageRunMetadata
	if err := readEngageMetadata(path, &metadata); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate checkpoint key accepted: %v", err)
	}
}

func TestEngageCorruptSavedReportKeepsCheckpointAndStop(t *testing.T) {
	stubEngageRunner(t)
	workspace, cwd := t.TempDir(), testEngageRoE(t)
	run := func(context.Context, engageDeps, string) (string, error) { return "done", nil }
	if _, err := runEngageSession(context.Background(), engageRunInput{Opts: engageOpts{workspace: workspace}, Cwd: cwd, Goal: "inspect", Run: run}); err != nil {
		t.Fatal(err)
	}
	runPath := filepath.Join(workspace, "run.json")
	before, _ := os.ReadFile(runPath)
	if err := os.WriteFile(filepath.Join(workspace, "report.json"), []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stopEngageWorkspace([]string{"--workspace", workspace}); err != nil {
		t.Fatal(err)
	}
	if _, err := runEngageSession(context.Background(), engageRunInput{Opts: engageOpts{resume: workspace}, Run: run}); err == nil || !strings.Contains(err.Error(), "prior report") {
		t.Fatalf("corrupt report accepted: %v", err)
	}
	after, _ := os.ReadFile(runPath)
	if string(before) != string(after) {
		t.Fatal("corrupt report overwrote run metadata")
	}
	if _, err := os.Stat(filepath.Join(workspace, "STOP")); err != nil {
		t.Fatal("corrupt report cleared the stop marker")
	}
}

func TestEngageAuditWriteFailureFailsClearly(t *testing.T) {
	stubEngageRunner(t)
	workspace, cwd := t.TempDir(), testEngageRoE(t)
	run := func(ctx context.Context, d engageDeps, _ string) (string, error) {
		if err := os.Mkdir(filepath.Join(workspace, "audit.jsonl"), 0700); err != nil {
			return "", err
		}
		_ = d.Gate.Authorize(ctx, secgate.Command{Binary: "curl", Args: []string{"http://192.0.2.1"}})
		return "done", nil
	}
	_, err := runEngageSession(context.Background(), engageRunInput{Opts: engageOpts{workspace: workspace}, Cwd: cwd, Goal: "inspect the lab", Run: run})
	if err == nil || !strings.Contains(err.Error(), "audit write failed") {
		t.Fatalf("audit failure was hidden: %v", err)
	}
}

func TestEngageRunnerSetupFailureLeavesWorkspaceEmpty(t *testing.T) {
	previous := newEngageRunnerForRun
	newEngageRunnerForRun = func(context.Context, *RoE) (*engageRunner, error) {
		return nil, errors.New("runner image missing")
	}
	t.Cleanup(func() { newEngageRunnerForRun = previous })
	workspace := t.TempDir()
	_, err := runEngageSession(context.Background(), engageRunInput{Opts: engageOpts{workspace: workspace}, Cwd: testEngageRoE(t), Goal: "inspect the lab"})
	if err == nil || !strings.Contains(err.Error(), "runner image missing") {
		t.Fatalf("runner setup failure hidden: %v", err)
	}
	entries, err := os.ReadDir(workspace)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed setup wrote operator workspace: %v %v", entries, err)
	}
}

func TestEngageResumeRejectsSymlinkedLock(t *testing.T) {
	stubEngageRunner(t)
	workspace, cwd := t.TempDir(), testEngageRoE(t)
	run := func(context.Context, engageDeps, string) (string, error) { return "done", nil }
	if _, err := runEngageSession(context.Background(), engageRunInput{Opts: engageOpts{workspace: workspace}, Cwd: cwd, Goal: "inspect", Run: run}); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "operator-file")
	if err := os.WriteFile(victim, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(workspace, "running.lock")
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, lock); err != nil {
		t.Fatal(err)
	}
	if _, err := runEngageSession(context.Background(), engageRunInput{Opts: engageOpts{resume: workspace}, Run: run}); err == nil || !strings.Contains(err.Error(), "running lock") {
		t.Fatalf("symlinked lock accepted: %v", err)
	}
	content, err := os.ReadFile(victim)
	if err != nil || string(content) != "preserve" {
		t.Fatalf("operator file changed: %q %v", content, err)
	}
}

func TestEngageStopCancelsLiveRun(t *testing.T) {
	stubEngageRunner(t)
	workspace, cwd := t.TempDir(), testEngageRoE(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := runEngageSession(ctx, engageRunInput{Opts: engageOpts{workspace: workspace}, Cwd: cwd, Goal: "inspect the lab", Run: func(ctx context.Context, _ engageDeps, _ string) (string, error) {
			<-ctx.Done()
			return "", ctx.Err()
		}})
		done <- err
	}()
	ready := false
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(filepath.Join(workspace, "run.json")); err == nil {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("live run did not create a checkpoint")
	}
	if err := stopEngageWorkspace([]string{"--workspace", workspace}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stop did not cancel the run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not terminate the run")
	}
	var checkpoint engageRunMetadata
	if err := readEngageMetadata(filepath.Join(workspace, "run.json"), &checkpoint); err != nil || checkpoint.Status != "stopped" {
		t.Fatalf("stopped status=%+v err=%v", checkpoint, err)
	}
}

func TestEngageWebDecisionsReachTranscriptAndReport(t *testing.T) {
	stubEngageRunner(t)
	workspace, cwd := t.TempDir(), testEngageRoE(t)
	run := func(ctx context.Context, d engageDeps, _ string) (string, error) {
		if decision := d.Gate.AuthorizeAPIRequest(ctx, secgate.APIRequest{Method: "GET", URL: "https://192.0.2.1/read"}); !decision.Allowed {
			return "", fmt.Errorf("permitted API read denied: %+v", decision)
		}
		if decision := d.Gate.AuthorizeAPIRequest(ctx, secgate.APIRequest{Method: "POST", URL: "https://192.0.2.1/write"}); decision.Allowed {
			return "", errors.New("unlisted API write allowed")
		}
		if decision := d.Gate.AuthorizeWebRedirect("https://198.51.100.2/elsewhere"); decision.Allowed {
			return "", errors.New("out-of-scope redirect allowed")
		}
		return "done", nil
	}
	if _, err := runEngageSession(context.Background(), engageRunInput{Opts: engageOpts{workspace: workspace}, Cwd: cwd, Goal: "inspect the lab", Run: run}); err != nil {
		t.Fatal(err)
	}
	transcript, err := os.ReadFile(filepath.Join(workspace, "actions.jsonl"))
	if err != nil || !strings.Contains(string(transcript), `"status":"allowed"`) || !strings.Contains(string(transcript), `"status":"denied"`) || !strings.Contains(string(transcript), "192.0.2.1/read") || !strings.Contains(string(transcript), "198.51.100.2") {
		t.Fatalf("web decisions missing: %q %v", transcript, err)
	}
	report, err := os.ReadFile(filepath.Join(workspace, "report.json"))
	var saved struct {
		Status  string `json:"status"`
		Denials []struct {
			Action string `json:"action"`
		} `json:"denials"`
	}
	if err == nil {
		err = json.Unmarshal(report, &saved)
	}
	if err != nil || saved.Status != "complete" || len(saved.Denials) < 2 {
		t.Fatalf("report missing or incomplete: %q %v", report, err)
	}
	markdown, err := os.ReadFile(filepath.Join(workspace, "report.md"))
	if err != nil || !strings.Contains(string(markdown), "## Policy denials") || !strings.Contains(string(markdown), "deny:roe-action") {
		t.Fatalf("denials missing from Markdown report: %q %v", markdown, err)
	}
}
