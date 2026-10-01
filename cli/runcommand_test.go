package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"blkchain/cli/internal/secgate"
)

// stubbed execRunner for hermetic tests.
func withStubExec(t *testing.T, fn func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult) {
	t.Helper()
	prev := execRunner
	execRunner = fn
	t.Cleanup(func() { execRunner = prev })
}

// stubbed execPipeline for hermetic tests.
func withStubPipeline(t *testing.T, fn func(ctx context.Context, stages []pipelineStage, dir string, capBytes int, timeout time.Duration) runResult) {
	t.Helper()
	prev := execPipeline
	execPipeline = fn
	t.Cleanup(func() { execPipeline = prev })
}

func autoGate(t *testing.T) *secgate.Gate {
	t.Helper()
	s, err := secgate.ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &secgate.Gate{Mode: secgate.Auto, Scope: s, Allow: secgate.NewAllowlist("nmap", "curl")}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	return g
}

// countingConfirmer records Confirm calls and returns ok.
type countingConfirmer struct {
	ok    bool
	calls atomic.Int32
}

func (c *countingConfirmer) Confirm(ctx context.Context, cmd secgate.Command) bool {
	c.calls.Add(1)
	return c.ok
}

// safeLocalGate builds a Safe-mode gate on a local scope with the given
// confirmer, so pipeline stages of ordinary binaries pass the deny-layers and
// confirmation is exercised.
func safeLocalGate(t *testing.T, confirm secgate.Confirmer) *secgate.Gate {
	t.Helper()
	s, err := secgate.ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &secgate.Gate{Mode: secgate.Safe, Scope: s, Confirm: confirm, Approvals: secgate.NewSessionApprovals()}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	return g
}

const threeStagePipeline = `{"pipeline":[{"binary":"id"},{"binary":"grep","args":["uid"]},{"binary":"head","args":["-n","1"]}]}`

// TestRunCommandPipelineConfirmsOnce: a /safe 3-stage pipeline whose stages all
// pass the deny-layers prompts the human EXACTLY once, not once per stage, then
// runs.
func TestRunCommandPipelineConfirmsOnce(t *testing.T) {
	cc := &countingConfirmer{ok: true}
	callCount := 0
	withStubPipeline(t, func(ctx context.Context, stages []pipelineStage, dir string, capBytes int, timeout time.Duration) runResult {
		callCount++
		return runResult{Output: "a"}
	})
	g := safeLocalGate(t, cc)
	tool := newRunCommandTool(g, 1000, time.Second, "", func() string { return "t1" }, func(string, string) {})
	out, err := tool.Call(context.Background(), threeStagePipeline)
	if err != nil {
		t.Fatal(err)
	}
	if cc.calls.Load() != 1 {
		t.Errorf("Confirm called %d times, want exactly 1 for the whole pipeline", cc.calls.Load())
	}
	if callCount != 1 {
		t.Errorf("execPipeline called %d times, want 1", callCount)
	}
	if !strings.Contains(out, "UNTRUSTED command BEGIN") {
		t.Errorf("output not wrapped:\n%s", out)
	}
}

// TestRunCommandPipelineConfirmRefusedAborts: a refusing confirmer aborts the
// pipeline before any execution.
func TestRunCommandPipelineConfirmRefusedAborts(t *testing.T) {
	cc := &countingConfirmer{ok: false}
	called := false
	withStubPipeline(t, func(ctx context.Context, stages []pipelineStage, dir string, capBytes int, timeout time.Duration) runResult {
		called = true
		return runResult{Output: "must not run"}
	})
	g := safeLocalGate(t, cc)
	tool := newRunCommandTool(g, 1000, time.Second, "", func() string { return "t1" }, func(string, string) {})
	out, err := tool.Call(context.Background(), threeStagePipeline)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("execPipeline must NOT run when the pipeline confirmation is refused")
	}
	if cc.calls.Load() != 1 {
		t.Errorf("Confirm called %d times, want 1", cc.calls.Load())
	}
	if !strings.Contains(strings.ToLower(out), "denied") {
		t.Errorf("want a denial message, got %q", out)
	}
	if strings.Contains(out, "UNTRUSTED") {
		t.Errorf("a refused pipeline must not wrap output, got %q", out)
	}
}

// TestRunCommandPipelineLocalAutoConfirmsOnce: a local /auto pipeline requires
// human confirmation (the LOCAL profile forces HITL in every mode) but still
// only once per pipeline, via ConfirmCommand, then runs.
func TestRunCommandPipelineLocalAutoConfirmsOnce(t *testing.T) {
	cc := &countingConfirmer{ok: true}
	callCount := 0
	withStubPipeline(t, func(ctx context.Context, stages []pipelineStage, dir string, capBytes int, timeout time.Duration) runResult {
		callCount++
		return runResult{Output: "a"}
	})
	s, err := secgate.ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &secgate.Gate{Mode: secgate.Auto, Scope: s, Confirm: cc, Approvals: secgate.NewSessionApprovals()}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	tool := newRunCommandTool(g, 1000, time.Second, "", func() string { return "t1" }, func(string, string) {})
	if _, err := tool.Call(context.Background(), threeStagePipeline); err != nil {
		t.Fatal(err)
	}
	if cc.calls.Load() != 1 {
		t.Errorf("Confirm called %d times, want exactly 1 (local /auto confirms once per pipeline)", cc.calls.Load())
	}
	if callCount != 1 {
		t.Errorf("execPipeline called %d times, want 1", callCount)
	}
}

func TestResolveRunCaps(t *testing.T) {
	cases := []struct {
		name        string
		timeout     string
		maxBytes    string
		wantTimeout time.Duration
		wantBytes   int
	}{
		{"defaults when unset", "", "", 300 * time.Second, 4 << 20},
		{"valid values", "120", "2097152", 120 * time.Second, 2097152},
		{"timeout clamped up", "1", "1", 5 * time.Second, 64 << 10},
		{"timeout clamped down", "99999", "999999999", 1800 * time.Second, 64 << 20},
		{"unparsable falls back", "abc", "xyz", 300 * time.Second, 4 << 20},
		{"negative clamped", "-5", "-5", 5 * time.Second, 64 << 10},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("BLKCHAIN_RUN_TIMEOUT", c.timeout)
			t.Setenv("BLKCHAIN_RUN_MAX_BYTES", c.maxBytes)
			gotT, gotB := resolveRunCaps()
			if gotT != c.wantTimeout {
				t.Errorf("timeout = %v, want %v", gotT, c.wantTimeout)
			}
			if gotB != c.wantBytes {
				t.Errorf("capBytes = %d, want %d", gotB, c.wantBytes)
			}
		})
	}
}

func TestRunCommandDeniedDoesNotExec(t *testing.T) {
	called := false
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		called = true
		return runResult{Output: "should not run"}
	})
	g := autoGate(t)
	tool := newRunCommandTool(g, 1000, time.Second, "", func() string { return "" }, func(string, string) {})
	// Out-of-scope target -> denied.
	out, err := tool.Call(context.Background(), `{"binary":"nmap","args":["-p","80","8.8.8.8"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("execRunner must NOT be called on a denied command")
	}
	if !strings.Contains(strings.ToLower(out), "denied") {
		t.Errorf("want a denial message, got %q", out)
	}
}

func TestRunCommandNumericBypassDenied(t *testing.T) {
	called := false
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		called = true
		return runResult{}
	})
	g := autoGate(t)
	tool := newRunCommandTool(g, 1000, time.Second, "", func() string { return "" }, func(string, string) {})
	// 10.0.0.5 is in scope and passes the gate, but 127.1 canonicalizes to
	// loopback and must be denied by the exec-time re-check.
	out, err := tool.Call(context.Background(), `{"binary":"curl","args":["10.0.0.5","127.1"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("numeric out-of-scope target must be denied before exec")
	}
	if !strings.Contains(out, "127.0.0.1") {
		t.Errorf("want the resolved out-of-scope IP in the message, got %q", out)
	}
}

func TestRunCommandExecutesAndWraps(t *testing.T) {
	var capturedTask, capturedOut string
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		return runResult{Output: "PORT   STATE\n22/tcp open"}
	})
	g := autoGate(t)
	tool := newRunCommandTool(g, 1000, time.Second, "", func() string { return "t1" },
		func(task, out string) { capturedTask, capturedOut = task, out })
	out, err := tool.Call(context.Background(), `{"binary":"nmap","args":["-p","22","10.0.0.5"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "UNTRUSTED command BEGIN") {
		t.Errorf("output not wrapped:\n%s", out)
	}
	if !strings.Contains(out, "22/tcp open") {
		t.Errorf("output missing:\n%s", out)
	}
	if capturedTask != "t1" || !strings.Contains(capturedOut, "22/tcp open") {
		t.Errorf("capture wrong: task=%q out=%q", capturedTask, capturedOut)
	}
}

func TestRunCommandTimeoutMessage(t *testing.T) {
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		return runResult{TimedOut: true}
	})
	g := autoGate(t)
	tool := newRunCommandTool(g, 1000, time.Second, "", func() string { return "t1" }, func(string, string) {})
	out, err := tool.Call(context.Background(), `{"binary":"nmap","args":["-p","22","10.0.0.5"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(out), "timed out") {
		t.Errorf("want a timeout message, got %q", out)
	}
}

func TestRunCommandBadArgs(t *testing.T) {
	called := false
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		called = true
		return runResult{}
	})
	g := autoGate(t)
	tool := newRunCommandTool(g, 1000, time.Second, "", func() string { return "" }, func(string, string) {})
	out, err := tool.Call(context.Background(), `{"binary":"","args":[]}`)
	if err != nil {
		t.Fatal(err)
	}
	if called || strings.Contains(out, "UNTRUSTED") {
		t.Error("an invalid command must not execute/wrap")
	}
}

func TestCappedWriterDropsOverflow(t *testing.T) {
	res := &cappedWriter{cap: 5, buf: &bytes.Buffer{}}
	n, err := res.Write([]byte("abcdefgh"))
	if err != nil || n != 8 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if _, err := res.Write([]byte("zz")); err != nil {
		t.Fatal(err)
	}
	if got := res.buf.String(); got != "abcde" {
		t.Errorf("capped output = %q, want abcde", got)
	}
}

func TestRealExecEchoSmoke(t *testing.T) {
	if os.Getenv("BLKCHAIN_EXEC_SMOKE") != "1" {
		t.Skip("set BLKCHAIN_EXEC_SMOKE=1 to run the real-exec smoke test")
	}
	res := realExec(context.Background(), "echo", []string{"hello"}, "", 100, time.Second)
	if res.TimedOut || !strings.Contains(res.Output, "hello") {
		t.Errorf("echo smoke failed: %+v", res)
	}
}

func TestRunCommandPassesWorkDir(t *testing.T) {
	var gotDir string
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		gotDir = dir
		return runResult{Output: "ok"}
	})
	g := autoGate(t)
	tool := newRunCommandTool(g, 1000, time.Second, "/tmp/scratchX", func() string { return "t1" }, func(string, string) {})
	if _, err := tool.Call(context.Background(), `{"binary":"nmap","args":["-p","22","10.0.0.5"]}`); err != nil {
		t.Fatal(err)
	}
	if gotDir != "/tmp/scratchX" {
		t.Errorf("workDir not threaded to execRunner: %q", gotDir)
	}
}

func TestRunCommandFileAccessViolationDenied(t *testing.T) {
	called := false
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		called = true
		return runResult{}
	})
	g := autoGate(t)
	tool := newRunCommandTool(g, 1000, time.Second, "/scratch", func() string { return "" }, func(string, string) {})
	// curl -o ../audit.jsonl escapes the scratch working directory; it must be
	// denied before exec even though the target itself is in scope.
	out, err := tool.Call(context.Background(), `{"binary":"curl","args":["-o","../audit.jsonl","10.0.0.5"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("a file-access-violating command must NOT be executed")
	}
	if !strings.Contains(out, "file path outside the working directory") {
		t.Errorf("want a file-access denial message, got %q", out)
	}
}

func TestRunCommandAuditsAllowDenyAndExecDistinctly(t *testing.T) {
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		return runResult{Output: "ok"}
	})
	// nonexistent.invalid is listed by name so it passes the gate's InScope
	// check (unlike TestRunCommandUnresolvableHostnameDenied's default scope,
	// where an unlisted hostname is denied earlier, at the gate's own scope
	// layer). .invalid never resolves (RFC 6761), so the exec-time DNS
	// re-check denies it, exercising deny:resolve specifically.
	s, err := secgate.ParseScope(strings.NewReader("10.0.0.0/24\nnonexistent.invalid\n"))
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	g := &secgate.Gate{
		Mode: secgate.Auto, Scope: s, Allow: secgate.NewAllowlist("nmap", "curl"),
		Audit: func(action, detail string) { actions = append(actions, action) },
	}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	tool := newRunCommandTool(g, 1000, time.Second, "", func() string { return "" }, func(string, string) {})

	// An allowed, executed command audits "allow" (from Gate.Authorize) then "exec".
	if _, err := tool.Call(context.Background(), `{"binary":"nmap","args":["-p","22","10.0.0.5"]}`); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 || actions[0] != "allow" || actions[1] != "exec" {
		t.Fatalf("want [allow exec], got %v", actions)
	}

	// A file-access violation is authorized by the gate (scope/allowlist pass)
	// but must be denied and audited at exec time, distinct from "allow".
	actions = nil
	if _, err := tool.Call(context.Background(), `{"binary":"curl","args":["-o","../x","10.0.0.5"]}`); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 || actions[0] != "allow" || actions[1] != "deny:fileaccess" {
		t.Fatalf("want [allow deny:fileaccess], got %v", actions)
	}

	// A numeric-canonicalization scope bypass (127.1 -> loopback) is likewise
	// gate-allowed but denied at the exec-time re-check, audited distinctly.
	actions = nil
	if _, err := tool.Call(context.Background(), `{"binary":"curl","args":["10.0.0.5","127.1"]}`); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 || actions[0] != "allow" || actions[1] != "deny:scope-recheck" {
		t.Fatalf("want [allow deny:scope-recheck], got %v", actions)
	}

	// An unresolvable hostname is likewise gate-allowed but denied at the
	// DNS re-check, audited distinctly.
	actions = nil
	if _, err := tool.Call(context.Background(), `{"binary":"curl","args":["http://nonexistent.invalid/"]}`); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 || actions[0] != "allow" || actions[1] != "deny:resolve" {
		t.Fatalf("want [allow deny:resolve], got %v", actions)
	}
}

func TestRunCommandPipelineDeniedStageDoesNotExec(t *testing.T) {
	// A denied stage ANYWHERE aborts the whole pipeline before any exec. Prove it
	// for a middle stage and for the last stage, not only the first.
	cases := []struct {
		name      string
		args      string
		wantStage string
	}{
		{
			"middle stage denied",
			`{"pipeline":[{"binary":"curl","args":["10.0.0.5"]},{"binary":"sh","args":["-c","id"]},{"binary":"curl","args":["10.0.0.5"]}]}`,
			"stage 2",
		},
		{
			"last stage denied",
			`{"pipeline":[{"binary":"curl","args":["10.0.0.5"]},{"binary":"nmap","args":["-p","22","10.0.0.5"]},{"binary":"bash","args":["-c","id"]}]}`,
			"stage 3",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			called := false
			withStubPipeline(t, func(ctx context.Context, stages []pipelineStage, dir string, capBytes int, timeout time.Duration) runResult {
				called = true
				return runResult{Output: "must not run"}
			})
			g := autoGate(t)
			tool := newRunCommandTool(g, 1000, time.Second, "", func() string { return "" }, func(string, string) {})
			out, err := tool.Call(context.Background(), c.args)
			if err != nil {
				t.Fatal(err)
			}
			if called {
				t.Fatal("execPipeline must NOT be called when any stage is denied")
			}
			if !strings.Contains(out, c.wantStage) {
				t.Errorf("want the denied stage index %q in the message, got %q", c.wantStage, out)
			}
			if !strings.Contains(strings.ToLower(out), "denied") {
				t.Errorf("want a denial message, got %q", out)
			}
			if strings.Contains(out, "UNTRUSTED") {
				t.Errorf("a denied pipeline must not wrap output, got %q", out)
			}
		})
	}
}

func TestRunCommandPipelineValidation(t *testing.T) {
	cases := []struct {
		name string
		args string
		want string
	}{
		{"one stage", `{"pipeline":[{"binary":"nmap","args":["10.0.0.5"]}]}`, "at least 2"},
		{"too many stages", `{"pipeline":[{"binary":"nmap","args":["10.0.0.5"]},{"binary":"curl","args":["10.0.0.5"]},{"binary":"nmap","args":["10.0.0.5"]},{"binary":"curl","args":["10.0.0.5"]}]}`, "at most"},
		{"empty stage binary", `{"pipeline":[{"binary":"nmap","args":["10.0.0.5"]},{"binary":"  "}]}`, "empty binary"},
		{"both binary and pipeline", `{"binary":"nmap","args":["10.0.0.5"],"pipeline":[{"binary":"curl","args":["10.0.0.5"]},{"binary":"nmap","args":["10.0.0.5"]}]}`, "not both"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			called := false
			withStubPipeline(t, func(ctx context.Context, stages []pipelineStage, dir string, capBytes int, timeout time.Duration) runResult {
				called = true
				return runResult{}
			})
			g := autoGate(t)
			tool := newRunCommandTool(g, 1000, time.Second, "", func() string { return "" }, func(string, string) {})
			out, err := tool.Call(context.Background(), c.args)
			if err != nil {
				t.Fatal(err)
			}
			if called {
				t.Fatal("an invalid pipeline must not run")
			}
			if strings.Contains(out, "UNTRUSTED") {
				t.Errorf("an invalid pipeline must not wrap output, got %q", out)
			}
			if !strings.Contains(out, c.want) {
				t.Errorf("want %q in the message, got %q", c.want, out)
			}
		})
	}
}

func TestRunCommandPipelineExecutesAndWraps(t *testing.T) {
	var capturedTask, capturedOut string
	callCount := 0
	withStubPipeline(t, func(ctx context.Context, stages []pipelineStage, dir string, capBytes int, timeout time.Duration) runResult {
		callCount++
		if len(stages) != 2 {
			t.Errorf("want 2 stages threaded to execPipeline, got %d", len(stages))
		}
		return runResult{Output: "22/tcp open"}
	})
	g := autoGate(t)
	tool := newRunCommandTool(g, 1000, time.Second, "", func() string { return "tP" },
		func(task, out string) { capturedTask, capturedOut = task, out })
	out, err := tool.Call(context.Background(), `{"pipeline":[{"binary":"curl","args":["10.0.0.5"]},{"binary":"nmap","args":["-p","22","10.0.0.5"]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if callCount != 1 {
		t.Fatalf("execPipeline called %d times, want 1", callCount)
	}
	if !strings.Contains(out, "UNTRUSTED command BEGIN") {
		t.Errorf("output not wrapped:\n%s", out)
	}
	if !strings.Contains(out, "22/tcp open") {
		t.Errorf("output missing:\n%s", out)
	}
	if capturedTask != "tP" || !strings.Contains(capturedOut, "22/tcp open") {
		t.Errorf("capture wrong: task=%q out=%q", capturedTask, capturedOut)
	}
}

func TestRealExecPipelineFilters(t *testing.T) {
	for _, bin := range []string{"printf", "grep"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}
	// printf writes three lines; grep filters to the one line. The pipe wiring is
	// the security-relevant mechanism, and there is no shell in the code path.
	stages := []pipelineStage{
		{Binary: "printf", Args: []string{"alpha\nsshd\nbravo\n"}},
		{Binary: "grep", Args: []string{"sshd"}},
	}
	res := realExecPipeline(context.Background(), stages, "", 1<<20, 5*time.Second)
	if res.TimedOut {
		t.Fatalf("unexpected timeout: %+v", res)
	}
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if got := strings.TrimSpace(res.Output); got != "sshd" {
		t.Errorf("pipeline output = %q, want %q", got, "sshd")
	}
}

func TestRealExecPipelineHeadEarlyClose(t *testing.T) {
	for _, bin := range []string{"seq", "head"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}
	// head exits after one line; the upstream seq gets SIGPIPE/EPIPE, which is
	// normal and must NOT surface as a pipeline error.
	stages := []pipelineStage{
		{Binary: "seq", Args: []string{"1", "100000"}},
		{Binary: "head", Args: []string{"-n", "1"}},
	}
	res := realExecPipeline(context.Background(), stages, "", 1<<20, 5*time.Second)
	if res.TimedOut {
		t.Fatalf("unexpected timeout: %+v", res)
	}
	if res.Err != nil {
		t.Errorf("head-style early close surfaced an error: %v", res.Err)
	}
	if got := strings.TrimSpace(res.Output); got != "1" {
		t.Errorf("pipeline output = %q, want %q", got, "1")
	}
}

func TestRunCommandUnresolvableHostnameDenied(t *testing.T) {
	called := false
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		called = true
		return runResult{}
	})
	g := autoGate(t)
	tool := newRunCommandTool(g, 1000, time.Second, "", func() string { return "t1" }, func(string, string) {})
	// .invalid never resolves (RFC 6761); ResolveScopeViolation fails closed.
	out, err := tool.Call(context.Background(), `{"binary":"curl","args":["http://nonexistent.invalid/"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("an unresolvable hostname must be denied before exec (fail closed)")
	}
	if !strings.Contains(strings.ToLower(out), "scope") && !strings.Contains(strings.ToLower(out), "resolve") {
		t.Errorf("want a resolve/scope denial, got %q", out)
	}
}

// TestRunCommandStampsPhaseArmedAndTierGates: the task-aware tool stamps the
// engagement phase/armed onto every Command, so the gate tiers it. An unarmed
// exploit command is denied at the tier layer; an armed+confirmed one runs.
func TestRunCommandStampsPhaseArmedAndTierGates(t *testing.T) {
	// Unarmed exploit context: run_command is denied at the tier layer.
	g := safeLocalGate(t, &countingConfirmer{ok: true})
	tool := newRunCommandToolForTask(g, 1<<20, time.Minute, "", func() string { return "t1" }, nil,
		secgate.Command{Phase: secgate.PhaseExploit, Armed: false})
	out, _ := tool.Call(context.Background(), `{"binary":"id"}`)
	if !strings.Contains(out, "denied") || !strings.Contains(strings.ToLower(out), "arm") {
		t.Errorf("unarmed exploit run_command: out=%q, want a tier deny mentioning arming", out)
	}

	// Armed exploit context + approving confirmer: it runs (stub exec).
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		return runResult{Output: "ran " + bin}
	})
	g2 := safeLocalGate(t, &countingConfirmer{ok: true})
	tool2 := newRunCommandToolForTask(g2, 1<<20, time.Minute, "", func() string { return "t1" }, nil,
		secgate.Command{Phase: secgate.PhaseExploit, Armed: true})
	out2, _ := tool2.Call(context.Background(), `{"binary":"id"}`)
	if !strings.Contains(out2, "ran id") {
		t.Errorf("armed+confirmed exploit run_command: out=%q, want it to run", out2)
	}
}
