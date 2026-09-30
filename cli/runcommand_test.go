package main

import (
	"bytes"
	"context"
	"os"
	"strings"
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
