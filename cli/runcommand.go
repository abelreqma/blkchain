package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"
)

const (
	runCommandTimeout  = 60 * time.Second
	runCommandCapBytes = 1 << 20
)

type runCommandArgs struct {
	Binary string   `json:"binary" desc:"the command binary (a bare name, no path; resolved via PATH)"`
	Args   []string `json:"args,omitempty" desc:"the literal arguments; no shell, no metacharacters"`
}

// runResult is the captured output of one execution.
type runResult struct {
	Output   string
	TimedOut bool
	Err      error
}

// execRunner runs a shell-free command with a timeout and byte cap. Stubbed in tests.
var execRunner = realExec

// newRunCommandTool builds the run_command tool. It executes ONLY when the gate
// allows the command AND the exec-time scope re-check finds no out-of-scope
// resolved address. activeTask names the task to attribute captured output to.
func newRunCommandTool(g *secgate.Gate, capBytes int, timeout time.Duration, workDir string, activeTask func() string, capture func(taskID, output string)) tooldef.Tool {
	return newStoreTool("run_command",
		"Run a bounded, shell-free security tool command against an in-scope target. Provide a bare binary name and literal args (no shell, no pipes or redirection). Output is returned as untrusted data.",
		runCommandArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			var a runCommandArgs
			if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
				return "run_command: invalid arguments: " + err.Error(), nil
			}
			if strings.TrimSpace(a.Binary) == "" {
				return "run_command: invalid arguments: binary is required", nil
			}
			cmd := secgate.Command{Binary: a.Binary, Args: a.Args}
			if d := g.Authorize(ctx, cmd); !d.Allowed {
				msg := "run_command denied: " + d.Reason
				if d.Suggestion != "" {
					msg += " Suggestion: " + d.Suggestion
				}
				return msg, nil
			}
			if ip, ok := secgate.ScopeViolation(g.Scope, cmd); ok {
				if g.Audit != nil {
					g.Audit("deny:scope-recheck", secgate.Signature(cmd))
				}
				return "run_command denied: a target resolves to an out-of-scope address: " + ip, nil
			}
			if host, ip, bad := secgate.ResolveScopeViolation(g.Scope, cmd); bad {
				if g.Audit != nil {
					g.Audit("deny:resolve", secgate.Signature(cmd))
				}
				if ip != "" {
					return "run_command denied: " + host + " resolves to an out-of-scope address: " + ip, nil
				}
				return "run_command denied: could not resolve " + host + " to verify it is in scope", nil
			}
			if arg, bad := secgate.FileAccessViolation(cmd); bad {
				if g.Audit != nil {
					g.Audit("deny:fileaccess", secgate.Signature(cmd))
				}
				return "run_command denied: file path outside the working directory is not allowed: " + arg, nil
			}
			if g.Audit != nil {
				g.Audit("exec", secgate.Signature(cmd))
			}
			res := execRunner(ctx, cmd.Binary, cmd.Args, workDir, capBytes, timeout)
			if res.TimedOut {
				return "run_command: the command timed out and was terminated after " + timeout.String(), nil
			}
			if capture != nil {
				capture(activeTask(), res.Output)
			}
			var b strings.Builder
			if res.Err != nil {
				fmt.Fprintf(&b, "(command exited with an error: %s)\n", res.Err.Error())
			}
			b.WriteString(secgate.WrapUntrusted("command", res.Output))
			return b.String(), nil
		})
}

// realExec runs bin with args, no shell, minimal env, a timeout, and an output
// cap. On timeout it kills the child's process group.
func realExec(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx2, bin, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Kill the whole process group (negative pid) so children die too.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return cmd.Process.Kill()
	}
	// Do not wait forever on pipes held open by an orphaned grandchild.
	cmd.WaitDelay = 2 * time.Second
	var buf bytes.Buffer
	w := &cappedWriter{cap: capBytes, buf: &buf}
	cmd.Stdout = w
	cmd.Stderr = w
	err := cmd.Run()
	if cmd.Process != nil {
		// Reap any daemonized grandchild left in the group after a normal exit.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	timedOut := ctx2.Err() == context.DeadlineExceeded
	return runResult{Output: buf.String(), TimedOut: timedOut, Err: nonTimeoutErr(err, timedOut)}
}

func nonTimeoutErr(err error, timedOut bool) error {
	if timedOut {
		return nil
	}
	return err
}

// cappedWriter writes at most cap bytes to buf and silently drops the rest.
type cappedWriter struct {
	cap int
	buf *bytes.Buffer
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	room := w.cap - w.buf.Len()
	if room <= 0 {
		return len(p), nil // pretend consumed; drop overflow
	}
	if len(p) > room {
		w.buf.Write(p[:room])
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}

var _ io.Writer = (*cappedWriter)(nil)
