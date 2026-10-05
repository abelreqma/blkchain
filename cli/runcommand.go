package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"
)

const (
	runCommandTimeout  = 300 * time.Second
	runCommandCapBytes = 4 << 20

	runTimeoutMinSec = 5
	runTimeoutMaxSec = 1800
	runCapMinBytes   = 64 << 10
	runCapMaxBytes   = 64 << 20

	maxPipelineStages = 3
)

// resolveRunCaps returns the per-command timeout and output byte cap, from
// BLKCHAIN_RUN_TIMEOUT (seconds) and BLKCHAIN_RUN_MAX_BYTES. A parsable value
// outside the allowed range is clamped; an unset or unparsable value uses the
// default. The Episode wall-clock and command caps remain the hard backstop.
func resolveRunCaps() (timeout time.Duration, capBytes int) {
	secs := clampEnvInt("BLKCHAIN_RUN_TIMEOUT", int(runCommandTimeout/time.Second), runTimeoutMinSec, runTimeoutMaxSec)
	capBytes = clampEnvInt("BLKCHAIN_RUN_MAX_BYTES", runCommandCapBytes, runCapMinBytes, runCapMaxBytes)
	return time.Duration(secs) * time.Second, capBytes
}

func clampEnvInt(name string, def, lo, hi int) int {
	v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

type pipelineStage struct {
	Binary        string   `json:"binary" desc:"the stage command binary (a bare name, no path; resolved via PATH)"`
	Args          []string `json:"args,omitempty" desc:"the literal arguments for this stage; no shell, no metacharacters"`
	DiscardStderr bool     `json:"discard_stderr,omitempty" desc:"discard this stage's stderr instead of capturing it"`
}

type runCommandArgs struct {
	Binary   string          `json:"binary" desc:"the command binary (a bare name, no path; resolved via PATH)"`
	Args     []string        `json:"args,omitempty" desc:"the literal arguments; no shell, no metacharacters"`
	Pipeline []pipelineStage `json:"pipeline,omitempty" desc:"optional: run a shell-free pipeline of 2-3 stages, each stdout piped to the next stdin; every stage is authorized independently; provide either a single binary+args OR a pipeline, not both"`
}

// runResult is the captured output of one execution.
type runResult struct {
	Output   string
	TimedOut bool
	Err      error
}

// execRunner runs a shell-free command with a timeout and byte cap. Stubbed in tests.
var execRunner = realExec

// execPipeline runs a shell-free pipeline with a timeout and byte cap. Stubbed in tests.
var execPipeline = realExecPipeline

// authorizeCommand runs g.Authorize (deny-layers, confirmation, then the
// exec-time rechecks) for one command. It returns the authorized command to
// execute (the input command, or an operator-edited substitute the gate
// re-validated) and an empty deny message; or a zero command and a non-empty deny
// message (already audited) when the command is not allowed. The caller MUST run
// the returned command, not the one it passed in, so an operator edit takes effect.
func authorizeCommand(ctx context.Context, g *secgate.Gate, cmd secgate.Command) (secgate.Command, string) {
	d := g.Authorize(ctx, cmd)
	if !d.Allowed {
		return secgate.Command{}, denyMessage(d)
	}
	run := d.Command
	if run.Binary == "" {
		run = cmd // defensive: a Decision that did not set the authorized command
	}
	return run, ""
}

// checkCommand runs g.Check (deny-layers plus the exec-time rechecks, NO
// confirmation). It returns a non-empty deny message (already audited) when the
// command is not allowed, or "" when it passes. A pipeline confirms ONCE via
// g.ConfirmCommand, then calls it per stage so the rechecks run after
// confirmation.
func checkCommand(ctx context.Context, g *secgate.Gate, cmd secgate.Command) string {
	if d := g.Check(ctx, cmd); !d.Allowed {
		return denyMessage(d)
	}
	return ""
}

func denyMessage(d secgate.Decision) string {
	msg := "run_command denied: " + d.Reason
	if d.Suggestion != "" {
		msg += " Suggestion: " + d.Suggestion
	}
	return msg
}

// newRunCommandTool builds the run_command tool. It executes ONLY when the gate
// allows the command AND the exec-time scope re-check finds no out-of-scope
// resolved address. activeTask names the task to attribute captured output to.
func newRunCommandTool(g *secgate.Gate, capBytes int, timeout time.Duration, workDir string, activeTask func() string, capture func(taskID, output string)) tooldef.Tool {
	return newRunCommandToolForTask(g, capBytes, timeout, workDir, activeTask, capture, secgate.Command{}, nil)
}

// newRunCommandToolForTask is newRunCommandTool with the engagement context
// (phase/surface/armed) in cmdCtx stamped onto every Command the tool builds, so
// the gate derives the per-action tier for the task's phase (exploit/post-ex
// require an armed task and force per-action confirmation). A zero cmdCtx is the
// recon/unarmed default posture. grounder, when non-nil, grounds each proposed
// command against the tool's real interface before the gate authorizes it (a
// hallucinated flag is rejected and re-grounded, not executed); nil disables
// grounding.
func newRunCommandToolForTask(g *secgate.Gate, capBytes int, timeout time.Duration, workDir string, activeTask func() string, capture func(taskID, output string), cmdCtx secgate.Command, grounder *helpGrounder) tooldef.Tool {
	return newStoreTool("run_command",
		"Run a bounded, shell-free security tool command against an in-scope target. Provide a bare binary name and literal args (no shell, no pipes or redirection). For a multi-stage filter, pass a structured `pipeline` of 2-3 stages (each a bare binary + literal args); stages are piped stdout to stdin with no shell, and every stage is authorized independently. Output is returned as untrusted data.",
		runCommandArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			var a runCommandArgs
			if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
				return "run_command: invalid arguments: " + err.Error(), nil
			}
			hasBinary := strings.TrimSpace(a.Binary) != ""
			if hasBinary && len(a.Pipeline) > 0 {
				return "run_command: invalid arguments: provide either binary or pipeline, not both", nil
			}

			if len(a.Pipeline) == 0 {
				if !hasBinary {
					return "run_command: invalid arguments: binary is required", nil
				}
				cmd := secgate.Command{Binary: a.Binary, Args: a.Args, Phase: cmdCtx.Phase, Surface: cmdCtx.Surface, Armed: cmdCtx.Armed, Kind: cmdCtx.Kind, Target: cmdCtx.Target}
				// Help-grounding runs before the gate: a command using a flag or
				// subcommand absent from the tool's real interface is rejected and
				// re-grounded (never executed). An advisory note (grounding could
				// not verify, but fails open to the gate) is prepended to output.
				// Grounding checks the model's PROPOSED command; an operator who
				// edits it at the gate is a trusted human, so the edited run is
				// executed without re-grounding.
				oc := grounder.ground(ctx, cmd)
				if oc.Reject {
					return oc.Msg, nil
				}
				// run is the authorized command: cmd, or an operator-edited substitute
				// the gate re-validated. Execute run, not cmd, so an edit takes effect.
				run, msg := authorizeCommand(ctx, g, cmd)
				if msg != "" {
					return msg, nil
				}
				if g.Audit != nil {
					g.Audit("exec", secgate.Signature(run))
				}
				res := execRunner(ctx, run.Binary, run.Args, workDir, capBytes, timeout)
				if res.TimedOut {
					return "run_command: the command timed out and was terminated after " + timeout.String(), nil
				}
				if capture != nil {
					capture(activeTask(), res.Output)
				}
				var b strings.Builder
				if oc.Msg != "" {
					fmt.Fprintf(&b, "(grounding: %s)\n", oc.Msg)
				}
				if res.Err != nil {
					fmt.Fprintf(&b, "(command exited with an error: %s)\n", res.Err.Error())
				}
				b.WriteString(secgate.WrapUntrusted("command", res.Output))
				return b.String(), nil
			}

			// Pipeline form.
			if len(a.Pipeline) < 2 {
				return "run_command: invalid arguments: a pipeline needs at least 2 stages; use binary/args for a single command", nil
			}
			if len(a.Pipeline) > maxPipelineStages {
				return "run_command: invalid arguments: a pipeline may have at most " + strconv.Itoa(maxPipelineStages) + " stages", nil
			}
			for i := range a.Pipeline {
				if strings.TrimSpace(a.Pipeline[i].Binary) == "" {
					return "run_command: invalid arguments: pipeline stage " + strconv.Itoa(i+1) + " has an empty binary", nil
				}
			}
			// Confirm the whole pipeline once, FIRST. The synthetic display command
			// has binary "pipeline" and one arg per stage rendered as
			// "bin arg1 arg2 ...", so its Signature is stable and an approval is
			// remembered for an identical pipeline.
			cmds := make([]secgate.Command, len(a.Pipeline))
			stageStrs := make([]string, len(a.Pipeline))
			for i := range a.Pipeline {
				cmds[i] = secgate.Command{Binary: a.Pipeline[i].Binary, Args: a.Pipeline[i].Args, Phase: cmdCtx.Phase, Surface: cmdCtx.Surface, Armed: cmdCtx.Armed, Kind: cmdCtx.Kind, Target: cmdCtx.Target}
				stageStrs[i] = strings.Join(append([]string{cmds[i].Binary}, cmds[i].Args...), " ")
			}
			// Ground every stage BEFORE confirming or running any: a grounded-reject
			// in any stage aborts the whole pipeline with zero side effects (fail
			// closed), like a denied stage. Advisory notes (grounding could not
			// verify) are collected and prepended to the pipeline output.
			var groundNotes []string
			for i := range cmds {
				oc := grounder.ground(ctx, cmds[i])
				if oc.Reject {
					return "run_command grounded-reject (stage " + strconv.Itoa(i+1) + "): " + oc.Msg, nil
				}
				if oc.Msg != "" {
					groundNotes = append(groundNotes, "stage "+strconv.Itoa(i+1)+": "+oc.Msg)
				}
			}
			display := secgate.Command{Binary: "pipeline", Args: stageStrs, Phase: cmdCtx.Phase, Surface: cmdCtx.Surface, Armed: cmdCtx.Armed}
			if d := g.ConfirmCommand(ctx, display); !d.Allowed {
				return "run_command denied: " + d.Reason, nil
			}
			// Then check EVERY stage (deny-layers plus the exec-time rechecks) before
			// running ANY: a denied stage anywhere aborts the whole pipeline with zero
			// side effects (fail closed). Running the check after confirmation closes
			// the window in which a hostname could re-resolve out of scope while the
			// human prompt was open. checkCommand does NOT prompt again.
			for i := range cmds {
				if msg := checkCommand(ctx, g, cmds[i]); msg != "" {
					reason := strings.TrimPrefix(msg, "run_command denied: ")
					return "run_command denied (stage " + strconv.Itoa(i+1) + "): " + reason, nil
				}
			}
			if g.Audit != nil {
				sigs := make([]string, len(cmds))
				for i := range cmds {
					sigs[i] = secgate.Signature(cmds[i])
				}
				g.Audit("exec", strings.Join(sigs, " | "))
			}
			res := execPipeline(ctx, a.Pipeline, workDir, capBytes, timeout)
			if res.TimedOut {
				return "run_command: the pipeline timed out and was terminated after " + timeout.String(), nil
			}
			if capture != nil {
				capture(activeTask(), res.Output)
			}
			var b strings.Builder
			for _, note := range groundNotes {
				fmt.Fprintf(&b, "(grounding: %s)\n", note)
			}
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
	cmd, err := newSandboxedCommand(ctx2, bin, args, dir)
	if err != nil {
		return runResult{Err: err}
	}
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
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
	err = cmd.Run()
	if cmd.Process != nil {
		// Reap any daemonized grandchild left in the group after a normal exit.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	timedOut := ctx2.Err() == context.DeadlineExceeded
	return runResult{Output: buf.String(), TimedOut: timedOut, Err: nonTimeoutErr(err, timedOut)}
}

// realExecPipeline runs a shell-free pipeline: each stage's stdout is wired to
// the next stage's stdin through an explicit OS pipe, with NO shell and NO
// metacharacter interpretation. Only the final stage's stdout is the pipeline
// result; every non-discarded stderr is folded into the same capped buffer.
// One timeout bounds the whole pipeline; on cancel every stage's process group
// is killed. A broken pipe on an upstream stage (a downstream stage like head
// exiting early) is normal and is not reported as an error.
func realExecPipeline(ctx context.Context, stages []pipelineStage, dir string, capBytes int, timeout time.Duration) runResult {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var buf bytes.Buffer
	lw := &lockedWriter{w: &cappedWriter{cap: capBytes, buf: &buf}}

	n := len(stages)
	cmds := make([]*exec.Cmd, n)
	for i := range stages {
		c, err := newSandboxedCommand(ctx2, stages[i].Binary, stages[i].Args, dir)
		if err != nil {
			return runResult{Err: err}
		}
		c.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
		c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		c.WaitDelay = 2 * time.Second
		pc := c
		c.Cancel = func() error {
			if pc.Process == nil {
				return nil
			}
			// Kill the whole process group (negative pid) so children die too.
			_ = syscall.Kill(-pc.Process.Pid, syscall.SIGKILL)
			return pc.Process.Kill()
		}
		if stages[i].DiscardStderr {
			c.Stderr = io.Discard
		} else {
			c.Stderr = lw
		}
		cmds[i] = c
	}

	// Wire stdout -> stdin between consecutive stages via explicit OS pipes. The
	// final stage's stdout is the pipeline result.
	var parentFiles []*os.File
	for i := 0; i < n-1; i++ {
		pr, pw, err := os.Pipe()
		if err != nil {
			for _, f := range parentFiles {
				_ = f.Close()
			}
			return runResult{Err: err}
		}
		cmds[i].Stdout = pw
		cmds[i+1].Stdin = pr
		parentFiles = append(parentFiles, pr, pw)
	}
	cmds[n-1].Stdout = lw

	// Start every stage, then close the parent's copies of the inter-stage pipe
	// ends so a downstream stage sees EOF once its upstream exits.
	var started []*exec.Cmd
	var startErr error
	for i := range cmds {
		if err := cmds[i].Start(); err != nil {
			startErr = err
			break
		}
		started = append(started, cmds[i])
	}
	for _, f := range parentFiles {
		_ = f.Close()
	}
	if startErr != nil {
		for _, c := range started {
			if c.Process != nil {
				_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
			}
		}
		for _, c := range started {
			_ = c.Wait()
		}
		return runResult{Output: buf.String(), Err: startErr}
	}

	// Wait in order; keep only the LAST stage's non-timeout error. An upstream
	// stage dying on a broken pipe is normal and must not fail the pipeline.
	var lastErr error
	for i, c := range cmds {
		err := c.Wait()
		if c.Process != nil {
			// Reap any daemonized grandchild left in the group after exit.
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		}
		if i == n-1 {
			lastErr = err
		}
	}
	timedOut := ctx2.Err() == context.DeadlineExceeded
	return runResult{Output: buf.String(), TimedOut: timedOut, Err: nonTimeoutErr(lastErr, timedOut)}
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

// lockedWriter serializes concurrent writes to w. A pipeline folds several
// stages' stderr into one shared capped buffer, and each stage's stderr copy
// runs on its own goroutine, so the shared writer must be mutex-guarded.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

var _ io.Writer = (*lockedWriter)(nil)
