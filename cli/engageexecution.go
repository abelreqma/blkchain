package main

import (
	"blkchain/cli/internal/promptguard"
	"blkchain/cli/internal/secgate"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type engageRuntimeKey struct{}
type engageRuntime struct {
	runner *engageRunner
	trace  *actionTranscript
	policy *secgate.Policy
	cancel context.CancelFunc
}

func runtimeFor(ctx context.Context) *engageRuntime {
	r, _ := ctx.Value(engageRuntimeKey{}).(*engageRuntime)
	return r
}

func releaseEngageWorker(ctx context.Context, dir string) {
	if r := runtimeFor(ctx); r != nil && r.runner != nil {
		r.runner.Release(dir)
	}
}

func (t *actionTranscript) begin(task, kind, command string, count int) (string, int, error) {
	t.orderMu.Lock()
	defer t.orderMu.Unlock()
	t.mu.Lock()
	if t.actions+count > t.maxActions || t.used >= t.maxBytes {
		t.mu.Unlock()
		return "", 0, errors.New("engagement action or capture budget reached")
	}
	t.actions += count
	t.seq++
	id := fmt.Sprintf("a-%06d", t.seq)
	remaining := t.maxBytes - t.used
	t.mu.Unlock()
	err := t.recordOrdered(actionRecord{ID: id, Task: task, Kind: kind, Command: command, Status: "running", ExitCode: -1, Stages: count})
	return id, remaining, err
}

func recordEngageDenial(ctx context.Context, c secgate.Command, reason string) {
	if r := runtimeFor(ctx); r != nil {
		if err := r.trace.record(actionRecord{Task: c.TaskID, Kind: "command", Command: secgate.Signature(c), Status: "denied", ExitCode: -1, Reason: reason}); err != nil {
			r.cancel()
		}
	}
}

func runAuthorized(ctx context.Context, g *secgate.Gate, bin string, args []string, dir string, limit int, timeout time.Duration, taskID string) runResult {
	if g == nil || g.Policy == nil {
		return execRunner(ctx, bin, args, dir, limit, timeout)
	}
	return runIsolatedAction(ctx, g, []pipelineStage{{Binary: bin, Args: args}}, dir, limit, timeout, taskID)
}

func runAuthorizedPipeline(ctx context.Context, g *secgate.Gate, stages []pipelineStage, dir string, limit int, timeout time.Duration, taskID string) runResult {
	if g == nil || g.Policy == nil {
		return execPipeline(ctx, stages, dir, limit, timeout)
	}
	return runIsolatedAction(ctx, g, stages, dir, limit, timeout, taskID)
}

func runIsolatedAction(ctx context.Context, g *secgate.Gate, stages []pipelineStage, dir string, limit int, timeout time.Duration, taskID string) runResult {
	r := runtimeFor(ctx)
	if r == nil || r.runner == nil || r.trace == nil || r.policy != g.Policy {
		return runResult{Err: errors.New("isolated runner context missing; host execution is disabled")}
	}
	if ctx.Err() != nil {
		return runResult{Err: ctx.Err()}
	}
	policyRemaining := g.PolicyBytesRemaining()
	if policyRemaining <= 0 {
		err := g.ClaimPolicyBytes(1)
		r.cancel()
		return runResult{Err: err}
	}
	var commands []string
	for _, s := range stages {
		commands = append(commands, secgate.Signature(secgate.Command{Binary: s.Binary, Args: s.Args}))
	}
	id, remaining, err := r.trace.begin(taskID, "command", strings.Join(commands, " | "), len(stages))
	if err != nil {
		r.cancel()
		return runResult{Err: err}
	}
	if limit > g.Policy.OutputBytes {
		limit = g.Policy.OutputBytes
	}
	if limit > remaining {
		limit = remaining
	}
	if limit > policyRemaining {
		limit = policyRemaining
	}
	if timeout > g.Policy.Timeout() {
		timeout = g.Policy.Timeout()
	}
	start := time.Now()
	resolve := r.runner.resolve
	if resolve == nil {
		resolve = net.DefaultResolver.LookupIPAddr
	}
	plan, planErr := planWildcardEgress(ctx, g.Scope, stages, resolve)
	var result runResult
	var outputs []isolatedStageResult
	if planErr != nil {
		result.Err = planErr
		if g.Audit != nil {
			g.Audit("deny:scope-recheck", strings.Join(commands, " | ")+" :: "+planErr.Error())
		}
	} else {
		result, outputs = r.runner.RunScoped(ctx, stages, dir, limit, timeout, plan, g.Policy)
	}
	status := "complete"
	if planErr != nil {
		status = "denied"
	} else if result.TimedOut {
		status = "timeout"
	} else if ctx.Err() != nil {
		status = "canceled"
	} else if result.Err != nil {
		status = "failed"
	}
	if len(outputs) == 0 {
		outputs = []isolatedStageResult{{Stderr: result.Output, ExitCode: -1}}
	}
	for index, output := range outputs {
		if claimErr := g.ClaimPolicyBytes(len(output.Stdout) + len(output.Stderr)); claimErr != nil {
			r.cancel()
			result.Err = errors.Join(result.Err, claimErr)
			status = "failed"
		}
		command := strings.Join(commands, " | ")
		eventID := id
		if len(stages) > 1 {
			eventID = fmt.Sprintf("%s.%d", id, index+1)
			if index < len(commands) {
				command = commands[index]
			}
		}
		rec := actionRecord{ID: eventID, Task: taskID, Kind: "command", Command: command, Status: status, DurationMS: time.Since(start).Milliseconds(), ExitCode: output.ExitCode, Stdout: output.Stdout, Stderr: output.Stderr, Dropped: output.Dropped}
		if result.Err != nil {
			rec.Reason = result.Err.Error()
		}
		if err := r.trace.record(rec); err != nil {
			r.cancel()
			result.Err = err
		}
	}
	return result
}

func effectiveEngagePrompt(g *secgate.Gate, prompt string) string {
	if g == nil || g.Policy == nil {
		return prompt
	}
	return prompt + "\n\nOperator rules of engagement (code-enforced policy):\n" + g.Policy.Canonical +
		"\nCommands run inside the isolated target runner, not on the operator workstation. Use its installed tools and /work for scratch files. The runner has no DNS: every in-scope hostname is pre-resolved in /etc/hosts, and any other lookup is dropped and stalls until the command timeout, so pass -n to nmap and address other tools by a scoped hostname or an IP. Auto performs RoE-authorized actions without approval or arming prompts. Safe approves unapproved actions. Scope, caps, and denials apply in both modes.\n" + promptguard.UntrustedInputClause
}
