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

// actionOrigin is the task context an action inherits. Its surface decides where
// the action executes: a declared foothold covers a surface set, and an action on
// a covered surface runs on the foothold instead of in the sandbox worker.
type actionOrigin struct {
	TaskID  string
	Surface secgate.Surface
}

func runAuthorized(ctx context.Context, g *secgate.Gate, bin string, args []string, dir string, limit int, timeout time.Duration, origin actionOrigin) runResult {
	if g == nil || g.Policy == nil {
		return execRunner(ctx, bin, args, dir, limit, timeout)
	}
	return runIsolatedAction(ctx, g, []pipelineStage{{Binary: bin, Args: args}}, dir, limit, timeout, origin)
}

func runAuthorizedPipeline(ctx context.Context, g *secgate.Gate, stages []pipelineStage, dir string, limit int, timeout time.Duration, origin actionOrigin) runResult {
	if g == nil || g.Policy == nil {
		return execPipeline(ctx, stages, dir, limit, timeout)
	}
	return runIsolatedAction(ctx, g, stages, dir, limit, timeout, origin)
}

// footholdStages rewrites authorized stages to run on the foothold. The rewrite
// happens after authorization and after the egress decision, so the gate and the
// scope check always read the operator's own command and never the carrier argv.
func footholdStages(t *footholdTransport, stages []pipelineStage) []pipelineStage {
	out := make([]pipelineStage, len(stages))
	for i, s := range stages {
		argv := t.Wrap(append([]string{s.Binary}, s.Args...))
		out[i] = pipelineStage{Binary: argv[0], Args: argv[1:], DiscardStderr: s.DiscardStderr}
	}
	return out
}

// pivotDestination reports the foothold an action on this surface runs on, or ""
// when it runs in the sandbox worker. The decision is code-derived from the
// sealed policy and the task's surface; no model or corpus text reaches it.
func pivotDestination(g *secgate.Gate, r *engageRuntime, surface secgate.Surface) string {
	if r == nil || r.runner == nil || r.runner.foothold == nil || g == nil || g.Policy == nil {
		return ""
	}
	if !g.Policy.Foothold.Covers(surface) {
		return ""
	}
	return g.Policy.Foothold.Host
}

func runIsolatedAction(ctx context.Context, g *secgate.Gate, stages []pipelineStage, dir string, limit int, timeout time.Duration, origin actionOrigin) runResult {
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
	id, remaining, err := r.trace.begin(origin.TaskID, "command", strings.Join(commands, " | "), len(stages))
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
	// A pivoted action contacts exactly one address from the worker, the
	// foothold, which the guard already pins. Its own targets are reached by the
	// foothold, outside this firewall, so the resolve-time egress plan does not
	// apply and resolution cannot be rechecked there: scope for a pivoted action
	// is enforced by the gate alone. Every such action records its destination.
	destination := pivotDestination(g, r, origin.Surface)
	exec := stages
	var plan engageEgressPlan
	var planErr error
	if destination != "" {
		exec = footholdStages(r.runner.foothold, stages)
		if g.Audit != nil {
			g.Audit("foothold", "destination="+destination+" transport="+r.runner.foothold.name+" :: "+strings.Join(commands, " | "))
		}
	} else {
		plan, planErr = planWildcardEgress(ctx, g.Scope, stages, resolve)
	}
	var result runResult
	var outputs []isolatedStageResult
	if planErr != nil {
		result.Err = planErr
		if g.Audit != nil {
			g.Audit("deny:scope-recheck", strings.Join(commands, " | ")+" :: "+planErr.Error())
		}
	} else {
		result, outputs = r.runner.RunScoped(ctx, exec, dir, limit, timeout, plan, g.Policy)
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
		rec := actionRecord{ID: eventID, Task: origin.TaskID, Kind: "command", Command: command, Destination: destination, Status: status, DurationMS: time.Since(start).Milliseconds(), ExitCode: output.ExitCode, Stdout: output.Stdout, Stderr: output.Stderr, Dropped: output.Dropped}
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
		"\nCommands run inside the isolated target runner, not on the operator workstation. Use its installed tools and /work for scratch files. The runner has no DNS: every in-scope hostname is pre-resolved in /etc/hosts, and any other lookup is dropped and stalls until the command timeout, so pass -n to nmap and address other tools by a scoped hostname or an IP. Auto performs RoE-authorized actions without approval or arming prompts. Safe approves unapproved actions. Scope, caps, and denials apply in both modes.\n" +
		footholdPromptClause(g.Policy.Foothold) + promptguard.UntrustedInputClause
}

// footholdPromptClause tells the model which surfaces execute on the operator's
// foothold rather than in the runner, because the two destinations differ in
// ways that change what a command should look like: the foothold has its own
// installed tools, its own filesystem, and its own resolver, so the runner's
// pre-resolved /etc/hosts and its missing DNS do not apply there. The clause is
// derived from the sealed policy; it states where commands go and never invites
// the model to choose.
func footholdPromptClause(f *secgate.Foothold) string {
	if f == nil {
		return ""
	}
	surfaces := make([]string, 0, len(f.Surfaces))
	for _, s := range f.Surfaces {
		surfaces = append(surfaces, string(s))
	}
	return "The operator has declared a foothold. Tasks on the " + strings.Join(surfaces, ", ") +
		" surface run on " + f.Host + ", a host the operator already controls, and every other task runs in the runner." +
		" On the foothold use its own tools, its own paths, and its own name resolution; the runner's /etc/hosts pins and its lack of DNS do not apply there." +
		" You do not choose where a command runs: the surface of its task decides, and each action records its destination.\n"
}
