package main

import (
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/promptguard"
	"blkchain/cli/internal/secgate"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

type engageRuntimeKey struct{}
type engageRuntime struct {
	runner *engageRunner
	trace  *actionTranscript
	store  *engagement.Store
	policy *secgate.Policy
	cancel context.CancelFunc
	// staged records the scannable material each worker working directory holds.
	staged *vulnScanQueue
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

func (t *actionTranscript) begin(task, kind, command string, count int, exempt ...bool) (string, int, error) {
	budgetExempt := len(exempt) > 0 && exempt[0]
	t.orderMu.Lock()
	defer t.orderMu.Unlock()
	t.mu.Lock()
	if !budgetExempt && t.actions+count > t.maxActions || t.used >= t.maxBytes {
		t.mu.Unlock()
		return "", 0, errors.New("engagement action or capture budget reached")
	}
	if !budgetExempt {
		t.actions += count
	}
	t.seq++
	id := fmt.Sprintf("a-%06d", t.seq)
	remaining := t.maxBytes - t.used
	t.mu.Unlock()
	err := t.recordOrdered(actionRecord{ID: id, Task: task, Kind: kind, Command: command, Status: "running", ExitCode: -1, Stages: count, BudgetExempt: budgetExempt})
	return id, remaining, err
}

func recordEngageDenial(ctx context.Context, c secgate.Command, reason string) {
	if c.InternalProbe {
		return
	}
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
	TaskID         string
	Surface        secgate.Surface
	SkipVulnIngest bool
	UseRawWorker   bool
	RequireHTTP200 bool
	BudgetExempt   bool
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

func stagesSucceeded(result runResult, outputs []isolatedStageResult, origin actionOrigin) bool {
	if result.Err != nil || result.TimedOut || len(outputs) == 0 {
		return false
	}
	if origin.RequireHTTP200 && (len(outputs) != 1 || strings.TrimSpace(outputs[0].Stdout) != "200") {
		return false
	}
	for _, output := range outputs {
		if output.ExitCode != 0 {
			return false
		}
	}
	return true
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

func cloudCredentialStages(stages []pipelineStage, identity secgate.CloudIdentity) []pipelineStage {
	out := make([]pipelineStage, len(stages))
	for i, stage := range stages {
		out[i] = stage
		env := []string{"-i", "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", "HOME=/tmp"}
		switch {
		case identity.Provider == "aws" && stage.Binary == "aws":
			env = append(env, "AWS_SHARED_CREDENTIALS_FILE="+identity.CredentialFile, "AWS_CONFIG_FILE=/dev/null", "AWS_EC2_METADATA_DISABLED=true", "AWS_PAGER=")
		case identity.Provider == "gcp" && stage.Binary == "gcloud":
			env = append(env, "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE="+identity.CredentialFile, "CLOUDSDK_CORE_DISABLE_PROMPTS=1")
		default:
			continue
		}
		out[i].Binary = "/usr/bin/env"
		out[i].Args = append(append(env, stage.Binary), stage.Args...)
	}
	return out
}

// pivotDestination reports the foothold an action on this surface runs on, or ""
// when it runs in the sandbox worker. The decision uses the declared or
// operator-attached foothold and the task's surface; no model or corpus text reaches it.
func pivotDestination(g *secgate.Gate, r *engageRuntime, surface secgate.Surface) string {
	if r == nil || r.runner == nil || r.runner.foothold == nil || g == nil || g.Policy == nil {
		return ""
	}
	if !g.EffectiveFoothold().Covers(surface) {
		return ""
	}
	return g.EffectiveFoothold().Host
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
	budgetExempt := origin.BudgetExempt
	if len(stages) == 1 && secgate.BudgetExempt(secgate.Command{Binary: stages[0].Binary, Args: stages[0].Args}) {
		budgetExempt = true
	}
	id, remaining, err := r.trace.begin(origin.TaskID, "command", strings.Join(commands, " | "), len(stages), budgetExempt)
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
	rawSession := destination != "" && r.runner.foothold.name == "raw-session"
	msfSession := destination != "" && r.runner.foothold.name == "msf-rpc"
	httpForm := destination != "" && r.runner.foothold.name == "http-form"
	var plan engageEgressPlan
	var planErr error
	if destination != "" {
		if identity, ok := g.CloudIdentities[origin.Surface]; ok {
			exec = cloudCredentialStages(stages, identity)
		}
		if !rawSession && !msfSession && !httpForm {
			exec = footholdStages(r.runner.foothold, exec)
		}
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
	} else if rawSession {
		result, outputs = runRawSessionStages(ctx, r.runner.foothold.raw, exec, limit, timeout)
	} else if msfSession {
		result, outputs = runMSFRPCStages(ctx, r.runner.foothold.msf, exec, limit, timeout)
	} else if httpForm {
		result, outputs = runHTTPFormStages(ctx, r.runner, r.runner.foothold.form, exec, dir, limit, timeout, g.Policy, origin.UseRawWorker)
	} else {
		beforeClose := func(worker *engageRunner, action runResult, stagesOut []isolatedStageResult) {
			if r.staged == nil || r.store == nil || origin.TaskID == "" || ctx.Err() != nil || !stagesSucceeded(action, stagesOut, origin) {
				return
			}
			r.staged.note(dir, origin.TaskID, stages)
			scoped := *r
			scoped.runner = worker
			scanCtx := context.WithValue(ctx, engageRuntimeKey{}, &scoped)
			runStagedVulnScans(scanCtx, vulnScanDeps{Gate: g, Store: r.store}, r.staged, dir)
		}
		result, outputs = r.runner.RunScoped(ctx, exec, dir, limit, timeout, plan, g.Policy, origin.UseRawWorker, beforeClose)
	}
	if len(stages) == 1 && len(outputs) == 1 && result.Err != nil && !result.TimedOut {
		scanner := strings.ToLower(stages[0].Binary)
		if slices.Contains(vulnScanners(), scanner) && outputs[0].Dropped == 0 &&
			vulnScanResultBearing(scanner, outputs[0].ExitCode) && scanProducedReport(scanner, outputs[0].Stdout) &&
			result.Err.Error() == fmt.Sprintf("exit status %d", outputs[0].ExitCode) {
			result.Err = nil
		}
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
	// Material a command writes lives in the worker's tmpfs, so it is noted here and scanned before that worker is released.
	if status == "complete" && !plan.Dynamic && destination == "" && stagesSucceeded(result, outputs, origin) {
		r.staged.note(dir, origin.TaskID, stages)
	}
	if len(outputs) == 0 {
		outputs = []isolatedStageResult{{Stderr: result.Output, ExitCode: -1}}
	}
	result.ExitCode = outputs[len(outputs)-1].ExitCode
	result.Stdout = outputs[len(outputs)-1].Stdout
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
			continue
		}
		if origin.SkipVulnIngest || r.store == nil || origin.TaskID == "" || index >= len(stages) {
			continue
		}
		scanner := strings.ToLower(stages[index].Binary)
		if !slices.Contains(vulnScanners(), scanner) {
			continue
		}
		if status != "complete" || output.Dropped != 0 || !vulnScanResultBearing(scanner, output.ExitCode) || !scanProducedReport(scanner, output.Stdout) {
			_ = r.store.Audit("vulnscan", "scan-gap", origin.TaskID+" "+scanner+": no complete scanner report")
			continue
		}
		task, err := r.store.GetTask(origin.TaskID)
		if err == nil {
			_, err = ingestVulnOutput(ctx, r.store, task, scanner, output.Stdout)
		}
		if err != nil {
			_ = r.store.Audit("vulnscan", "ingest-failed", origin.TaskID+" "+scanner+": "+capRunes(err.Error(), 300))
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
		footholdPromptClause(g.EffectiveFoothold()) + promptguard.UntrustedInputClause
}

// footholdPromptClause tells the model which surfaces execute on the operator's
// foothold rather than in the runner, because the two destinations differ in
// ways that change what a command should look like: the foothold has its own
// installed tools, its own filesystem, and its own resolver, so the runner's
// pre-resolved /etc/hosts and its missing DNS do not apply there. The clause is
// derived from the operator's declaration or attachment; it states where
// commands go and never invites the model to choose.
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
