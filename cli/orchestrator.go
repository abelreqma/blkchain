package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/promptguard"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/skillcat"
	"blkchain/cli/internal/tooldef"

	"github.com/tmc/langchaingo/llms"
)

// engageDeps carries everything an engagement run needs. Asker is used by the
// orchestrator to ask the operator for clarification; in /auto it is an AutoAsker.
type engageDeps struct {
	Model toolLoopModel
	RC    searcher
	Cfg   ragconfig.Config
	Prefs modelPrefs
	Store *engagement.Store
	Asker askuser.Asker
	Gate  *secgate.Gate // command-execution gate for executors; nil disables run_command
	Runs  *RunOutputs   // per-episode captured command output for evidence verification
	// ToolHelp is the shared tool-knowledge cache backing help-grounding; nil
	// disables grounding (commands still pass through the gate unchanged).
	ToolHelp toolHelpCache
	// Confirmer is the optional human confirmer for /safe local mode; the mmdflux
	// viz session sets this. When nil, engagecmd falls back to the terminal
	// confirmer on a TTY.
	Confirmer secgate.Confirmer
	// WorkDir is the working directory run_command executes in (a per-engagement
	// scratch dir). Empty inherits the process's own cwd.
	WorkDir string
	// Catalog is the loaded skill catalog; nil or empty is safe and yields no
	// routable skills.
	Catalog *skillcat.Catalog
	// Progress, when set, is called after each committed plan mutation with the
	// new revision and a fresh snapshot, for a live view of the engagement. It is
	// nil-safe (nil disables it) and must not mutate the store.
	Progress    func(rev int64, snap engagement.Engagement)
	OnStop      func(reason string)
	MaxActions  int
	WallSeconds int
	// ReconTiers routes recon-phase tasks through the code-orchestrated recon tier
	// ladder (ReconLoop) instead of the generic single-pass executor loop. The
	// production composition root (buildEngageDeps) sets it; tests default it off
	// so the generic-loop regression tests keep their behavior.
	ReconTiers bool
	// ExploitTools is the operator's .blkchain/config.yaml exploit_tools list:
	// vetted structured-argv tools that extend the per-finding exploit-tier
	// allowlist for every exploit task. Empty is the code-owned default catalog only.
	// The engage entrypoints copy it from gatePolicy after buildEngageDeps.
	ExploitTools []string
	// ArmReq asks the operator when RoE auto-arm does not authorize the task.
	ArmReq      ArmRequester
	AutoActions *autoActionPolicy
}

var orchestratorSystemPrompt = "You are the orchestrator of a scoped offensive penetration test. " +
	"Own the end-to-end attack plan and drive it toward demonstrated impact: reconnaissance, reachable attack-path " +
	"validation, initial access, privilege escalation, lateral movement, and post-exploitation when they fit the objective " +
	"and rules of engagement; preserve the evidence needed for reporting. Use plan_add, plan_update, and plan_complete to shape " +
	"a task DAG over the store; use kb_search and kb_answer to ground technique choices when useful. " +
	"Begin where the goal, the chosen domain, and the current evidence point: when the goal already names a target, " +
	"domain, or foothold, plan directly toward it and use reconnaissance only to fill the specific gaps that path needs, " +
	"rather than defaulting to broad network scanning; when the goal is open-ended, build attack-surface breadth first. " +
	"Choose each task's tooling to fit the surface and the goal, not a fixed default. Then prioritize the strongest " +
	"evidence-backed paths by likelihood, impact, prerequisites, and test cost. Dispatch small batches of open task_ids with dispatch_batch; " +
	"use dispatch_agent for a single deep task. Executors return evidence; fold each result into the plan, use the updated " +
	"engagement vantage after demonstrated access, and create the next distinct task when a path is established. " +
	"Set basis_ids to the task or finding that supports each follow-on so the chain from observation to impact stays auditable. " +
	"You do not run commands against targets. Complete tasks only when exact-quote evidence supports the outcome; distinguish " +
	"confirmed access, failed hypotheses, blocked actions, and untested paths. " +
	"Before planning any task, read the current engagement state: never create a task that duplicates an open task or re-runs " +
	"something in the 'already discovered (do not repeat)' list. Each dispatch result ends with the refreshed state - use it, " +
	"advance to the next distinct step, and when coverage is sufficient for the goal, stop and return a final summary rather " +
	"than re-scanning. " +
	"Domains available for tasks: " + strings.Join(domainNames(), ", ") + ". " + promptguard.UntrustedInputClause

type dispatchArgs struct {
	TaskID string `json:"task_id" desc:"id of the open task to hand to a specialized executor"`
}

// markTaskActive returns a copy of task with Status set to active, for
// inclusion in an Apply Delta's Upserts. It does not call Store.Apply
// itself, so a caller dispatching several tasks at once (dispatch_batch) can
// collect one markTaskActive result per task into a single atomic Apply.
func markTaskActive(task engagement.Task) engagement.Task {
	task.Status = engagement.StatusActive
	return task
}

// newExecutorScratchDir creates a fresh per-executor scratch subdirectory
// under root, the engagement's scratch root (kept outside the workspace).
// Concurrent calls with the same root each get a distinct directory, since
// os.MkdirTemp is safe under concurrent use. An empty root means run_command
// is disabled, so no scratch dir is created; the returned cleanup is always
// safe to call.
func newExecutorScratchDir(root string) (dir string, cleanup func(), err error) {
	if root == "" {
		return "", func() {}, nil
	}
	dir, err = os.MkdirTemp(root, "exec-")
	if err != nil {
		return "", func() {}, err
	}
	return dir, func() { os.RemoveAll(dir) }, nil
}

// newDispatchAgentTool builds the orchestrator-only dispatch_agent tool.
func newDispatchAgentTool(d engageDeps) tooldef.Tool {
	return newStoreTool("dispatch_agent",
		"Hand one task to a domain-specialized executor agent. The domain is derived from the task kind. Returns the executor's evidence summary.",
		dispatchArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			var a dispatchArgs
			if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
				return "dispatch_agent: invalid arguments: " + err.Error(), nil
			}
			if strings.TrimSpace(a.TaskID) == "" {
				return "dispatch_agent: invalid arguments: task_id is required", nil
			}
			task, err := d.Store.GetTask(a.TaskID)
			if err != nil {
				return fmt.Sprintf("dispatch_agent: task %q not found", a.TaskID), nil
			}
			dom := domainFor(task.Kind)
			activeID := task.ID
			stage := engagement.Stage{Label: "dispatch", Tool: dom.Name}
			if _, err := d.Store.Apply(engagement.Delta{
				Kind:        "dispatch",
				Detail:      task.ID,
				Upserts:     []engagement.Task{markTaskActive(task)},
				SetActiveID: &activeID,
				SetStage:    &stage,
			}); err != nil {
				return "dispatch_agent: could not set stage: " + err.Error(), nil
			}
			out, rerr := runExecutor(ctx, d, task.ID)
			return withProjection(ctx, d.Store, out), rerr
		})
}

// withProjection appends the current engagement projection to a dispatch result.
// The orchestrator otherwise sees the projection (coverage, open tasks, and the
// "already discovered (do not repeat)" list) only in its opening message, so over
// a long loop it re-plans completed recon. Refreshing it after every dispatch
// keeps current state in front of the model. A projection error is non-fatal: the
// result is returned unchanged.
func withProjection(ctx context.Context, st *engagement.Store, result string) string {
	proj, err := projectionText(ctx, st)
	if err != nil || strings.TrimSpace(proj) == "" {
		return result
	}
	return result + "\n\n--- engagement state (refreshed; do not re-plan completed work) ---\n" + proj
}

const (
	maxBatchTasks       = 16
	engageParallelDef   = 3
	engageParallelMin   = 1
	engageParallelMax   = 8
	engageParallelEnv   = "BLKCHAIN_ENGAGE_PARALLEL"
	batchErrTaskDone    = "already done"
	batchErrTaskNA      = "marked not applicable"
	batchErrTaskUnknown = "not found"
	batchErrTaskBlocked = "blocked (not actionable; e.g. an ungrounded corpus-coverage-gap candidate)"
)

// engageParallel returns the cap on concurrently running executors in one
// dispatch_batch call, from BLKCHAIN_ENGAGE_PARALLEL clamped to 1..8. An unset
// or unparsable value gives the default of 3.
func engageParallel() int {
	return clampEnvInt(engageParallelEnv, engageParallelDef, engageParallelMin, engageParallelMax)
}

type dispatchBatchArgs struct {
	TaskIDs []string `json:"task_ids" desc:"ids of the open tasks to run concurrently, each on its own specialized executor (at most 16)"`
}

// batchResult is the outcome of one executor in a batch.
type batchResult struct {
	TaskID string
	Result string
	Err    error
}

// runBatch runs exec once per id, at most engageParallel() at a time, and
// returns the results sorted by task id so the aggregate does not depend on
// completion order. A panic in exec or a canceled context is recorded as that
// task's error; it never aborts the other tasks. All executors share d, so the
// engagement-wide Gate and Episode budget is not multiplied by concurrency.
func runBatch(ctx context.Context, d engageDeps, ids []string, exec func(ctx context.Context, d engageDeps, taskID string) (string, error)) []batchResult {
	sem := make(chan struct{}, engageParallel())
	results := make([]batchResult, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		results[i].TaskID = id
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			results[i].Err = ctx.Err()
			continue
		}
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					results[i].Err = fmt.Errorf("executor panic: %v", r)
				}
			}()
			results[i].Result, results[i].Err = exec(ctx, d, id)
		}(i, id)
	}
	wg.Wait()
	sortBatchResults(results)
	return results
}

func sortBatchResults(rs []batchResult) {
	sort.Slice(rs, func(a, b int) bool { return rs[a].TaskID < rs[b].TaskID })
}

// newDispatchBatchTool builds the orchestrator-only dispatch_batch tool, which
// runs several open tasks concurrently on the shared store, gate, and run
// captures.
func newDispatchBatchTool(d engageDeps) tooldef.Tool {
	return newDispatchBatchToolWith(d, runExecutor)
}

func newDispatchBatchToolWith(d engageDeps, exec func(ctx context.Context, d engageDeps, taskID string) (string, error)) tooldef.Tool {
	return newStoreTool("dispatch_batch",
		"Hand several independent open tasks to specialized executors that run concurrently (bounded). Returns one labeled result per task, sorted by task id. Use dispatch_agent for a single task.",
		dispatchBatchArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			var a dispatchBatchArgs
			if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
				return "dispatch_batch: invalid arguments: " + err.Error(), nil
			}
			if len(a.TaskIDs) == 0 {
				return "dispatch_batch: invalid arguments: task_ids is required", nil
			}
			if len(a.TaskIDs) > maxBatchTasks {
				return fmt.Sprintf("dispatch_batch: too many task_ids (%d, max %d)", len(a.TaskIDs), maxBatchTasks), nil
			}

			var valid []string
			var skipped []batchResult
			var upserts []engagement.Task
			seen := map[string]bool{}
			for _, id := range a.TaskIDs {
				id = strings.TrimSpace(id)
				if id == "" || seen[id] {
					continue
				}
				seen[id] = true
				task, err := d.Store.GetTask(id)
				if err != nil {
					skipped = append(skipped, batchResult{TaskID: id, Result: "skipped: task " + batchErrTaskUnknown})
					continue
				}
				if task.Status == engagement.StatusDone {
					skipped = append(skipped, batchResult{TaskID: id, Result: "skipped: task is " + batchErrTaskDone})
					continue
				}
				if task.Status == engagement.StatusNA {
					skipped = append(skipped, batchResult{TaskID: id, Result: "skipped: task is " + batchErrTaskNA})
					continue
				}
				// A blocked task is not actionable: the model never auto-dispatches an
				// ungrounded corpus-coverage-gap candidate (citation-gate
				// enforcement). It stays operator-visible and can be re-planned once
				// grounded; arming is separately refused by armTask.
				if task.Status == engagement.StatusBlocked {
					skipped = append(skipped, batchResult{TaskID: id, Result: "skipped: task is " + batchErrTaskBlocked})
					continue
				}
				valid = append(valid, id)
				upserts = append(upserts, markTaskActive(task))
			}

			var results []batchResult
			if len(valid) > 0 {
				stage := engagement.Stage{Label: "dispatch", Tool: "batch"}
				if _, err := d.Store.Apply(engagement.Delta{
					Kind:     "dispatch_batch",
					Detail:   strings.Join(valid, ","),
					Upserts:  upserts,
					SetStage: &stage,
				}); err != nil {
					return "dispatch_batch: could not mark tasks active: " + err.Error(), nil
				}
				results = runBatch(ctx, d, valid, exec)
			}
			results = append(results, skipped...)
			sortBatchResults(results)

			var b strings.Builder
			for i, r := range results {
				if i > 0 {
					b.WriteString("\n\n")
				}
				fmt.Fprintf(&b, "== %s ==\n", r.TaskID)
				if r.Err != nil {
					fmt.Fprintf(&b, "error: %v", r.Err)
					if r.Result != "" {
						b.WriteString("\n" + r.Result)
					}
					continue
				}
				b.WriteString(r.Result)
			}
			return withProjection(ctx, d.Store, b.String()), nil
		})
}

// runExecutor runs one surface-specialized executor for a task id. It is the
// adapter dispatch_agent/dispatch_batch call; it fetches the task and routes to
// executorFor(d, task).Run.
func runExecutor(ctx context.Context, d engageDeps, taskID string) (string, error) {
	task, err := d.Store.GetTask(taskID)
	if err != nil {
		return fmt.Sprintf("executor: task %q not found", taskID), nil
	}
	return executorFor(d, task).Run(ctx, task)
}

// runOrchestrator runs the top-level engagement loop for a goal.
func runOrchestrator(ctx context.Context, d engageDeps, goal string) (final string, runErr error) {
	runCtx, cancelRun := context.WithCancelCause(ctx)
	defer cancelRun(nil)
	ctx = withExecutorStop(runCtx, cancelRun)
	if d.Gate != nil {
		ctx = withExecutorScope(ctx, d.Gate.Scope)
	}
	ctx, stopBudget, err := engageBudgetContext(ctx, d.Store, d.MaxActions, d.WallSeconds)
	if err != nil {
		return "", err
	}
	defer stopBudget()
	defer func() {
		cause := context.Cause(runCtx)
		if cause == nil || errors.Is(cause, context.Canceled) {
			cause = context.Cause(ctx)
		}
		if cause != nil && !errors.Is(cause, context.Canceled) && !errors.Is(cause, context.DeadlineExceeded) &&
			!errors.Is(cause, errEngageWorkBudget) && !errors.Is(cause, errEngageWallBudget) && !errors.Is(runErr, cause) {
			if errors.Is(runErr, context.Canceled) {
				runErr = cause
			} else {
				runErr = errors.Join(runErr, cause)
			}
		}
	}()
	defer func() {
		if report, stopped, stopErr := engageBudgetStop(ctx, d.Store, goal); stopped {
			if d.OnStop != nil {
				d.OnStop("engagement budget")
			}
			final, runErr = report, stopErr
		}
	}()
	if d.Progress != nil {
		remove := d.Store.AddOnApply(d.Progress)
		defer remove()
	}
	// Attach every multi-flow on-apply listener registered via registerOnApply.
	// This runs in all engage flows (CLI/REPL/MCP) because they funnel through
	// here. Each listener is removed when the engagement loop returns.
	for _, fn := range onApplyListeners {
		remove := d.Store.AddOnApply(fn)
		defer remove()
	}
	reg := tooldef.NewRegistry()
	// Evidence is verified against the shared per-episode capture when present,
	// so the orchestrator cannot record a quote no executor actually captured.
	recordEvidence := newRecordEvidenceTool(d.Store)
	if d.Runs != nil {
		recordEvidence = newVerifiedRecordEvidenceTool(d.Store, d.Runs.Contains)
	}
	for _, t := range []tooldef.Tool{
		newKBSearchTool(d.RC, d.Cfg),
		newKBAnswerTool(d.RC, d.Cfg, !d.Prefs.Web),
		newPlanAddTool(d.Store),
		newPlanUpdateTool(d.Store),
		newPlanCompleteTool(d.Store),
		recordEvidence,
		newAskUserTool(d.Asker),
		newDispatchAgentTool(d),
		newDispatchBatchTool(d),
	} {
		if err := reg.Register(t); err != nil {
			return "", err
		}
	}

	proj, err := projectionText(ctx, d.Store)
	if err != nil {
		return "", err
	}
	human := fmt.Sprintf("Engagement state:\n%s\n\nGoal: %s\n\nPlan and drive this engagement one task at a time.", proj, goal)
	msgs := []llms.MessageContent{
		{Role: llms.ChatMessageTypeSystem, Parts: []llms.ContentPart{llms.TextPart(orchestratorSystemPrompt)}},
		{Role: llms.ChatMessageTypeHuman, Parts: []llms.ContentPart{llms.TextPart(human)}},
	}
	var options []llms.CallOption
	if model := strings.TrimSpace(os.Getenv("BLKCHAIN_ENGAGE_ORCHESTRATOR_MODEL")); model != "" {
		options = append(options, llms.WithModel(model))
	}
	caps := engageLoopCaps()
	finalized := false
	caps.Progress = func(ctx context.Context) (string, error) { return engagementProgress(ctx, d.Store) }
	caps.Finalize = func(ctx context.Context, reason string) (string, error) {
		if err := consumeEngageWork(ctx); err != nil {
			return "", err
		}
		finalized = true
		if d.OnStop != nil {
			d.OnStop(reason)
		}
		return synthesizeEngagement(ctx, d, goal, reason, options...)
	}
	final, _, err = runToolLoop(ctx, d.Model, reg, msgs, caps, options...)
	if finalized {
		return final, err
	}
	if err == nil {
		if strings.TrimSpace(final) == "" {
			report, reportErr := engagementStoreReport(ctx, d.Store, goal)
			if reportErr != nil {
				return "", reportErr
			}
			if d.OnStop != nil {
				d.OnStop("empty final response")
			}
			return "Engagement paused: empty final response.\n\n" + boundedEngageReport(report), nil
		}
		if len([]rune(final)) > 65536 {
			if d.OnStop != nil {
				d.OnStop("oversized final response")
			}
			return "Engagement paused: oversized final response.\n\n" + capRunes(final, 65536) + "\n[final response truncated]", nil
		}
		snap, snapErr := d.Store.Snapshot(ctx)
		if snapErr != nil {
			return "", snapErr
		}
		for _, task := range snap.Tasks {
			if task.Status == engagement.StatusTodo || task.Status == engagement.StatusActive || task.Status == engagement.StatusBlocked {
				if d.OnStop != nil {
					d.OnStop("open tasks remain")
				}
				return "Engagement paused: open tasks remain.\n\n" + final, nil
			}
		}
	}
	return final, err
}

type askUserArgs struct {
	Question    string          `json:"question" desc:"the clarification to ask the user"`
	Detail      string          `json:"detail,omitempty" desc:"optional extra context for the question"`
	Options     []askUserOption `json:"options,omitempty" desc:"offered answers"`
	AllowCustom bool            `json:"allow_custom,omitempty" desc:"whether the user may type a custom answer"`
}

type askUserOption struct {
	Label string `json:"label" desc:"short label shown to the user"`
	Note  string `json:"note,omitempty" desc:"optional explanation"`
	Value string `json:"value" desc:"the value returned if this option is chosen"`
}

// newAskUserTool exposes the clarification protocol as a tool. In /auto the
// AutoAsker returns a canceled result, so the orchestrator proceeds without a
// human.
func newAskUserTool(a askuser.Asker) tooldef.Tool {
	if a == nil {
		a = askuser.AutoAsker{}
	}
	return newStoreTool("ask_user",
		"Ask the user a clarifying question. In autonomous mode this is suppressed and returns a canceled result.",
		askUserArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			var in askUserArgs
			if err := json.Unmarshal([]byte(argsJSON), &in); err != nil {
				return "ask_user: invalid arguments: " + err.Error(), nil
			}
			if strings.TrimSpace(in.Question) == "" {
				return "ask_user: invalid arguments: question is required", nil
			}
			c := askuser.Clarification{Question: in.Question, Detail: in.Detail, AllowCustom: in.AllowCustom}
			for _, o := range in.Options {
				c.Options = append(c.Options, askuser.ClarifyOption{Label: o.Label, Note: o.Note, Value: o.Value})
			}
			r := a.Ask(ctx, c)
			if r.Canceled {
				return "user canceled or clarification suppressed", nil
			}
			if strings.TrimSpace(r.Custom) != "" {
				return "user answered: " + r.Custom, nil
			}
			if strings.TrimSpace(r.Value) == "" {
				return "user gave no answer", nil
			}
			return "user chose: " + r.Value, nil
		})
}
