package main

import (
	"context"
	"fmt"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"

	"github.com/tmc/langchaingo/llms"
)

type surfaceExecutor interface {
	Run(ctx context.Context, task engagement.Task) (string, error)
}

// surfaceExecutors is the per-surface executor registry. Each future per-surface
// executor registers its factory from its OWN file via init() (registerExecutor),
// so no two surface sessions edit this file. Nothing is registered today, so
// executorFor falls back to genericExecutor for every surface, as before.
var surfaceExecutors = map[engagement.Surface]func(engageDeps) surfaceExecutor{}

// registerExecutor registers a factory for a surface. It is the seam the surface
// SPs fill in; call it once per surface from that surface's own file.
func registerExecutor(surface engagement.Surface, factory func(engageDeps) surfaceExecutor) {
	surfaceExecutors[surface] = factory
}

// executorFor selects the executor for a task by its Surface. A surface with a
// registered factory uses it; every other surface falls back to genericExecutor.
func executorFor(d engageDeps, task engagement.Task) surfaceExecutor {
	if factory, ok := surfaceExecutors[task.Surface]; ok {
		return factory(d)
	}
	return genericExecutor{d: d}
}

type genericExecutor struct {
	d engageDeps
}

// Run runs one domain-specialized executor for a task. It gets its own bounded
// projection and its own message slice; nothing is aliased across agents.
func (e genericExecutor) Run(ctx context.Context, task engagement.Task) (string, error) {

	v, err := e.d.Store.Vantage(ctx)
	if err != nil {
		return fmt.Sprintf("executor: task %s could not read the engagement vantage: %v", task.ID, err), nil
	}
	if v != "" && !v.Reaches(task.Surface) {
		return fmt.Sprintf("executor: task %s surface %q is not reachable at the current vantage %q; advance the vantage first", task.ID, task.Surface, v), nil
	}

	if e.d.ReconTiers && task.Phase == engagement.PhaseRecon && e.d.Gate != nil && e.d.Runs != nil {
		return e.runReconPhase(ctx, task)
	}

	if (task.Phase == engagement.PhaseExploit || task.Phase == engagement.PhasePostEx) && e.d.Gate != nil && e.d.Runs != nil {
		return e.runExploitPhase(ctx, task)
	}

	dom := domainForTask(task)

	reg := tooldef.NewRegistry()

	activeTask := func() string { return task.ID }
	tools := []tooldef.Tool{
		newKBSearchTool(e.d.RC, e.d.Cfg),
		newKBAnswerTool(e.d.RC, e.d.Cfg, !e.d.Prefs.Web),
		newPlanAddTool(e.d.Store),
		newPlanUpdateTool(e.d.Store),
		newRouteSkillTool(e.d.Catalog, e.d.Store, activeTask),
	}
	if e.d.Gate != nil && e.d.Runs != nil {
		runTimeout, runCap := resolveRunCaps()
		execDir, cleanup, err := newExecutorScratchDir(e.d.WorkDir)
		if err != nil {
			return "", err
		}
		defer cleanup()
		// Stamp the task's engagement context so the gate tiers each run_command
		// for its phase (exploit/post-ex require an armed task and force per-action
		// confirmation). secgate mirrors engagement's Phase/Surface by string value.
		cmdCtx := secgate.Command{
			Phase:   secgate.Phase(string(task.Phase)),
			Surface: secgate.Surface(string(task.Surface)),
			Armed:   task.Armed,

			Kind:   task.Kind,
			Target: task.Target,
		}
		// Help-grounding: ground each proposed command against the tool's real
		// interface before the gate authorizes it. nil ToolHelp disables it.
		grounder := newTaskGrounder(e.d.ToolHelp, e.d.Gate, execDir, cmdCtx)
		tools = append(tools,
			newRunCommandToolForTask(e.d.Gate, runCap, runTimeout, execDir, activeTask, e.d.Runs.Add, cmdCtx, grounder),
			newVerifiedRecordEvidenceTool(e.d.Store, e.d.Runs.Contains),
		)
	} else {
		tools = append(tools, newRecordEvidenceTool(e.d.Store))
	}
	for _, t := range tools {
		if err := reg.Register(t); err != nil {
			return "", err
		}
	}

	proj, err := projectionText(ctx, e.d.Store)
	if err != nil {
		return "", err
	}
	human := genericTaskPrompt(proj, task)
	msgs := []llms.MessageContent{
		{Role: llms.ChatMessageTypeSystem, Parts: []llms.ContentPart{llms.TextPart(dom.Prompt)}},
		{Role: llms.ChatMessageTypeHuman, Parts: []llms.ContentPart{llms.TextPart(human)}},
	}
	final, _, err := runToolLoop(ctx, e.d.Model, reg, msgs, LoopCaps{MaxRounds: 6, MaxCalls: 12})
	return final, err
}

func genericTaskPrompt(proj string, task engagement.Task) string {
	return fmt.Sprintf("Engagement state:\n%s\n\nYour task %s [%s]:\n target: %s\n objective: %s\n done when: %s\n\nExecute this task now. Advance the objective with the strongest evidence-backed action available. State the attack hypothesis, prerequisite, and expected signal, then make one bounded run_command call against the task target. Inspect the real output and adapt; record an exact quote of material output with record_evidence. If blocked, preserve the denial and its reason rather than retrying through another path. Do not call plan_add for this task; create a separate task only for a distinct, newly evidenced next step and link it with basis_ids.",
		proj, task.ID, task.Kind, task.Target, task.Objective, task.DoneWhen)
}
