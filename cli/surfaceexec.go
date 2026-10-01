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

// executorFor selects the executor for a task by its Surface. Every surface maps
// to genericExecutor today; the switch is the seam the surface SPs fill in.
func executorFor(d engageDeps, task engagement.Task) surfaceExecutor {
	switch task.Surface {
	default:
		return genericExecutor{d: d}
	}
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
	dom := domainFor(task.Kind)

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
		}
		tools = append(tools,
			newRunCommandToolForTask(e.d.Gate, runCap, runTimeout, execDir, activeTask, e.d.Runs.Add, cmdCtx),
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
	human := fmt.Sprintf("Engagement state:\n%s\n\nYour task %s [%s]:\n target: %s\n objective: %s\n done when: %s\n\nWork this task now.",
		proj, task.ID, task.Kind, task.Target, task.Objective, task.DoneWhen)
	msgs := []llms.MessageContent{
		{Role: llms.ChatMessageTypeSystem, Parts: []llms.ContentPart{llms.TextPart(dom.Prompt)}},
		{Role: llms.ChatMessageTypeHuman, Parts: []llms.ContentPart{llms.TextPart(human)}},
	}
	final, _, err := runToolLoop(ctx, e.d.Model, reg, msgs, LoopCaps{MaxRounds: 6, MaxCalls: 12})
	return final, err
}
