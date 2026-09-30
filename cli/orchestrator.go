package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
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
	// WorkDir is the working directory run_command executes in (a per-engagement
	// scratch dir). Empty inherits the process's own cwd.
	WorkDir string
}

var orchestratorSystemPrompt = "You are the orchestrator of an authorized, single-user, offline security-testing engagement. " +
	"You own the task plan. Use plan_add, plan_update, and plan_complete to shape a task DAG over the store; " +
	"use kb_search and kb_answer to ground your reasoning when it helps. " +
	"Select one open task at a time and hand it to a specialized executor with dispatch_agent (pass its task_id); " +
	"the executor works the task and returns evidence, which you fold back into the plan. " +
	"You do not run commands against targets. Complete a task only when exact-quote evidence exists for it. " +
	"Domains available for tasks: " + strings.Join(domainNames(), ", ") + "."

type dispatchArgs struct {
	TaskID string `json:"task_id" desc:"id of the open task to hand to a specialized executor"`
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
				SetActiveID: &activeID,
				SetStage:    &stage,
			}); err != nil {
				return "dispatch_agent: could not set stage: " + err.Error(), nil
			}
			return runExecutor(ctx, d, task.ID)
		})
}

// runExecutor runs one domain-specialized executor for a task. It gets its own
// bounded projection and its own message slice; nothing is aliased across
// agents.
func runExecutor(ctx context.Context, d engageDeps, taskID string) (string, error) {
	task, err := d.Store.GetTask(taskID)
	if err != nil {
		return fmt.Sprintf("executor: task %q not found", taskID), nil
	}
	dom := domainFor(task.Kind)

	reg := tooldef.NewRegistry()
	tools := []tooldef.Tool{
		newKBSearchTool(d.RC, d.Cfg),
		newKBAnswerTool(d.RC, d.Cfg, !d.Prefs.Web),
		newPlanAddTool(d.Store),
		newPlanUpdateTool(d.Store),
	}
	if d.Gate != nil && d.Runs != nil {
		activeTask := func() string {
			snap, err := d.Store.Snapshot(ctx)
			if err != nil {
				return ""
			}
			return snap.ActiveID
		}
		tools = append(tools,
			newRunCommandTool(d.Gate, runCommandCapBytes, runCommandTimeout, d.WorkDir, activeTask, d.Runs.Add),
			newVerifiedRecordEvidenceTool(d.Store, d.Runs.Contains),
		)
	} else {
		tools = append(tools, newRecordEvidenceTool(d.Store))
	}
	for _, t := range tools {
		if err := reg.Register(t); err != nil {
			return "", err
		}
	}

	proj, err := projectionText(ctx, d.Store)
	if err != nil {
		return "", err
	}
	human := fmt.Sprintf("Engagement state:\n%s\n\nYour task %s [%s]:\n target: %s\n objective: %s\n done when: %s\n\nWork this task now.",
		proj, task.ID, task.Kind, task.Target, task.Objective, task.DoneWhen)
	msgs := []llms.MessageContent{
		{Role: llms.ChatMessageTypeSystem, Parts: []llms.ContentPart{llms.TextPart(dom.Prompt)}},
		{Role: llms.ChatMessageTypeHuman, Parts: []llms.ContentPart{llms.TextPart(human)}},
	}
	final, _, err := runToolLoop(ctx, d.Model, reg, msgs, LoopCaps{MaxRounds: 6, MaxCalls: 12})
	return final, err
}

// runOrchestrator runs the top-level engagement loop for a goal.
func runOrchestrator(ctx context.Context, d engageDeps, goal string) (string, error) {
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
	final, _, err := runToolLoop(ctx, d.Model, reg, msgs, LoopCaps{MaxRounds: 8, MaxCalls: 16})
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
