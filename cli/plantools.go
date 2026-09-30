package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/tooldef"
)

type planTaskArgs struct {
	ID        string   `json:"id" desc:"stable task id, e.g. t1"`
	Kind      string   `json:"kind,omitempty" desc:"task kind or domain, e.g. recon, web, ad, cloud"`
	Target    string   `json:"target,omitempty" desc:"the in-scope target the task acts on"`
	Objective string   `json:"objective,omitempty" desc:"what the task should achieve"`
	DoneWhen  string   `json:"done_when,omitempty" desc:"the observable condition that completes the task"`
	Status    string   `json:"status,omitempty" desc:"todo, active, done, na, or blocked; defaults to todo"`
	DependsOn []string `json:"depends_on,omitempty" desc:"ids of tasks that must finish first"`
}

type planCompleteArgs struct {
	ID string `json:"id" desc:"id of the task to mark done"`
}

type recordEvidenceArgs struct {
	TaskID string `json:"task_id" desc:"id of the task the evidence belongs to"`
	Quote  string `json:"quote" desc:"an exact quote of real tool or command output"`
}

func planTaskFromArgs(a planTaskArgs) engagement.Task {
	status := engagement.Status(a.Status)
	if status == "" {
		status = engagement.StatusTodo
	}
	return engagement.Task{
		ID:        a.ID,
		Kind:      a.Kind,
		Target:    a.Target,
		Objective: a.Objective,
		DoneWhen:  a.DoneWhen,
		Status:    status,
		DependsOn: a.DependsOn,
	}
}

func newPlanAddTool(st *engagement.Store) tooldef.Tool {
	return newStoreTool("plan_add",
		"Add a task to the engagement plan. Provide a stable id and its kind, target, and objective.",
		planTaskArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			var a planTaskArgs
			if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
				return "plan_add: invalid arguments: " + err.Error(), nil
			}
			rev, err := st.Apply(engagement.Delta{
				Upserts: []engagement.Task{planTaskFromArgs(a)},
				Kind:    "plan_add",
				Detail:  a.ID,
			})
			if err != nil {
				return "plan_add: rejected: " + err.Error(), nil
			}
			return fmt.Sprintf("added task %s (revision %d)", a.ID, rev), nil
		})
}

func newPlanUpdateTool(st *engagement.Store) tooldef.Tool {
	return newStoreTool("plan_update",
		"Update an existing task in the engagement plan. Only the fields you provide change; omitted fields keep their current values. The task must already exist (use plan_add to create one).",
		planTaskArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			var a planTaskArgs
			if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
				return "plan_update: invalid arguments: " + err.Error(), nil
			}
			cur, err := st.GetTask(a.ID)
			if errors.Is(err, engagement.ErrNotFound) {
				return "plan_update: task " + a.ID + " not found", nil
			}
			if err != nil {
				return "plan_update: " + err.Error(), nil
			}
			if a.Kind != "" {
				cur.Kind = a.Kind
			}
			if a.Target != "" {
				cur.Target = a.Target
			}
			if a.Objective != "" {
				cur.Objective = a.Objective
			}
			if a.DoneWhen != "" {
				cur.DoneWhen = a.DoneWhen
			}
			if a.Status != "" {
				cur.Status = engagement.Status(a.Status)
			}
			if len(a.DependsOn) > 0 {
				cur.DependsOn = a.DependsOn
			}
			rev, err := st.Apply(engagement.Delta{
				Upserts: []engagement.Task{cur},
				Kind:    "plan_update",
				Detail:  a.ID,
			})
			if err != nil {
				return "plan_update: rejected: " + err.Error(), nil
			}
			return fmt.Sprintf("updated task %s (revision %d)", a.ID, rev), nil
		})
}

func newPlanCompleteTool(st *engagement.Store) tooldef.Tool {
	return newStoreTool("plan_complete",
		"Mark a task done. A task should be completed only when exact-quote evidence exists for it.",
		planCompleteArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			var a planCompleteArgs
			if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
				return "plan_complete: invalid arguments: " + err.Error(), nil
			}
			if strings.TrimSpace(a.ID) == "" {
				return "plan_complete: invalid arguments: id is required", nil
			}
			rev, err := st.Apply(engagement.Delta{Completes: []string{a.ID}, Kind: "plan_complete", Detail: a.ID})
			if err != nil {
				return "plan_complete: rejected: " + err.Error(), nil
			}
			return fmt.Sprintf("completed task %s (revision %d)", a.ID, rev), nil
		})
}

func newRecordEvidenceTool(st *engagement.Store) tooldef.Tool {
	return newStoreTool("record_evidence",
		"Store an exact quote of real tool or command output as evidence for a task.",
		recordEvidenceArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			var a recordEvidenceArgs
			if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
				return "record_evidence: invalid arguments: " + err.Error(), nil
			}
			if strings.TrimSpace(a.TaskID) == "" || strings.TrimSpace(a.Quote) == "" {
				return "record_evidence: invalid arguments: task_id and quote are required", nil
			}
			id, err := st.RecordEvidence(a.TaskID, a.Quote)
			if err != nil {
				return "record_evidence: " + err.Error(), nil
			}
			return fmt.Sprintf("recorded evidence %d for task %s", id, a.TaskID), nil
		})
}

// storeTool is a tooldef.Tool backed by a function, mirroring kbTool.
type storeTool struct {
	name, desc string
	schema     map[string]any
	call       func(ctx context.Context, argsJSON string) (string, error)
}

func (t storeTool) Name() string           { return t.name }
func (t storeTool) Description() string    { return t.desc }
func (t storeTool) Schema() map[string]any { return t.schema }
func (t storeTool) Call(ctx context.Context, argsJSON string) (string, error) {
	return t.call(ctx, argsJSON)
}

// newStoreTool builds a storeTool, generating the arg schema from argsProto.
func newStoreTool(name, desc string, argsProto any, call func(ctx context.Context, argsJSON string) (string, error)) tooldef.Tool {
	schema, err := tooldef.SchemaFor(argsProto)
	if err != nil {
		panic(err) // static struct; a failure is a programming error
	}
	return storeTool{name: name, desc: desc, schema: schema, call: call}
}
