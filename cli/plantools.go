package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/tooldef"
)

type planTaskArgs struct {
	ID         string   `json:"id" desc:"stable task id, e.g. t1"`
	Kind       string   `json:"kind,omitempty" desc:"task kind or domain, e.g. recon, web, ad, cloud"`
	Target     string   `json:"target,omitempty" desc:"the in-scope target the task acts on"`
	Objective  string   `json:"objective,omitempty" desc:"what the task should achieve"`
	DoneWhen   string   `json:"done_when,omitempty" desc:"the observable condition that completes the task"`
	Status     string   `json:"status,omitempty" desc:"todo, active, done, na, or blocked; defaults to todo"`
	Phase      string   `json:"phase,omitempty" desc:"recon, exploit, post-ex, or report; defaults to recon"`
	Surface    string   `json:"surface,omitempty" desc:"local, network, web, ad, cloud (or cloud-aws/cloud-gcp/cloud-azure), container, or ai-security; defaults from kind"`
	Capability string   `json:"capability,omitempty" desc:"passive, enumerate, or active"`
	DependsOn  []string `json:"depends_on,omitempty" desc:"ids of tasks that must finish first"`
	BasisIDs   []string `json:"basis_ids,omitempty" desc:"ids of the task(s) or finding(s) this task was derived from (provenance; not a scheduling dependency)"`
}

type planCompleteArgs struct {
	ID          string  `json:"id" desc:"id of the task to mark done"`
	Basis       string  `json:"basis" desc:"how the cited evidence meets the task's done_when condition"`
	EvidenceIDs []int64 `json:"evidence_ids" desc:"the record_evidence ids of the quotes that establish done_when"`
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
		ID:         a.ID,
		Kind:       a.Kind,
		Target:     a.Target,
		Objective:  a.Objective,
		DoneWhen:   a.DoneWhen,
		Status:     status,
		Phase:      engagement.Phase(a.Phase),
		Surface:    engagement.Surface(a.Surface),
		Capability: engagement.Capability(a.Capability),
		DependsOn:  a.DependsOn,
		BasisIDs:   a.BasisIDs,
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
			if strings.EqualFold(strings.TrimSpace(a.Status), string(engagement.StatusDone)) {
				return "plan_add: cannot set status done directly; record_evidence then plan_complete", nil
			}
			if existing, err := st.GetTask(a.ID); err == nil && existing.CodeCandidate {
				return "plan_add: code-derived candidate cannot be replaced by a model task", nil
			} else if err != nil && !errors.Is(err, engagement.ErrNotFound) {
				return "plan_add: " + err.Error(), nil
			}
			// Storm guard: under repeated command failure an executor loop otherwise
			// re-adds near-identical recon tasks. Reject a plan_add that duplicates an
			// OPEN task on (kind, target, objective, surface). Re-adding the same id
			// is an update, not a storm, so it is allowed.
			if dup, err := findOpenDuplicateTask(st, a); err != nil {
				return "plan_add: " + err.Error(), nil
			} else if dup != "" && dup != a.ID {
				return fmt.Sprintf("plan_add: duplicate of open task %s (same kind/target/objective/surface); not added", dup), nil
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

func findOpenDuplicateTask(st *engagement.Store, a planTaskArgs) (string, error) {
	snap, err := st.Snapshot(context.Background())
	if err != nil {
		return "", err
	}
	k := strings.TrimSpace(a.Kind)
	tg := strings.TrimSpace(a.Target)
	ob := strings.TrimSpace(a.Objective)
	sf := strings.TrimSpace(a.Surface)
	for _, t := range snap.Tasks {
		if t.Status != engagement.StatusTodo && t.Status != engagement.StatusActive {
			continue
		}
		if strings.TrimSpace(t.Kind) != k || strings.TrimSpace(t.Target) != tg || strings.TrimSpace(t.Objective) != ob {
			continue
		}
		if sf != "" && strings.TrimSpace(string(t.Surface)) != sf {
			continue
		}
		return t.ID, nil
	}
	return "", nil
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
			if strings.EqualFold(strings.TrimSpace(a.Status), string(engagement.StatusDone)) {
				return "plan_update: cannot set status done directly; record_evidence then plan_complete", nil
			}
			cur, err := st.GetTask(a.ID)
			if errors.Is(err, engagement.ErrNotFound) {
				return "plan_update: task " + a.ID + " not found", nil
			}
			if err != nil {
				return "plan_update: " + err.Error(), nil
			}
			if cur.CodeCandidate {
				if (a.Kind != "" && a.Kind != cur.Kind) || (a.Target != "" && a.Target != cur.Target) ||
					(a.Phase != "" && a.Phase != string(cur.Phase)) || (a.Surface != "" && a.Surface != string(cur.Surface)) {
					return "plan_update: code-derived candidate identity cannot be changed", nil
				}
				if cur.Status == engagement.StatusBlocked && a.Status != "" && a.Status != string(engagement.StatusBlocked) {
					return "plan_update: blocked code-derived candidate needs code-owned grounding", nil
				}
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
			if a.Phase != "" {
				cur.Phase = engagement.Phase(a.Phase)
			}
			if a.Surface != "" {
				cur.Surface = engagement.Surface(a.Surface)
			}
			if a.Capability != "" {
				cur.Capability = engagement.Capability(a.Capability)
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

// newPlanCompleteTool builds plan_complete. Recorded evidence alone does not
// show that a task met its success condition, so completion also requires a
// stated done_when, a basis relating the evidence to it, and the evidence ids
// that basis cites. Code checks that each cited id is a real evidence row of
// that task; the basis itself is the caller's assertion and is stored as such.
func newPlanCompleteTool(st *engagement.Store) tooldef.Tool {
	return newStoreTool("plan_complete",
		"Mark a task done. The task needs a done_when condition, recorded evidence, the ids of the evidence that establishes that condition, and a basis saying how it does.",
		planCompleteArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			var a planCompleteArgs
			if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
				return "plan_complete: invalid arguments: " + err.Error(), nil
			}
			if strings.TrimSpace(a.ID) == "" {
				return "plan_complete: invalid arguments: id is required", nil
			}
			task, err := st.GetTask(a.ID)
			if errors.Is(err, engagement.ErrNotFound) {
				return "plan_complete: task " + a.ID + " not found", nil
			}
			if err != nil {
				return "plan_complete: " + err.Error(), nil
			}
			if strings.TrimSpace(task.DoneWhen) == "" {
				return "plan_complete: cannot complete " + a.ID + " without a done_when condition; plan_update it with the observable condition the task must meet, then complete it", nil
			}
			rows, err := st.EvidenceRowsFor(a.ID)
			if err != nil {
				return "plan_complete: " + err.Error(), nil
			}
			if len(rows) == 0 {
				return "plan_complete: cannot complete " + a.ID + " without recorded evidence; run the task, then record_evidence an exact quote of its output first", nil
			}
			if strings.TrimSpace(a.Basis) == "" {
				return "plan_complete: cannot complete " + a.ID + " without a basis; state how the recorded evidence meets its done_when condition", nil
			}
			cited, err := citedEvidenceIDs(rows, a.EvidenceIDs)
			if err != nil {
				return "plan_complete: " + err.Error(), nil
			}
			rev, err := st.Apply(engagement.Delta{
				Completes:             []string{a.ID},
				CompletionBasis:       a.Basis,
				CompletionEvidenceIDs: cited,
				Kind:                  "plan_complete",
				Detail:                a.ID,
			})
			if err != nil {
				return "plan_complete: rejected: " + err.Error(), nil
			}
			return fmt.Sprintf("completed task %s (revision %d)", a.ID, rev), nil
		})
}

// citedEvidenceIDs returns the cited ids as decimal strings, in the order given
// and without repeats. Every id must be an evidence row of the same task, so a
// completion cannot cite evidence that does not exist or belongs elsewhere.
func citedEvidenceIDs(rows []engagement.EvidenceRow, cited []int64) ([]string, error) {
	if len(cited) == 0 {
		return nil, errors.New("evidence_ids is required; cite the record_evidence ids whose quotes establish the done_when condition")
	}
	known := make(map[int64]bool, len(rows))
	for _, r := range rows {
		known[r.ID] = true
	}
	seen := map[int64]bool{}
	out := make([]string, 0, len(cited))
	for _, id := range cited {
		if !known[id] {
			return nil, fmt.Errorf("evidence %d is not recorded evidence for this task; cite an id record_evidence returned for it", id)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, strconv.FormatInt(id, 10))
	}
	return out, nil
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

// newVerifiedRecordEvidenceTool is record_evidence that accepts only a quote
// verify() confirms is a real substring of captured command output for the task.
func newVerifiedRecordEvidenceTool(st *engagement.Store, verify func(taskID, quote string) bool) tooldef.Tool {
	return newStoreTool("record_evidence",
		"Store an exact quote of real tool or command output as evidence for a task. The quote must appear verbatim in output run_command produced for that task.",
		recordEvidenceArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			var a recordEvidenceArgs
			if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
				return "record_evidence: invalid arguments: " + err.Error(), nil
			}
			if strings.TrimSpace(a.TaskID) == "" || strings.TrimSpace(a.Quote) == "" {
				return "record_evidence: invalid arguments: task_id and quote are required", nil
			}
			if verify != nil && !verify(a.TaskID, a.Quote) {
				return "record_evidence: rejected: the quote must be an exact quote of real command output for this task; run_command first and quote its output verbatim", nil
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
