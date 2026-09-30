package engagement

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// Status is the lifecycle state of a task.
type Status string

const (
	StatusTodo    Status = "todo"
	StatusActive  Status = "active"
	StatusDone    Status = "done"
	StatusNA      Status = "na"
	StatusBlocked Status = "blocked"
)

func (s Status) valid() bool {
	switch s {
	case StatusTodo, StatusActive, StatusDone, StatusNA, StatusBlocked:
		return true
	}
	return false
}

// Task is one unit of engagement work.
type Task struct {
	ID         string
	Kind       string
	Target     string
	Objective  string
	DoneWhen   string
	Status     Status
	DependsOn  []string
	BasisIDs   []string
	CreatedRev int64
	UpdatedRev int64
}

// ErrNotFound is returned when a task id does not exist.
var ErrNotFound = errors.New("engagement: task not found")

// marshalStrings encodes a string slice as JSON text; nil and empty give "[]".
func marshalStrings(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// unmarshalStrings decodes JSON text into a string slice; "" and "[]" give an
// empty slice.
func unmarshalStrings(s string) ([]string, error) {
	if s == "" {
		return []string{}, nil
	}
	out := []string{}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetTask returns the task with the given id, or ErrNotFound.
func (s *Store) GetTask(id string) (Task, error) {
	var (
		t         Task
		status    string
		deps, bas sql.NullString
	)
	err := s.db.QueryRow(
		`SELECT id, kind, target, objective, done_when, status, depends_on, basis_ids, created_rev, updated_rev
		 FROM task WHERE id = ?`, id).
		Scan(&t.ID, &t.Kind, &t.Target, &t.Objective, &t.DoneWhen, &status, &deps, &bas, &t.CreatedRev, &t.UpdatedRev)
	if errors.Is(err, sql.ErrNoRows) {
		return Task{}, ErrNotFound
	}
	if err != nil {
		return Task{}, err
	}
	t.Status = Status(status)
	if t.DependsOn, err = unmarshalStrings(deps.String); err != nil {
		return Task{}, err
	}
	if t.BasisIDs, err = unmarshalStrings(bas.String); err != nil {
		return Task{}, err
	}
	return t, nil
}

// Revision returns the current engagement revision counter.
func (s *Store) Revision(ctx context.Context) (int64, error) {
	return readRevision(ctx, s.db)
}
