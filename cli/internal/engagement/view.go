package engagement

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// Stage is where the harness is in the current step, for the live progress view.
type Stage struct {
	Label string
	Step  int
	Total int
	Tool  string
}

// Engagement is a point-in-time read of the whole engagement, for the REPL
// progress view. It is derived from the store; the store is the single source.
type Engagement struct {
	Revision int64
	Name     string
	Tasks    []Task
	ActiveID string
	Stage    Stage
}

// rowQueryer is the read subset shared by *sql.DB and *sql.Conn so meta and task
// reads work both inside and outside an Apply transaction.
type rowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// getMeta returns the value for key, or "" when the key is absent.
func getMeta(ctx context.Context, q rowQueryer, key string) (string, error) {
	var v string
	err := q.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

// allTasks returns every task ordered by creation revision then id.
func (s *Store) allTasks(ctx context.Context) ([]Task, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, kind, target, objective, done_when, status, depends_on, basis_ids, created_rev, updated_rev
		 FROM task ORDER BY created_rev ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Task{}
	for rows.Next() {
		var (
			t         Task
			status    string
			deps, bas sql.NullString
		)
		if err := rows.Scan(&t.ID, &t.Kind, &t.Target, &t.Objective, &t.DoneWhen, &status, &deps, &bas, &t.CreatedRev, &t.UpdatedRev); err != nil {
			return nil, err
		}
		t.Status = Status(status)
		if t.DependsOn, err = unmarshalStrings(deps.String); err != nil {
			return nil, err
		}
		if t.BasisIDs, err = unmarshalStrings(bas.String); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Snapshot returns the whole engagement as of now: revision, name, all tasks,
// the active task id, and the current stage. Missing meta rows read as zero.
func (s *Store) Snapshot(ctx context.Context) (Engagement, error) {
	var e Engagement
	rev, err := s.Revision(ctx)
	if err != nil {
		return Engagement{}, err
	}
	e.Revision = rev
	if e.Name, err = getMeta(ctx, s.db, "name"); err != nil {
		return Engagement{}, err
	}
	if e.ActiveID, err = getMeta(ctx, s.db, "active_id"); err != nil {
		return Engagement{}, err
	}
	stageJSON, err := getMeta(ctx, s.db, "stage")
	if err != nil {
		return Engagement{}, err
	}
	if stageJSON != "" {
		if err := json.Unmarshal([]byte(stageJSON), &e.Stage); err != nil {
			return Engagement{}, err
		}
	}
	if e.Tasks, err = s.allTasks(ctx); err != nil {
		return Engagement{}, err
	}
	return e, nil
}
