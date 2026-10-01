package engagement

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
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

// rowQueryer is the single-row read subset shared by *sql.DB and *sql.Conn so
// meta reads work both inside and outside a transaction.
type rowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// rowsQueryer is the multi-row read subset shared by *sql.DB and *sql.Conn so
// task reads work both inside and outside a transaction.
type rowsQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
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

// readRevision reads the monotonic revision counter through q.
func readRevision(ctx context.Context, q rowQueryer) (int64, error) {
	var v string
	if err := q.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'revision'`).Scan(&v); err != nil {
		return 0, err
	}
	return strconv.ParseInt(v, 10, 64)
}

// scanAllTasks returns every task ordered by creation revision then id, read
// through q.
func scanAllTasks(ctx context.Context, q rowsQueryer) ([]Task, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT id, kind, target, objective, done_when, status, depends_on, basis_ids, created_rev, updated_rev, phase, surface, capability
		 FROM task ORDER BY created_rev ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Task{}
	for rows.Next() {
		var (
			t                      Task
			status                 string
			deps, bas              sql.NullString
			phase, surface, capVal sql.NullString
		)
		if err := rows.Scan(&t.ID, &t.Kind, &t.Target, &t.Objective, &t.DoneWhen, &status, &deps, &bas, &t.CreatedRev, &t.UpdatedRev, &phase, &surface, &capVal); err != nil {
			return nil, err
		}
		t.Status = Status(status)
		t.Phase = Phase(phase.String)
		t.Surface = Surface(surface.String)
		t.Capability = Capability(capVal.String)
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

func (s *Store) Snapshot(ctx context.Context) (Engagement, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return Engagement{}, err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN DEFERRED"); err != nil {
		return Engagement{}, err
	}
	committed := false
	defer func() {
		if !committed {
			conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	var e Engagement

	if e.Revision, err = readRevision(ctx, conn); err != nil {
		return Engagement{}, err
	}
	if e.Name, err = getMeta(ctx, conn, "name"); err != nil {
		return Engagement{}, err
	}
	if e.ActiveID, err = getMeta(ctx, conn, "active_id"); err != nil {
		return Engagement{}, err
	}
	stageJSON, err := getMeta(ctx, conn, "stage")
	if err != nil {
		return Engagement{}, err
	}
	if stageJSON != "" {
		if err := json.Unmarshal([]byte(stageJSON), &e.Stage); err != nil {
			return Engagement{}, err
		}
	}
	if e.Tasks, err = scanAllTasks(ctx, conn); err != nil {
		return Engagement{}, err
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return Engagement{}, err
	}
	committed = true
	return e, nil
}
