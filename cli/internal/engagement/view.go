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
	// Vantage is the engagement's access context ("" when unset). It is read from
	// meta and advanced via Delta.SetVantage.
	Vantage Vantage
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
	return scanTasks(ctx, q, 0)
}

func scanTasks(ctx context.Context, q rowsQueryer, limit int) ([]Task, error) {
	query := `SELECT id, kind, target, objective, done_when, status, depends_on, basis_ids, created_rev, updated_rev, phase, surface, capability, armed, coverage_gap, code_candidate, citation, advisory, completion_basis, completion_evidence
		 FROM task ORDER BY created_rev ASC, id ASC`
	if limit > 0 {
		query = `SELECT substr(id, 1, 256), substr(kind, 1, 256), substr(target, 1, 1024), substr(objective, 1, 1024), substr(done_when, 1, 1024), status,
		 CASE WHEN length(depends_on) <= 4096 THEN depends_on ELSE NULL END,
		 CASE WHEN length(basis_ids) <= 4096 THEN basis_ids ELSE NULL END,
		 created_rev, updated_rev, phase, surface, capability, armed, coverage_gap, code_candidate,
		 CASE WHEN length(citation) <= 4096 THEN citation ELSE NULL END, substr(advisory, 1, 1024),
		 substr(completion_basis, 1, 1024),
		 CASE WHEN length(completion_evidence) <= 4096 THEN completion_evidence ELSE NULL END
		 FROM task ORDER BY CASE WHEN status IN ('todo', 'active') THEN 0 ELSE 1 END, created_rev ASC, id ASC LIMIT ?`
	}
	var args []any
	if limit > 0 {
		args = append(args, limit)
	}
	rows, err := q.QueryContext(ctx,
		query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Task{}
	for rows.Next() {
		var (
			t                          Task
			status                     string
			deps, bas                  sql.NullString
			phase, surface, capVal     sql.NullString
			cit                        sql.NullString
			advisory                   sql.NullString
			basis, citedEv             sql.NullString
			armed                      sql.NullInt64
			coverageGap, codeCandidate sql.NullInt64
		)
		if err := rows.Scan(&t.ID, &t.Kind, &t.Target, &t.Objective, &t.DoneWhen, &status, &deps, &bas, &t.CreatedRev, &t.UpdatedRev, &phase, &surface, &capVal, &armed, &coverageGap, &codeCandidate, &cit, &advisory, &basis, &citedEv); err != nil {
			return nil, err
		}
		t.Status = Status(status)
		t.Phase = Phase(phase.String)
		t.Surface = Surface(surface.String)
		t.Capability = Capability(capVal.String)
		t.Armed = armed.Int64 != 0
		t.CoverageGap = coverageGap.Int64 != 0
		t.CodeCandidate = codeCandidate.Int64 != 0
		t.Advisory = advisory.String
		t.CompletionBasis = basis.String
		if t.CompletionEvidenceIDs, err = unmarshalStrings(citedEv.String); err != nil {
			return nil, err
		}
		if t.DependsOn, err = unmarshalStrings(deps.String); err != nil {
			return nil, err
		}
		if t.BasisIDs, err = unmarshalStrings(bas.String); err != nil {
			return nil, err
		}
		if t.Citation, err = unmarshalCitation(cit.String); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) Snapshot(ctx context.Context) (Engagement, error) {
	e, _, err := s.snapshot(ctx, 0)
	return e, err
}

func (s *Store) ReportSnapshot(ctx context.Context, maxTasks int) (Engagement, bool, error) {
	return s.snapshot(ctx, maxTasks)
}

func (s *Store) snapshot(ctx context.Context, maxTasks int) (Engagement, bool, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return Engagement{}, false, err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN DEFERRED"); err != nil {
		return Engagement{}, false, err
	}
	committed := false
	defer func() {
		if !committed {
			conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	var e Engagement

	if e.Revision, err = readRevision(ctx, conn); err != nil {
		return Engagement{}, false, err
	}
	if e.Name, err = getMeta(ctx, conn, "name"); err != nil {
		return Engagement{}, false, err
	}
	if e.ActiveID, err = getMeta(ctx, conn, "active_id"); err != nil {
		return Engagement{}, false, err
	}
	stageJSON, err := getMeta(ctx, conn, "stage")
	if err != nil {
		return Engagement{}, false, err
	}
	if stageJSON != "" {
		if err := json.Unmarshal([]byte(stageJSON), &e.Stage); err != nil {
			return Engagement{}, false, err
		}
	}
	limit := 0
	if maxTasks > 0 {
		limit = maxTasks + 1
	}
	if e.Tasks, err = scanTasks(ctx, conn, limit); err != nil {
		return Engagement{}, false, err
	}
	truncated := maxTasks > 0 && len(e.Tasks) > maxTasks
	if truncated {
		e.Tasks = e.Tasks[:maxTasks]
	}
	vantageRaw, err := getMeta(ctx, conn, "vantage")
	if err != nil {
		return Engagement{}, false, err
	}
	e.Vantage = Vantage(vantageRaw)

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return Engagement{}, false, err
	}
	committed = true
	return e, truncated, nil
}

// Vantage returns the engagement's current access context, or "" when unset.
func (s *Store) Vantage(ctx context.Context) (Vantage, error) {
	v, err := getMeta(ctx, s.db, "vantage")
	return Vantage(v), err
}
