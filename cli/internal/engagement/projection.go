package engagement

import (
	"database/sql"
	"time"
)

// Coverage is the always-present summary of engagement progress. It is small
// and fixed-size so the orchestrator can see what already exists and avoid
// repeating discovery.
type Coverage struct {
	Total int
	Done  int
	Open  int
	Kinds map[string]int
}

func (s *Store) OpenTasks() ([]Task, error) {
	rows, err := s.db.Query(
		`SELECT id, kind, target, objective, done_when, status, depends_on, basis_ids, created_rev, updated_rev
		 FROM task WHERE status IN ('todo', 'active')
		 ORDER BY created_rev ASC, id ASC`)
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

func (s *Store) CoverageIndex() (Coverage, error) {
	c := Coverage{Kinds: map[string]int{}}
	rows, err := s.db.Query(
		`SELECT kind,
		        COUNT(*),
		        COALESCE(SUM(status = 'done'), 0),
		        COALESCE(SUM(status IN ('todo', 'active')), 0)
		 FROM task GROUP BY kind`)
	if err != nil {
		return Coverage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var n, done, open int
		if err := rows.Scan(&kind, &n, &done, &open); err != nil {
			return Coverage{}, err
		}
		c.Kinds[kind] = n
		c.Total += n
		c.Done += done
		c.Open += open
	}
	return c, rows.Err()
}

// Audit appends one row to the append-only audit log.
func (s *Store) Audit(actor, action, detail string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO audit (at, actor, action, detail) VALUES (?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339), actor, action, detail)
	return err
}
