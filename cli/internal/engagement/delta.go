package engagement

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// Delta is one atomic change to an engagement: tasks to add or replace, tasks
// to mark done, and the transition record that describes the change.
type Delta struct {
	Upserts     []Task
	Completes   []string
	Kind        string
	Detail      string
	SetName     *string
	SetActiveID *string
	SetStage    *Stage
}

func (s *Store) Apply(d Delta) (newRev int64, err error) {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	for _, t := range d.Upserts {
		if t.ID == "" {
			return 0, fmt.Errorf("engagement: upsert has empty task id")
		}
		if !t.Status.valid() {
			return 0, fmt.Errorf("engagement: task %q has invalid status %q", t.ID, t.Status)
		}
		for _, dep := range t.DependsOn {
			if dep == t.ID {
				return 0, fmt.Errorf("engagement: task %q depends on itself", t.ID)
			}
		}
	}

	// Ids that exist after this delta: every id already stored plus the upserts.
	known := map[string]bool{}
	rows, err := conn.QueryContext(ctx, `SELECT id FROM task`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		known[id] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	for _, t := range d.Upserts {
		known[t.ID] = true
	}
	for _, t := range d.Upserts {
		for _, dep := range t.DependsOn {
			if !known[dep] {
				return 0, fmt.Errorf("engagement: task %q depends on unknown task %q", t.ID, dep)
			}
		}
	}
	for _, id := range d.Completes {
		if !known[id] {
			return 0, fmt.Errorf("engagement: cannot complete unknown task %q", id)
		}
	}

	// Current status and dependencies of every stored task, for downgrade and
	// cycle checks. Upserts override a stored task's dependencies.
	curStatus := map[string]Status{}
	deps := map[string][]string{}
	drows, err := conn.QueryContext(ctx, `SELECT id, status, depends_on FROM task`)
	if err != nil {
		return 0, err
	}
	for drows.Next() {
		var id, st, dj string
		if err := drows.Scan(&id, &st, &dj); err != nil {
			drows.Close()
			return 0, err
		}
		curStatus[id] = Status(st)
		dd, err := unmarshalStrings(dj)
		if err != nil {
			drows.Close()
			return 0, err
		}
		deps[id] = dd
	}
	if err := drows.Err(); err != nil {
		drows.Close()
		return 0, err
	}
	drows.Close()
	for _, t := range d.Upserts {
		if curStatus[t.ID] == StatusDone && t.Status == StatusTodo {
			return 0, fmt.Errorf("engagement: task %q cannot move from done to todo", t.ID)
		}
		deps[t.ID] = t.DependsOn
	}
	if cyc := findCycle(deps); cyc != "" {
		return 0, fmt.Errorf("engagement: dependency cycle through task %q", cyc)
	}

	var v string
	if err := conn.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'revision'`).Scan(&v); err != nil {
		return 0, err
	}
	rev, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, err
	}
	newRev = rev + 1
	if _, err := conn.ExecContext(ctx, `UPDATE meta SET v = ? WHERE k = 'revision'`, strconv.FormatInt(newRev, 10)); err != nil {
		return 0, err
	}

	for _, t := range d.Upserts {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO task (id, kind, target, objective, done_when, status, depends_on, basis_ids, created_rev, updated_rev)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(id) DO UPDATE SET
			   kind = excluded.kind,
			   target = excluded.target,
			   objective = excluded.objective,
			   done_when = excluded.done_when,
			   status = excluded.status,
			   depends_on = excluded.depends_on,
			   basis_ids = excluded.basis_ids,
			   updated_rev = excluded.updated_rev`,
			t.ID, t.Kind, t.Target, t.Objective, t.DoneWhen, string(t.Status),
			marshalStrings(t.DependsOn), marshalStrings(t.BasisIDs), newRev, newRev); err != nil {
			return 0, err
		}
	}
	for _, id := range d.Completes {
		if _, err := conn.ExecContext(ctx,
			`UPDATE task SET status = 'done', updated_rev = ? WHERE id = ?`, newRev, id); err != nil {
			return 0, err
		}
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO transition (rev, at, kind, detail) VALUES (?, ?, ?, ?)`,
		newRev, time.Now().UTC().Format(time.RFC3339), d.Kind, d.Detail); err != nil {
		return 0, err
	}

	if d.SetName != nil {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO meta (k, v) VALUES ('name', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, *d.SetName); err != nil {
			return 0, err
		}
	}
	if d.SetActiveID != nil {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO meta (k, v) VALUES ('active_id', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, *d.SetActiveID); err != nil {
			return 0, err
		}
	}
	if d.SetStage != nil {
		b, err := json.Marshal(*d.SetStage)
		if err != nil {
			return 0, err
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO meta (k, v) VALUES ('stage', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, string(b)); err != nil {
			return 0, err
		}
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return 0, err
	}
	committed = true
	return newRev, nil
}

// findCycle returns a task id on a depends-on cycle, or "" when the graph is
// acyclic. Edges point from a task to each id it depends on. Missing ids are
// treated as leaves (unknown-dependency is checked separately).
func findCycle(deps map[string][]string) string {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var visit func(id string) string
	visit = func(id string) string {
		color[id] = gray
		for _, dep := range deps[id] {
			switch color[dep] {
			case gray:
				return dep
			case white:
				if c := visit(dep); c != "" {
					return c
				}
			}
		}
		color[id] = black
		return ""
	}
	for id := range deps {
		if color[id] == white {
			if c := visit(id); c != "" {
				return c
			}
		}
	}
	return ""
}
