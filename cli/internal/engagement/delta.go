package engagement

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	// SetVantage advances the engagement's access context. It is validated as a
	// known vantage and must not move backward (a lower rank than the current
	// vantage is rejected), so advancement is monotonic.
	SetVantage *Vantage
	// ReconUpserts are recon-coverage rows to insert or update, keyed by
	// (surface, asset). created_rev is preserved across an update; only
	// updated_rev advances.
	ReconUpserts []ReconCoverage
}

func (s *Store) Apply(d Delta) (newRev int64, err error) {
	s.wmu.Lock()
	newRev, err = s.applyLocked(d)
	s.wmu.Unlock()
	if err != nil {
		return 0, err
	}
	s.lmu.Lock()
	fns := make([]func(rev int64, e Engagement), 0, len(s.listeners))
	for _, fn := range s.listeners {
		fns = append(fns, fn)
	}
	s.lmu.Unlock()
	if len(fns) > 0 {
		if e, snapErr := s.Snapshot(context.Background()); snapErr == nil {
			for _, fn := range fns {
				fn(e.Revision, e)
			}
		}
	}
	return newRev, nil
}

// applyLocked runs the Apply transaction. The caller must hold wmu.
func (s *Store) applyLocked(d Delta) (newRev int64, err error) {
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

	// Validate and default each upsert into a local copy; the defaulted values
	// (not d.Upserts) are what gets written below.
	upserts := make([]Task, len(d.Upserts))
	for i, t := range d.Upserts {
		if t.ID == "" {
			return 0, fmt.Errorf("engagement: upsert has empty task id")
		}
		if !t.Status.valid() {
			return 0, fmt.Errorf("engagement: task %q has invalid status %q", t.ID, t.Status)
		}
		if t.Phase == "" {
			// Derive the default Phase from the Kind (fail-safe): a non-recon-nature
			// Kind such as exploit-dev gets its stricter phase instead of silently
			// defaulting to recon, so it does not route to the recon tier or escape the
			// arm requirement. surfaceForKind does the same for Surface just below.
			t.Phase = phaseForKind(t.Kind)
		}
		if !t.Phase.valid() {
			return 0, fmt.Errorf("engagement: task %q has invalid phase %q", t.ID, t.Phase)
		}
		if t.Surface == "" {
			t.Surface = surfaceForKind(t.Kind)
		}
		if !t.Surface.valid() {
			return 0, fmt.Errorf("engagement: task %q has invalid surface %q", t.ID, t.Surface)
		}
		if t.Capability != "" && !t.Capability.valid() {
			return 0, fmt.Errorf("engagement: task %q has invalid capability %q", t.ID, t.Capability)
		}
		for _, dep := range t.DependsOn {
			if dep == t.ID {
				return 0, fmt.Errorf("engagement: task %q depends on itself", t.ID)
			}
		}
		for _, b := range t.BasisIDs {
			if b == t.ID {
				return 0, fmt.Errorf("engagement: task %q lists itself as a basis", t.ID)
			}
		}
		upserts[i] = t
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
	for _, t := range upserts {
		known[t.ID] = true
	}
	for _, t := range upserts {
		for _, dep := range t.DependsOn {
			if !known[dep] {
				return 0, fmt.Errorf("engagement: task %q depends on unknown task %q", t.ID, dep)
			}
		}
		// basis_ids is provenance only: validated as known ids, never a
		// scheduling gate and never part of the cycle check.
		for _, b := range t.BasisIDs {
			if !known[b] {
				return 0, fmt.Errorf("engagement: task %q has unknown basis task %q", t.ID, b)
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
	for _, t := range upserts {
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

	for _, t := range upserts {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO task (id, kind, target, objective, done_when, status, depends_on, basis_ids, created_rev, updated_rev, phase, surface, capability, armed)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(id) DO UPDATE SET
			   kind = excluded.kind,
			   target = excluded.target,
			   objective = excluded.objective,
			   done_when = excluded.done_when,
			   status = excluded.status,
			   depends_on = excluded.depends_on,
			   basis_ids = excluded.basis_ids,
			   updated_rev = excluded.updated_rev,
			   phase = excluded.phase,
			   surface = excluded.surface,
			   capability = excluded.capability,
			   armed = excluded.armed`,
			t.ID, t.Kind, t.Target, t.Objective, t.DoneWhen, string(t.Status),
			marshalStrings(t.DependsOn), marshalStrings(t.BasisIDs), newRev, newRev,
			string(t.Phase), string(t.Surface), string(t.Capability), boolToInt(t.Armed)); err != nil {
			return 0, err
		}
	}
	for _, id := range d.Completes {
		if _, err := conn.ExecContext(ctx,
			`UPDATE task SET status = 'done', updated_rev = ? WHERE id = ?`, newRev, id); err != nil {
			return 0, err
		}
	}

	for _, rc := range d.ReconUpserts {
		if rc.Asset == "" {
			return 0, fmt.Errorf("engagement: recon coverage has empty asset")
		}
		if !rc.Surface.valid() {
			return 0, fmt.Errorf("engagement: recon coverage has invalid surface %q", rc.Surface)
		}
		for dim, st := range rc.Dimensions {
			if !st.valid() {
				return 0, fmt.Errorf("engagement: recon coverage dimension %q has invalid status %q", dim, st)
			}
		}
		// Resolve the "stamp this revision" novelty sentinel.
		noveltyRev := rc.LastNoveltyRev
		if noveltyRev == ReconNoveltyThisRev {
			noveltyRev = newRev
		}
		// Read-merge-write inside this transaction (which holds the write lock via
		// BEGIN IMMEDIATE), so two concurrent writers on the same (surface, asset)
		// row never clobber a covered dimension or regress a counter: coverage is
		// merged ReconCovered-wins and the counters stay monotonic.
		dims := rc.Dimensions
		iter := rc.IterationCount
		nov := noveltyRev
		var (
			prevDims string
			prevIter int
			prevNov  int64
		)
		switch err := conn.QueryRowContext(ctx,
			`SELECT dimensions, iteration_count, last_novelty_rev FROM recon_coverage WHERE surface = ? AND asset = ?`,
			string(rc.Surface), rc.Asset).Scan(&prevDims, &prevIter, &prevNov); {
		case err == nil:
			prev, perr := unmarshalReconDims(prevDims)
			if perr != nil {
				return 0, perr
			}
			dims = mergeReconDims(prev, rc.Dimensions)
			if prevIter > iter {
				iter = prevIter
			}
			if prevNov > nov {
				nov = prevNov
			}
		case errors.Is(err, sql.ErrNoRows):
			// first write for this row; use the incoming values as-is
		default:
			return 0, err
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO recon_coverage (surface, asset, dimensions, iteration_count, last_novelty_rev, created_rev, updated_rev)
			 VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(surface, asset) DO UPDATE SET
			   dimensions = excluded.dimensions,
			   iteration_count = excluded.iteration_count,
			   last_novelty_rev = excluded.last_novelty_rev,
			   updated_rev = excluded.updated_rev`,
			string(rc.Surface), rc.Asset, marshalReconDims(dims), iter, nov, newRev, newRev); err != nil {
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
	if d.SetVantage != nil {
		nv := *d.SetVantage
		if !nv.valid() {
			return 0, fmt.Errorf("engagement: invalid vantage %q", nv)
		}
		cur, err := getMeta(ctx, conn, "vantage")
		if err != nil {
			return 0, err
		}
		// Monotonic: a vantage never moves backward (that would re-lock surfaces).
		if cur != "" && Vantage(cur).rank() > nv.rank() {
			return 0, fmt.Errorf("engagement: vantage cannot move backward from %q to %q", cur, nv)
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO meta (k, v) VALUES ('vantage', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, string(nv)); err != nil {
			return 0, err
		}
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return 0, err
	}
	committed = true
	return newRev, nil
}

// boolToInt converts a bool to the 0/1 SQLite stores for an INTEGER column.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
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
