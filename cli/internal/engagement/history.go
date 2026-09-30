package engagement

// Transition is one recorded change to the engagement, as stored in the
// transition table.
type Transition struct {
	Rev    int64
	At     string
	Kind   string
	Detail string
}

// Transitions returns every recorded transition, oldest first (by rev).
func (s *Store) Transitions() ([]Transition, error) {
	rows, err := s.db.Query(
		`SELECT rev, at, kind, detail FROM transition ORDER BY rev ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Transition{}
	for rows.Next() {
		var t Transition
		if err := rows.Scan(&t.Rev, &t.At, &t.Kind, &t.Detail); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AllEvidence returns the stored quotes for every task, keyed by task id, each
// list oldest first. Tasks with no evidence are absent from the map.
func (s *Store) AllEvidence() (map[string][]string, error) {
	rows, err := s.db.Query(
		`SELECT task_id, quote FROM evidence ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var id, q string
		if err := rows.Scan(&id, &q); err != nil {
			return nil, err
		}
		out[id] = append(out[id], q)
	}
	return out, rows.Err()
}
