package engagement

import "time"

// EvidenceCap is the maximum number of characters (runes) of a quote kept as
// evidence.
const EvidenceCap = 4000

const truncatedMarker = "...[truncated]"

// RecordEvidence stores an exact quote as evidence for a task and returns the
// new row id. It returns ErrNotFound when the task does not exist. A quote
// longer than EvidenceCap runes is cut to EvidenceCap runes and marked.
func (s *Store) RecordEvidence(taskID, quote string) (int64, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if _, err := s.GetTask(taskID); err != nil {
		return 0, err
	}
	if r := []rune(quote); len(r) > EvidenceCap {
		quote = string(r[:EvidenceCap]) + truncatedMarker
	}
	res, err := s.db.Exec(
		`INSERT INTO evidence (task_id, quote, at) VALUES (?, ?, ?)`,
		taskID, quote, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// EvidenceRow is one stored evidence quote with its row id. The id is the
// stable, verifiable provenance handle for a parsed finding (the "evidence-quote
// id"): a parser that attributes a record to this quote records (task_id, id) so
// no parsed field exists without a quote it can be traced to.
type EvidenceRow struct {
	ID    int64
	Quote string
}

// EvidenceRowsFor returns the stored evidence rows for a task, oldest first,
// each with its row id for provenance. It mirrors EvidenceFor's ordering.
func (s *Store) EvidenceRowsFor(taskID string) ([]EvidenceRow, error) {
	rows, err := s.db.Query(
		`SELECT id, quote FROM evidence WHERE task_id = ? ORDER BY id ASC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EvidenceRow{}
	for rows.Next() {
		var r EvidenceRow
		if err := rows.Scan(&r.ID, &r.Quote); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// EvidenceFor returns the stored quotes for a task, oldest first.
func (s *Store) EvidenceFor(taskID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT quote FROM evidence WHERE task_id = ? ORDER BY id ASC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var q string
		if err := rows.Scan(&q); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}
