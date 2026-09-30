package engagement

import (
	"context"
	"time"
)

// Receipt is a recorded skill delivery for a task.
type Receipt struct {
	Skill        string
	BundleDigest string
	ContextGen   int64
	At           string
}

// RecordReceipt records a skill delivery bound to a task: the skill name, its
// content digest, and the store revision at delivery (context_gen). It returns
// the new row id, or ErrNotFound when the task does not exist.
func (s *Store) RecordReceipt(taskID, skill, bundleDigest string) (int64, error) {
	if _, err := s.GetTask(taskID); err != nil {
		return 0, err
	}
	rev, err := s.Revision(context.Background())
	if err != nil {
		return 0, err
	}
	res, err := s.db.Exec(
		`INSERT INTO receipt (task_id, skill, bundle_digest, context_gen, at) VALUES (?, ?, ?, ?, ?)`,
		taskID, skill, bundleDigest, rev, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ReceiptsFor returns the receipts for a task, oldest first.
func (s *Store) ReceiptsFor(taskID string) ([]Receipt, error) {
	rows, err := s.db.Query(
		`SELECT skill, bundle_digest, context_gen, at FROM receipt WHERE task_id = ? ORDER BY id ASC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Receipt{}
	for rows.Next() {
		var r Receipt
		if err := rows.Scan(&r.Skill, &r.BundleDigest, &r.ContextGen, &r.At); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
