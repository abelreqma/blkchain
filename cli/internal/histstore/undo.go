package histstore

import (
	"context"
	"database/sql"
	"fmt"
)

// UndoLastExchange removes the last completed exchange and coordinates its
// transcript update. updateTranscript appends the tombstone and returns the
// transcript's new length, which is committed as the session's watermark in the
// same transaction as the row deletions, so the two stores stay in step: either
// the exchange is gone from both and the tombstone is accounted for, or neither
// happened. meta carries the session's listing fields; its Watermark is ignored
// in favour of the length updateTranscript reports.
func (s *Store) UndoLastExchange(ctx context.Context, session string, meta SessionRow, updateTranscript func() (int64, error)) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT id, type FROM "+tableName+" WHERE session = ? ORDER BY id DESC LIMIT 2;", session)
	if err != nil {
		return false, err
	}
	var ids []int64
	var roles []string
	for rows.Next() {
		var id int64
		var role string
		if err = rows.Scan(&id, &role); err != nil {
			rows.Close()
			return false, err
		}
		ids, roles = append(ids, id), append(roles, role)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, err
	}
	if len(ids) == 0 {
		return false, nil
	}
	if len(ids) != 2 || roles[0] != RoleAI || roles[1] != RoleUser {
		return false, fmt.Errorf("the last exchange is incomplete")
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM "+tableName+" WHERE session = ? AND id IN (?, ?);", session, ids[0], ids[1]); err != nil {
		return false, err
	}
	if updateTranscript != nil {
		size, err := updateTranscript()
		if err != nil {
			return false, err
		}
		// A reported length of 0 means the caller wrote no transcript, so the
		// session has none to account for and its watermark is left alone.
		meta.ID = session
		meta.Watermark = sql.NullInt64{Int64: size, Valid: size > 0}
		if err := execUpsertMeta(ctx, tx, meta); err != nil {
			return false, err
		}
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}
