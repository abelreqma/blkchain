package histstore

import (
	"context"
	"fmt"
)

// UndoLastExchange removes the last completed exchange and coordinates its transcript update.
func (s *Store) UndoLastExchange(ctx context.Context, session string, updateTranscript func() error) (bool, error) {
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
		if err = updateTranscript(); err != nil {
			return false, err
		}
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}
