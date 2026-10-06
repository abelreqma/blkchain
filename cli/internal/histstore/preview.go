package histstore

import (
	"context"
	"database/sql"
	"errors"
)

func (s *Store) LastQuestion(ctx context.Context, session string) (string, error) {
	var text string
	err := s.db.QueryRowContext(ctx, "SELECT substr(content, 1, 1024) FROM "+tableName+" WHERE session = ? AND type = ? ORDER BY id DESC LIMIT 1;", session, RoleUser).Scan(&text)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return text, err
}
