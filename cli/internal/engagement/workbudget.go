package engagement

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"
)

func (s *Store) EnsureEngagementStart(now time.Time) (time.Time, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if _, err := s.db.Exec(`INSERT INTO meta (k, v) VALUES ('engage_started_at', ?) ON CONFLICT(k) DO NOTHING`, now.UTC().Format(time.RFC3339Nano)); err != nil {
		return time.Time{}, err
	}
	var raw string
	if err := s.db.QueryRow(`SELECT v FROM meta WHERE k = 'engage_started_at'`).Scan(&raw); err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339Nano, raw)
}

func (s *Store) ReserveEngagementAction(limit int64) (bool, error) {
	if limit <= 0 {
		return false, errors.New("engagement action limit must be positive")
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return false, err
	}
	committed := false
	defer func() {
		if !committed {
			conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	var raw string
	err = conn.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'engage_actions'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		raw = "0"
	} else if err != nil {
		return false, err
	}
	used, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || used < 0 {
		return false, fmt.Errorf("engagement action counter is invalid: %q", raw)
	}
	if used >= limit {
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return false, err
		}
		committed = true
		return false, nil
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO meta (k, v) VALUES ('engage_actions', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, strconv.FormatInt(used+1, 10)); err != nil {
		return false, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return false, err
	}
	committed = true
	return true, nil
}
