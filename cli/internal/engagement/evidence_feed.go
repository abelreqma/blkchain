package engagement

import (
	"context"
	"errors"
	"strconv"
)

type EvidenceEntry struct {
	ID      int64
	TaskID  string
	Surface Surface
	Quote   string
}

func (s *Store) EvidenceAfter(ctx context.Context, id int64, limit int) ([]EvidenceEntry, error) {
	if id < 0 || limit < 1 || limit > 500 {
		return nil, errors.New("invalid evidence cursor or limit")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT e.id,e.task_id,coalesce(nullif(t.surface,''),'unclassified'),e.quote
		FROM evidence e JOIN task t ON t.id=e.task_id WHERE e.id>? ORDER BY e.id LIMIT ?`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EvidenceEntry{}
	for rows.Next() {
		var entry EvidenceEntry
		if err := rows.Scan(&entry.ID, &entry.TaskID, &entry.Surface, &entry.Quote); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

func (s *Store) FindingParseCursor(ctx context.Context) (int64, error) {
	raw, err := getMeta(ctx, s.db, "finding_parse_cursor")
	if err != nil || raw == "" {
		return 0, err
	}
	return strconv.ParseInt(raw, 10, 64)
}

func (s *Store) AdvanceFindingParseCursor(ctx context.Context, id int64) error {
	if id <= 0 {
		return errors.New("invalid finding parse cursor")
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.db.ExecContext(ctx, `INSERT INTO meta(k,v) VALUES('finding_parse_cursor',?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v WHERE CAST(meta.v AS INTEGER)<CAST(excluded.v AS INTEGER)`, strconv.FormatInt(id, 10))
	return err
}

func (s *Store) HasFinding(ctx context.Context, id string) (bool, error) {
	var found int
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM finding_record WHERE id=?)`, id).Scan(&found)
	return found != 0, err
}
