package engagement

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const surfaceSchema = `
CREATE TABLE IF NOT EXISTS surface_record (
	id TEXT PRIMARY KEY,
	task_id TEXT NOT NULL,
	surface TEXT NOT NULL,
	asset TEXT NOT NULL,
	kind TEXT NOT NULL,
	name TEXT NOT NULL,
	value TEXT NOT NULL,
	detail TEXT NOT NULL,
	source TEXT NOT NULL,
	gap TEXT NOT NULL,
	evidence_id INTEGER NOT NULL,
	observed_at TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS surface_asset ON surface_record(asset, kind);
CREATE INDEX IF NOT EXISTS surface_kind ON surface_record(kind, name);
CREATE INDEX IF NOT EXISTS surface_task ON surface_record(task_id);
`

// SurfaceKinds are the classes of external-surface observation a record may carry.
func SurfaceKinds() []string {
	return []string{
		"tls-protocol", "tls-certificate", "http-header", "http-cookie",
		"http-cors", "http-method", "http-path", "dns-name",
	}
}

func validSurfaceKind(k string) bool {
	for _, v := range SurfaceKinds() {
		if v == k {
			return true
		}
	}
	return false
}

// SurfaceRecord is one external-surface observation: what was probed, what it reported, the probe's own result, what stayed unknown, and the output it came from.
type SurfaceRecord struct {
	ID         string          `json:"id"`
	TaskID     string          `json:"task_id"`
	Surface    Surface         `json:"surface"`
	Asset      string          `json:"asset"`
	Kind       string          `json:"kind"`
	Name       string          `json:"name"`
	Value      string          `json:"value,omitempty"`
	Detail     json.RawMessage `json:"detail,omitempty"`
	Source     string          `json:"source,omitempty"`
	Gap        string          `json:"gap,omitempty"`
	EvidenceID int64           `json:"evidence_id"`
	ObservedAt string          `json:"observed_at,omitempty"`
	CreatedAt  string          `json:"created_at,omitempty"`
	UpdatedAt  string          `json:"updated_at,omitempty"`
}

const maxSurfaceField = 1024
const maxSurfaceDetail = 64 << 10

// SurfaceFilter narrows a query. An empty field does not constrain.
type SurfaceFilter struct {
	Asset  string
	Kind   string
	Name   string
	Limit  int
	Offset int
}

func (s *Store) validateSurface(ctx context.Context, r SurfaceRecord) error {
	if !r.Surface.valid() {
		return errors.New("invalid surface")
	}
	if !validSurfaceKind(r.Kind) {
		return errors.New("unknown surface record kind")
	}
	if r.Asset == "" || !boundedVulnText(r.Asset, maxSurfaceField) {
		return errors.New("invalid asset")
	}
	if r.Name == "" || !boundedVulnText(r.Name, maxSurfaceField) {
		return errors.New("invalid name")
	}
	for _, f := range []string{r.Value, r.Source, r.Gap} {
		if !boundedVulnText(f, maxSurfaceField) {
			return errors.New("surface field exceeds bounds")
		}
	}
	if len(r.Detail) > maxSurfaceDetail {
		return errors.New("surface detail exceeds bounds")
	}
	if len(r.Detail) > 0 && !json.Valid(r.Detail) {
		return errors.New("surface detail is not JSON")
	}
	if r.EvidenceID <= 0 {
		return errors.New("surface record requires an evidence row")
	}
	var found int
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM evidence WHERE id=? AND task_id=?)`, r.EvidenceID, r.TaskID).Scan(&found); err != nil {
		return err
	}
	if found == 0 {
		return errors.New("surface evidence does not belong to the task")
	}
	return nil
}

// SaveSurface upserts one observation, so re-probing the same asset updates in place and created_at survives.
func (s *Store) SaveSurface(ctx context.Context, r SurfaceRecord) (SurfaceRecord, error) {
	if s == nil || s.db == nil {
		return SurfaceRecord{}, errors.New("engagement store unavailable")
	}
	if r.ID == "" || !boundedVulnText(r.ID, 128) {
		return SurfaceRecord{}, errors.New("invalid surface record id")
	}
	if err := s.validateSurface(ctx, r); err != nil {
		return SurfaceRecord{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if r.ObservedAt == "" {
		r.ObservedAt = now
	}
	detail := string(r.Detail)
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO surface_record (id, task_id, surface, asset, kind, name, value, detail, source, gap,
	evidence_id, observed_at, created_at, updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
	task_id=excluded.task_id, surface=excluded.surface, asset=excluded.asset,
	kind=excluded.kind, name=excluded.name, value=excluded.value,
	detail=excluded.detail, source=excluded.source, gap=excluded.gap,
	evidence_id=excluded.evidence_id,
	observed_at=MAX(surface_record.observed_at, excluded.observed_at),
	updated_at=excluded.updated_at`,
		r.ID, r.TaskID, string(r.Surface), r.Asset, r.Kind, r.Name, r.Value, detail,
		r.Source, r.Gap, r.EvidenceID, r.ObservedAt, now, now); err != nil {
		return SurfaceRecord{}, err
	}
	return s.Surface(ctx, r.ID)
}

func scanSurface(row interface{ Scan(...any) error }) (SurfaceRecord, error) {
	var r SurfaceRecord
	var surface, detail string
	if err := row.Scan(&r.ID, &r.TaskID, &surface, &r.Asset, &r.Kind, &r.Name, &r.Value,
		&detail, &r.Source, &r.Gap, &r.EvidenceID, &r.ObservedAt, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return SurfaceRecord{}, err
	}
	r.Surface = Surface(surface)
	if detail != "" {
		r.Detail = json.RawMessage(detail)
	}
	return r, nil
}

const surfaceColumns = `id, task_id, surface, asset, kind, name, value, detail, source, gap,
	evidence_id, observed_at, created_at, updated_at`

// Surface returns one observation by id.
func (s *Store) Surface(ctx context.Context, id string) (SurfaceRecord, error) {
	if s == nil || s.db == nil {
		return SurfaceRecord{}, errors.New("engagement store unavailable")
	}
	r, err := scanSurface(s.db.QueryRowContext(ctx,
		`SELECT `+surfaceColumns+` FROM surface_record WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return SurfaceRecord{}, errors.New("surface record not found")
	}
	return r, err
}

// Surfaces returns the observations matching f, ordered by asset, then kind, then name.
func (s *Store) Surfaces(ctx context.Context, f SurfaceFilter) ([]SurfaceRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("engagement store unavailable")
	}
	query := `SELECT ` + surfaceColumns + ` FROM surface_record`
	var where []string
	var args []any
	for _, c := range []struct {
		column, value string
	}{
		{"asset", f.Asset}, {"kind", f.Kind}, {"name", f.Name},
	} {
		if c.value != "" {
			where = append(where, c.column+"=?")
			args = append(args, c.value)
		}
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY asset, kind, name, id"
	if f.Limit == 0 {
		f.Limit = 100
	}
	if f.Limit < 1 || f.Limit > 100 || f.Offset < 0 || f.Offset > 1000000 {
		return nil, errors.New("surface page limit or offset is out of range")
	}
	query += " LIMIT ? OFFSET ?"
	args = append(args, f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SurfaceRecord
	for rows.Next() {
		r, err := scanSurface(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// SurfaceStats counts the observations per kind, for a report header.
func (s *Store) SurfaceStats(ctx context.Context) (map[string]int, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("engagement store unavailable")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT kind, COUNT(*) FROM surface_record GROUP BY kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			return nil, err
		}
		out[kind] = n
	}
	return out, rows.Err()
}
