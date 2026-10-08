package histstore

import (
	"context"
	"database/sql"
	"errors"
)

// sessionmeta.go holds the per-session listing row the resume and history
// pickers read, and the transcript watermark that makes a turn's two writes
// converge across processes.
//
// The listing used to live in a sidecar index.json beside the transcripts. Every
// writer read the whole file, replaced its own entry and wrote the file back, so
// two blk processes that both read before either wrote lost one entry, and both
// wrote through one shared temp filename, which could publish a splice of two
// documents. Here the row is the unit of update: an upsert touches one session
// and SQLite serializes writers across processes, so neither can happen.
//
// Watermark is the transcript length, in bytes, that the committed memory rows
// account for. A turn appends to its transcript first and then commits the
// memory rows together with this watermark in one transaction, so that
// transaction is the turn's only commit point. Bytes past the watermark belong
// to a turn that never committed, and the reader reconciles them away. A NULL
// watermark means no length was ever recorded, which is what a transcript
// written before this column has: the whole file then counts as committed and
// is never truncated.

const sessionRowTable = "blk_session_meta"

// SessionRow is one session's listing row plus its transcript watermark.
type SessionRow struct {
	ID        string
	Title     string
	MsgCount  int
	UpdatedAt int64
	Model     string
	Mode      string
	// Watermark is the committed transcript length. Valid is false when none
	// has ever been recorded, which means the whole transcript is committed.
	Watermark sql.NullInt64
}

// initSessionRows creates the listing table. Open calls it, so every handle to
// the database finds the table present.
func (s *Store) initSessionRows() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS ` + sessionRowTable + ` (
		id         TEXT PRIMARY KEY,
		title      TEXT    NOT NULL DEFAULT '',
		msg_count  INTEGER NOT NULL DEFAULT 0,
		updated_at INTEGER NOT NULL DEFAULT 0,
		model      TEXT    NOT NULL DEFAULT '',
		mode       TEXT    NOT NULL DEFAULT '',
		watermark  INTEGER
	);`)
	return err
}

// upsertMetaSQL writes one listing row. The fields a concurrent writer could
// hold a stale copy of are merged rather than replaced: updated_at and the
// watermark only ever move forward, so a late commit from a process that read
// earlier cannot make a session look older or shrink the committed length,
// which would truncate another process's committed turns. msg_count is read
// back from the memory rows inside the same statement, so it is right whichever
// process commits. A NULL watermark stays NULL: the length is unknown, and
// adopting a known-shorter one could truncate committed turns.
const upsertMetaSQL = `INSERT INTO ` + sessionRowTable + `
	(id, title, msg_count, updated_at, model, mode, watermark)
	VALUES (?, ?, (SELECT COUNT(*) FROM ` + tableName + ` WHERE session = ?), ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		title      = excluded.title,
		msg_count  = excluded.msg_count,
		updated_at = MAX(` + sessionRowTable + `.updated_at, excluded.updated_at),
		model      = excluded.model,
		mode       = excluded.mode,
		watermark  = CASE
			WHEN ` + sessionRowTable + `.watermark IS NULL THEN NULL
			WHEN excluded.watermark IS NULL THEN ` + sessionRowTable + `.watermark
			ELSE MAX(` + sessionRowTable + `.watermark, excluded.watermark)
		END;`

// execUpsertMeta runs upsertMetaSQL on tx or on the shared handle.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func execUpsertMeta(ctx context.Context, e execer, m SessionRow) error {
	_, err := e.ExecContext(ctx, upsertMetaSQL,
		m.ID, m.Title, m.ID, m.UpdatedAt, m.Model, m.Mode, m.Watermark)
	return err
}

// UpsertSessionRow writes one listing row on its own, for a change that is not
// a turn: a rename, or a session whose transcript grew without committing.
func (s *Store) UpsertSessionRow(ctx context.Context, m SessionRow) error {
	if s == nil {
		return errors.New("history store unavailable")
	}
	return execUpsertMeta(ctx, s.db, m)
}

// GetSessionRow returns one session's row. ok is false for an unknown session.
func (s *Store) GetSessionRow(ctx context.Context, id string) (m SessionRow, ok bool, err error) {
	if s == nil {
		return SessionRow{}, false, errors.New("history store unavailable")
	}
	row := s.db.QueryRowContext(ctx,
		"SELECT id, title, msg_count, updated_at, model, mode, watermark FROM "+sessionRowTable+" WHERE id = ?;", id)
	err = row.Scan(&m.ID, &m.Title, &m.MsgCount, &m.UpdatedAt, &m.Model, &m.Mode, &m.Watermark)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionRow{}, false, nil
	}
	if err != nil {
		return SessionRow{}, false, err
	}
	return m, true, nil
}

// SessionRows returns every listing row, most recently updated first.
func (s *Store) SessionRows(ctx context.Context) ([]SessionRow, error) {
	if s == nil {
		return nil, errors.New("history store unavailable")
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, title, msg_count, updated_at, model, mode, watermark FROM "+sessionRowTable+
			" ORDER BY updated_at DESC, id DESC;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRow
	for rows.Next() {
		var m SessionRow
		if err := rows.Scan(&m.ID, &m.Title, &m.MsgCount, &m.UpdatedAt, &m.Model, &m.Mode, &m.Watermark); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteSessionRow removes one listing row. An unknown session is a no-op.
func (s *Store) DeleteSessionRow(ctx context.Context, id string) error {
	if s == nil {
		return errors.New("history store unavailable")
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM "+sessionRowTable+" WHERE id = ?;", id)
	return err
}

// DeleteAllSessionRows removes every listing row.
func (s *Store) DeleteAllSessionRows(ctx context.Context) error {
	if s == nil {
		return errors.New("history store unavailable")
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM "+sessionRowTable+";")
	return err
}

// ImportSessionRows adds listing rows that are not present yet, for a one-time
// migration from the sidecar index. An existing row always wins, so importing
// twice, or importing while another process is writing, cannot overwrite live
// state. Imported rows carry no watermark, so their transcripts count as
// committed in full.
func (s *Store) ImportSessionRows(ctx context.Context, metas []SessionRow) error {
	if s == nil {
		return errors.New("history store unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, m := range metas {
		if _, err := tx.ExecContext(ctx, "INSERT INTO "+sessionRowTable+
			" (id, title, msg_count, updated_at, model, mode, watermark) VALUES (?, ?, ?, ?, ?, ?, NULL)"+
			" ON CONFLICT(id) DO NOTHING;",
			m.ID, m.Title, m.MsgCount, m.UpdatedAt, m.Model, m.Mode); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CommitTurn is a turn's single commit point: the user and assistant memory
// rows and the session's listing row, including the transcript length they
// account for, in one transaction. Either the whole turn is committed or none
// of it is, for every process sharing the database.
//
// The caller appends both transcript lines first and passes the resulting file
// length as meta.Watermark, so a process interrupted between the append and
// this call leaves a transcript tail past the last committed watermark, which
// the reader reconciles away.
func (s *Store) CommitTurn(ctx context.Context, user, ai string, meta SessionRow) error {
	if s == nil {
		return errors.New("history store unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	insert := "INSERT INTO " + tableName + " (session, content, type) VALUES (?, ?, ?);"
	if _, err := tx.ExecContext(ctx, insert, meta.ID, user, RoleUser); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, insert, meta.ID, ai, RoleAI); err != nil {
		return err
	}
	if err := execUpsertMeta(ctx, tx, meta); err != nil {
		return err
	}
	return tx.Commit()
}
