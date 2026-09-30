// Package engagement is the SQLite-backed store for a single engagement: its
// tasks, revision counter, transitions, evidence, receipts, and audit log.
package engagement

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Store is a handle on one engagement database.
type Store struct {
	db *sql.DB
	// onApply, when set, is called after each Apply that commits, with the new
	// revision and a fresh snapshot. It is best-effort progress notification for
	// a live view; a snapshot read error skips the call. Access is not
	// synchronized: the engagement run drives the store sequentially.
	onApply func(rev int64, e Engagement)
}

// SetOnApply registers a callback invoked after each committed Apply, with the
// new revision and a fresh snapshot. Passing nil clears it. It is intended for a
// live progress view and must not mutate the store.
func (s *Store) SetOnApply(fn func(rev int64, e Engagement)) {
	s.onApply = fn
}

const schema = `
CREATE TABLE IF NOT EXISTS task (
	id TEXT PRIMARY KEY,
	kind TEXT,
	target TEXT,
	objective TEXT,
	done_when TEXT,
	status TEXT,
	depends_on TEXT,
	basis_ids TEXT,
	created_rev INTEGER,
	updated_rev INTEGER
);
CREATE TABLE IF NOT EXISTS meta (
	k TEXT PRIMARY KEY,
	v TEXT
);
CREATE TABLE IF NOT EXISTS transition (
	rev INTEGER PRIMARY KEY,
	at TEXT,
	kind TEXT,
	detail TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	task_id TEXT,
	quote TEXT,
	at TEXT
);
CREATE TABLE IF NOT EXISTS receipt (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	task_id TEXT,
	skill TEXT,
	bundle_digest TEXT,
	context_gen INTEGER,
	at TEXT
);
CREATE TABLE IF NOT EXISTS audit (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	at TEXT,
	actor TEXT,
	action TEXT,
	detail TEXT
);
`

// Open opens (creating if needed) the engagement database at path and brings
// its schema up to date. The parent directory is created with mode 0700.
func Open(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, err
	}
	dsn := (&url.URL{
		Scheme:   "file",
		Path:     abs,
		RawQuery: "_busy_timeout=5000&_journal_mode=WAL",
	}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate %s: %w", abs, err)
	}
	return &Store{db: db}, nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// migrate creates every table if absent and seeds the revision counter. It is
// idempotent.
func migrate(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(schema); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO meta (k, v) VALUES ('revision', '0')`); err != nil {
		return err
	}
	return tx.Commit()
}
