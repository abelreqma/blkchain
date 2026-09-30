// Package engagement is the SQLite-backed store for a single engagement: its
// tasks, revision counter, transitions, evidence, receipts, and audit log.
package engagement

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

// Store is a handle on one engagement database.
type Store struct {
	db  *sql.DB
	wmu sync.Mutex // serializes every writer (Apply/RecordEvidence/RecordReceipt/Audit); reads stay lock-free under WAL
	// listeners are called after each Apply that commits, with the new revision
	// and a fresh snapshot. They are best-effort progress notification; a
	// snapshot read error skips the calls. They fire after the write lock is
	// released, so under concurrent writers they may be invoked from multiple
	// goroutines and revisions may arrive out of order. lmu guards the map.
	lmu       sync.Mutex
	listeners map[int]func(rev int64, e Engagement)
	nextID    int
}

// AddOnApply registers a listener invoked after each committed Apply with the
// new revision and a fresh snapshot. It returns a function that removes the
// listener. Safe to call concurrently. Listeners fire outside the write lock;
// keep them cheap and do not mutate the store from one.
func (s *Store) AddOnApply(fn func(rev int64, e Engagement)) (remove func()) {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	if s.listeners == nil {
		s.listeners = map[int]func(rev int64, e Engagement){}
	}
	id := s.nextID
	s.nextID++
	s.listeners[id] = fn
	return func() {
		s.lmu.Lock()
		delete(s.listeners, id)
		s.lmu.Unlock()
	}
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
