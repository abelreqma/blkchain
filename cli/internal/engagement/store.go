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
	path string
	db   *sql.DB
	bmu  sync.Mutex
	wmu  sync.Mutex // serializes every writer (Apply/RecordEvidence/RecordReceipt/Audit); reads stay lock-free under WAL
	// listeners are called after each Apply that commits, with the new revision
	// and a fresh snapshot. They are best-effort progress notification; a
	// snapshot read error skips the calls. They fire after the write lock is
	// released, so under concurrent writers they may be invoked from multiple
	// goroutines and revisions may arrive out of order. lmu guards the map.
	lmu                 sync.Mutex
	listeners           map[int]func(rev int64, e Engagement)
	webFindingListeners map[int]func([]byte) error
	evidenceListeners   map[int]func()
	nextID              int
}

func (s *Store) AddOnEvidence(fn func()) (remove func()) {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	if s.evidenceListeners == nil {
		s.evidenceListeners = map[int]func(){}
	}
	id := s.nextID
	s.nextID++
	s.evidenceListeners[id] = fn
	return func() {
		s.lmu.Lock()
		delete(s.evidenceListeners, id)
		s.lmu.Unlock()
	}
}

func (s *Store) notifyEvidence() {
	s.lmu.Lock()
	fns := make([]func(), 0, len(s.evidenceListeners))
	for _, fn := range s.evidenceListeners {
		fns = append(fns, fn)
	}
	s.lmu.Unlock()
	for _, fn := range fns {
		fn()
	}
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
	updated_rev INTEGER,
	phase TEXT,
	surface TEXT,
	capability TEXT,
	armed INTEGER,
	coverage_gap INTEGER,
	code_candidate INTEGER,
	citation TEXT,
	advisory TEXT,
	completion_basis TEXT,
	completion_evidence TEXT
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
CREATE TABLE IF NOT EXISTS recon_coverage (
	surface TEXT NOT NULL,
	asset TEXT NOT NULL,
	dimensions TEXT,
	iteration_count INTEGER,
	last_novelty_rev INTEGER,
	created_rev INTEGER,
	updated_rev INTEGER,
	PRIMARY KEY (surface, asset)
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
	if err := os.Chmod(abs, 0o600); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, path: abs}, nil
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
	if err := addMissingTaskColumns(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(webSchema); err != nil {
		return err
	}
	if _, err := tx.Exec(graphSchema); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO meta (k, v) VALUES ('revision', '0')`); err != nil {
		return err
	}
	return tx.Commit()
}

// addMissingTaskColumns adds the phase, surface, capability, and armed
// columns to a task table created before they existed. SQLite errors on a
// duplicate ADD COLUMN, so each column is added only when PRAGMA table_info
// does not already report it; a fresh database gets them from the CREATE
// TABLE above and this is a no-op.
func addMissingTaskColumns(tx *sql.Tx) error {
	rows, err := tx.Query(`PRAGMA table_info(task)`)
	if err != nil {
		return err
	}
	existing := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	cols := []struct {
		name string
		typ  string
	}{
		{"phase", "TEXT"},
		{"surface", "TEXT"},
		{"capability", "TEXT"},
		{"armed", "INTEGER"},
		{"coverage_gap", "INTEGER"},
		{"code_candidate", "INTEGER"},
		{"citation", "TEXT"},
		{"advisory", "TEXT"}, // D' follow-up: display-only prior-episode recall hint, additive.
		// The completer's stated basis for a done task and the evidence row ids it
		// cited. Written only by the completion path; empty on tasks completed
		// before the columns existed.
		{"completion_basis", "TEXT"},
		{"completion_evidence", "TEXT"},
	}
	for _, col := range cols {
		if existing[col.name] {
			continue
		}
		if _, err := tx.Exec(`ALTER TABLE task ADD COLUMN ` + col.name + ` ` + col.typ); err != nil {
			return err
		}
	}
	return nil
}
