// Package histstore is the persistent conversation memory for the REPL, backed
// by langchaingo's memory/sqlite3 chat message history at
// $XDG_DATA_HOME/blk/history.db. Every REPL turn is written here keyed by the
// session id, so /history can list past sessions and replay one. langchaingo
// owns the schema, the append path (AddUserMessage / AddAIMessage) and the
// per-session read; the session list is a small raw query on the shared
// *sql.DB, which langchaingo does not expose an API for.
//
// It lives in an importable internal package (not package main) so other parts
// of the binary under cli/internal/... can share the same database file and
// handle for their own namespaced tables. Open enables WAL and a busy timeout
// so those extra writers do not deadlock; DB() and DBPath() expose the shared
// handle and path.
package histstore

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tmc/langchaingo/memory/sqlite3"
)

// Role* are the message roles as langchaingo stores them (llms.ChatMessageType).
const (
	RoleUser = "human"
	RoleAI   = "ai"
)

// tableName is the messages table langchaingo creates and we query. It was
// renamed from blk_history; Open migrates an old table on first open.
const tableName = "blk_sessions"

// legacyTableName is the pre-rename table name, migrated to tableName.
const legacyTableName = "blk_history"

// Turn is one stored message, ordered by insert order (the table's id).
type Turn struct {
	Role    string
	Content string
}

// SessionMeta is one distinct session with its message count. Sessions are
// returned newest-touched first.
type SessionMeta struct {
	ID    string
	Count int
}

// Store wraps a single sqlite database shared across every session's langchaingo
// history handle.
type Store struct {
	db *sql.DB
}

// DBPath resolves $XDG_DATA_HOME/blk/history.db (falling back to
// ~/.local/share/blk/history.db). It is exported so other code in this binary
// that shares the history database (for example the engage harness's own
// namespaced tables) resolves the same path.
func DBPath() (string, error) {
	base := strings.TrimSpace(os.Getenv("XDG_DATA_HOME"))
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	dir := filepath.Join(base, "blk")
	if err := privateDir(dir); err != nil {
		return "", err
	}
	return filepath.Join(dir, "history.db"), nil
}

// OpenDefault opens the history store at its default path, returning nil (not an
// error) when it cannot be opened so the REPL degrades gracefully to having no
// persistent memory rather than failing to launch.
func OpenDefault() *Store {
	path, err := DBPath()
	if err != nil {
		return nil
	}
	s, err := Open(path)
	if err != nil {
		return nil
	}
	return s
}

// Open opens (creating if needed) the sqlite history database at path and
// ensures langchaingo's schema exists.
func Open(path string) (*Store, error) {
	// langchaingo blank-imports the mattn "sqlite3" driver; open the shared handle
	// through it so every per-session langchaingo handle reuses one connection pool.
	// WAL plus a busy timeout let the REPL and the engage harness write to the same
	// db file concurrently without "database is locked"; set them in the DSN so they
	// apply to every pooled connection. journal_mode=WAL persists in the file.
	dsn := "file:" + path + "?_busy_timeout=5000&_journal_mode=WAL"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.prepare(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// prepare runs the one-time setup every handle needs, retrying while the
// database is locked.
//
// Switching a fresh database to WAL takes an exclusive lock, and that switch
// does not go through the busy handler the DSN configures, so several blk
// processes opening the same new database at once can each be told the database
// is locked. The contention lasts only as long as one of them needs to finish
// its setup, so a bounded retry resolves it. Without this, a process that lost
// the race got no store at all: it would keep its transcripts but write no
// memory and no listing row.
func (s *Store) prepare() error {
	const attempts = 40
	var err error
	for i := range attempts {
		// Ping opens the first connection, which is where the DSN applies the
		// journal-mode switch, so it is inside the retry too.
		if err = s.db.Ping(); err == nil {
			// Rename an old blk_history table to blk_sessions before
			// langchaingo (re)creates the table under the new name, so existing
			// history survives the rename.
			s.migrate()
			// Constructing one handle runs langchaingo's CREATE TABLE IF NOT
			// EXISTS. It panics on a schema error, so recover into an error.
			if err = s.initSchema(); err == nil {
				if err = s.initSessionRows(); err == nil {
					return nil
				}
			}
		}
		if !lockedErr(err) {
			return err
		}
		if i < attempts-1 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	return err
}

// lockedErr reports whether err is SQLite's contention error. It matches on the
// message because the driver reports it as a plain error here, and the schema
// step reaches us through a recovered panic rather than a driver error value.
func lockedErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") || strings.Contains(msg, "database table is locked")
}

// migrate renames the old blk_history table to tableName when it exists and the
// new one does not. Best-effort: on any error the caller's
// initSchema still creates a fresh tableName, so a failed migration degrades to
// an empty (not corrupt) history rather than failing the open.
func (s *Store) migrate() {
	exists := func(name string) bool {
		var n int
		if err := s.db.QueryRow(
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", name,
		).Scan(&n); err != nil {
			return false
		}
		return n > 0
	}
	if exists(tableName) || !exists(legacyTableName) {
		return
	}
	_, _ = s.db.Exec("ALTER TABLE " + legacyTableName + " RENAME TO " + tableName)
}

// initSchema creates the table via a throwaway langchaingo handle, translating
// its panic-on-error into a returned error.
func (s *Store) initSchema() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("history schema init: %v", r)
		}
	}()
	s.handle("_schema")
	return nil
}

// handle returns a langchaingo history bound to one session, sharing s.db.
func (s *Store) handle(session string) *sqlite3.SqliteChatMessageHistory {
	return sqlite3.NewSqliteChatMessageHistory(
		sqlite3.WithDB(s.db),
		sqlite3.WithTableName(tableName),
		sqlite3.WithSession(session),
	)
}

// AppendUser records a user turn for the session.
func (s *Store) AppendUser(ctx context.Context, session, text string) error {
	return s.handle(session).AddUserMessage(ctx, text)
}

// AppendAI records an assistant turn for the session.
func (s *Store) AppendAI(ctx context.Context, session, text string) error {
	return s.handle(session).AddAIMessage(ctx, text)
}

// Messages returns the session's turns in insert order. An unknown session
// yields no rows and no error.
func (s *Store) Messages(ctx context.Context, session string) ([]Turn, error) {
	q := "SELECT content, type FROM " + tableName + " WHERE session = ? ORDER BY id ASC;"
	rows, err := s.db.QueryContext(ctx, q, session)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Turn
	for rows.Next() {
		var t Turn
		if err := rows.Scan(&t.Content, &t.Role); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Sessions returns every distinct session, most-recently-touched first, with its
// message count. Recency is the largest row id in the session, which is stable
// even when several rows share a one-second created timestamp.
func (s *Store) Sessions(ctx context.Context) ([]SessionMeta, error) {
	q := "SELECT session, COUNT(*) AS n FROM " + tableName +
		" GROUP BY session ORDER BY MAX(id) DESC;"
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionMeta
	for rows.Next() {
		var m SessionMeta
		if err := rows.Scan(&m.ID, &m.Count); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// EraseSession removes every row of one session. An unknown session is a no-op.
func (s *Store) EraseSession(ctx context.Context, session string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM "+tableName+" WHERE session = ?;", session)
	return err
}

// EraseAll removes every row, clearing all stored sessions.
func (s *Store) EraseAll(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM "+tableName+";")
	return err
}

// DB returns the shared database handle so other code in this binary can create
// and use its own namespaced tables in the same history database (WAL is on).
func (s *Store) DB() *sql.DB { return s.db }

// Close releases the database handle.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// privateDir creates dir with owner-only permissions, mirroring the helper in
// package main's paths.go (duplicated so this package stands alone).
func privateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}
