package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"blkchain/cli/internal/histstore"
)

// sqlToolHelpCache is the sqlite-backed toolHelpCache. It stores learned tool
// interfaces in the blk_tool_help table on the shared history database so a
// tool's help is read once and reused across engagements.
type sqlToolHelpCache struct {
	db *sql.DB
}

// newSQLToolHelpCache creates the blk_tool_help table (if absent) and returns a
// cache over db. A nil db yields (nil, nil) so the caller treats grounding as
// disabled and degrades gracefully.
func newSQLToolHelpCache(db *sql.DB) (*sqlToolHelpCache, error) {
	if db == nil {
		return nil, nil
	}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS blk_tool_help (
		binary TEXT NOT NULL,
		version TEXT NOT NULL,
		flags TEXT NOT NULL,
		subcommands TEXT NOT NULL,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (binary, version)
	);`)
	if err != nil {
		return nil, err
	}
	return &sqlToolHelpCache{db: db}, nil
}

// Lookup returns the cached interface for binary+version. A missing row is a
// miss (hit=false), not an error. A query or scan error is returned.
func (c *sqlToolHelpCache) Lookup(binary, version string) (toolInterface, bool, error) {
	var flagsJSON, subsJSON string
	err := c.db.QueryRow(
		`SELECT flags, subcommands FROM blk_tool_help WHERE binary = ? AND version = ?`,
		binary, version,
	).Scan(&flagsJSON, &subsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return toolInterface{}, false, nil
	}
	if err != nil {
		return toolInterface{}, false, err
	}
	var iface toolInterface
	if err := json.Unmarshal([]byte(flagsJSON), &iface.Flags); err != nil {
		return toolInterface{}, false, err
	}
	if err := json.Unmarshal([]byte(subsJSON), &iface.Subcommands); err != nil {
		return toolInterface{}, false, err
	}
	return iface, true, nil
}

// Store upserts the interface for binary+version. INSERT OR REPLACE keeps the
// write idempotent when two executors ground the same binary concurrently.
func (c *sqlToolHelpCache) Store(binary, version string, iface toolInterface) error {
	flagsJSON, err := json.Marshal(iface.Flags)
	if err != nil {
		return err
	}
	subsJSON, err := json.Marshal(iface.Subcommands)
	if err != nil {
		return err
	}
	_, err = c.db.Exec(
		`INSERT OR REPLACE INTO blk_tool_help (binary, version, flags, subcommands, updated_at) VALUES (?,?,?,?,?)`,
		binary, version, string(flagsJSON), string(subsJSON), time.Now().Unix(),
	)
	return err
}

// openToolHelpCache opens the shared history database and builds a tool-help
// cache over it, returning the cache plus a close func. On any failure it
// returns (nil, no-op) so grounding degrades to disabled. The returned
// toolHelpCache is the untyped nil on failure so a caller's `cache == nil`
// check works (a typed-nil interface is not == nil).
func openToolHelpCache() (toolHelpCache, func()) {
	store := histstore.OpenDefault()
	if store == nil {
		return nil, func() {}
	}
	cache, err := newSQLToolHelpCache(store.DB())
	if err != nil || cache == nil {
		store.Close()
		return nil, func() {}
	}
	return cache, func() { store.Close() }
}
