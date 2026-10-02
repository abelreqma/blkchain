package main

import (
	"database/sql"
	"os"
	"time"
)

// roestore.go persists RoE recall-by-directory in the blk_roe table on the
// shared histstore handle (storage contract: a NEW table, never a
// blk_sessions key prefix). It lets `blk engage` remember which ROE.md goes with
// a working directory and reuse it on the next run from the same directory. All
// operations degrade gracefully when the store is unavailable (nil db).

// ensureRoETable creates the blk_roe table if it does not exist. A nil db is a
// no-op (the store is optional).
func ensureRoETable(db *sql.DB) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS blk_roe (
		workdir TEXT PRIMARY KEY,
		roe_path TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`)
	return err
}

// rememberRoE upserts the ROE.md path used for a working directory. A nil db is
// a graceful no-op.
func rememberRoE(db *sql.DB, workdir, roePath string) error {
	if db == nil {
		return nil
	}
	if err := ensureRoETable(db); err != nil {
		return err
	}
	_, err := db.Exec(`INSERT INTO blk_roe (workdir, roe_path, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(workdir) DO UPDATE SET roe_path=excluded.roe_path, updated_at=excluded.updated_at`,
		workdir, roePath, time.Now().UTC().Format(time.RFC3339))
	return err
}

// recallRoE returns the ROE.md path remembered for workdir, but only when that
// file still exists. A nil db, a miss, or a vanished file returns ("", false).
func recallRoE(db *sql.DB, workdir string) (string, bool) {
	if db == nil {
		return "", false
	}
	var p string
	if err := db.QueryRow(`SELECT roe_path FROM blk_roe WHERE workdir = ?`, workdir).Scan(&p); err != nil || p == "" {
		return "", false
	}
	if _, err := os.Stat(p); err != nil {
		return "", false
	}
	return p, true
}
