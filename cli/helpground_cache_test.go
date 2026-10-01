package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func openTestCache(t *testing.T) *sqlToolHelpCache {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	c, err := newSQLToolHelpCache(db)
	if err != nil {
		t.Fatalf("newSQLToolHelpCache: %v", err)
	}
	return c
}

func TestToolHelpCacheRoundTrip(t *testing.T) {
	c := openTestCache(t)
	if _, hit, err := c.Lookup("nmap", "v1"); err != nil || hit {
		t.Fatalf("empty lookup: hit=%v err=%v", hit, err)
	}
	want := toolInterface{Flags: []string{"-sV", "--script"}}
	if err := c.Store("nmap", "v1", want); err != nil {
		t.Fatalf("store: %v", err)
	}
	got, hit, err := c.Lookup("nmap", "v1")
	if err != nil || !hit {
		t.Fatalf("lookup after store: hit=%v err=%v", hit, err)
	}
	if len(got.Flags) != 2 || got.Flags[0] != "-sV" || got.Flags[1] != "--script" {
		t.Fatalf("flags round-trip mismatch: %#v", got.Flags)
	}
}

func TestToolHelpCacheReplaceIsIdempotent(t *testing.T) {
	c := openTestCache(t)
	if err := c.Store("git", "v1", toolInterface{Subcommands: []string{"clone"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Store("git", "v1", toolInterface{Subcommands: []string{"clone", "push"}}); err != nil {
		t.Fatal(err)
	}
	got, hit, err := c.Lookup("git", "v1")
	if err != nil || !hit {
		t.Fatalf("hit=%v err=%v", hit, err)
	}
	if len(got.Subcommands) != 2 {
		t.Fatalf("replace should keep the latest: %#v", got.Subcommands)
	}
}

func TestNewSQLToolHelpCacheNilDB(t *testing.T) {
	c, err := newSQLToolHelpCache(nil)
	if err != nil || c != nil {
		t.Fatalf("nil db should yield (nil,nil): c=%v err=%v", c, err)
	}
}
