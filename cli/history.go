package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	// historyMaxEntries and historyMaxBytes cap the history file, what
	// loadHistory returns, and the TUI's history in memory; the newest entries
	// are kept.
	historyMaxEntries = 1000
	historyMaxBytes   = 1 << 20
	// historyTrimEntries and historyTrimBytes are what a file at the cap is
	// trimmed to, so the next rewrite is at least 100 appends away.
	historyTrimEntries = 900
	historyTrimBytes   = historyMaxBytes / 10 * 9
	// historyMaxEntryBytes is the longest line read back as an entry. A longer
	// line is skipped, not stored.
	historyMaxEntryBytes = historyMaxBytes / 2
)

// historyPath returns ~/.config/blkchain/history (honoring XDG_CONFIG_HOME),
// mirroring the pattern in paths.go's configPath.
func historyPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	path := filepath.Join(base, "blkchain", "history")
	if err := privateDir(filepath.Dir(path)); err != nil {
		return "", err
	}
	return path, nil
}

// loadHistory returns the REPL's saved command history, oldest first, at most
// historyMaxEntries. It returns nil if the history file is missing or
// unreadable.
func loadHistory() []string {
	p, err := historyPath()
	if err != nil {
		return nil
	}
	entries, _, err := readHistory(p)
	if err != nil {
		return nil
	}
	return entries
}

// errHistoryNotRegular refuses a history path that is a symlink or anything
// else that is not a regular file.
var errHistoryNotRegular = errors.New("the history file is not a regular file")

// readHistory reads the newest historyMaxBytes of the file at p and returns its
// newest historyMaxEntries entries and the file's size. Each line holds one
// entry as a JSON string, so a multi-line draft stays one entry; a line that is
// not a JSON string is a plain entry from an older file. A line longer than
// historyMaxEntryBytes is skipped, and never costs the lines around it. A path
// that is a symlink or not a regular file is neither read nor chmod-ed.
func readHistory(p string) ([]string, int64, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, 0, err
	}
	if !fi.Mode().IsRegular() {
		return nil, 0, errHistoryNotRegular
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return nil, 0, err
	}
	if fi, err = f.Stat(); err != nil {
		return nil, 0, err
	}
	size := fi.Size()
	skipFirst := false
	if size > historyMaxBytes {
		// Start inside the newest historyMaxBytes and drop the partial first line.
		if _, err := f.Seek(size-historyMaxBytes, io.SeekStart); err != nil {
			return nil, 0, err
		}
		skipFirst = true
	}
	data, err := io.ReadAll(io.LimitReader(f, historyMaxBytes))
	if err != nil {
		return nil, 0, err
	}
	lines := bytes.Split(data, []byte("\n"))
	if skipFirst {
		lines = lines[1:]
	}
	var entries []string
	for _, ln := range lines {
		if len(ln) == 0 || len(ln) > historyMaxEntryBytes {
			continue
		}
		var e string
		if json.Unmarshal(ln, &e) != nil {
			e = string(ln)
		}
		entries = append(entries, e)
	}
	if len(entries) > historyMaxEntries {
		entries = entries[len(entries)-historyMaxEntries:]
	}
	return entries, size, nil
}

// appendHistory appends one entry to the history file, creating private
// storage for the file if needed. Blank entries, entries identical to the last
// saved one, and entries too long to read back are skipped. When the file
// would pass historyMaxEntries or historyMaxBytes it is rewritten with the
// newest entries that fit in historyTrimEntries and historyTrimBytes.
func appendHistory(line string) error {
	if strings.TrimSpace(line) == "" {
		return nil
	}
	enc, err := json.Marshal(line)
	if err != nil || len(enc) > historyMaxEntryBytes {
		return err
	}

	p, err := historyPath()
	if err != nil {
		return err
	}
	entries, size, err := readHistory(p)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(entries) > 0 && entries[len(entries)-1] == line {
		return nil
	}
	if len(entries) >= historyMaxEntries || size+int64(len(enc))+1 > historyMaxBytes {
		return rewriteHistory(p, append(entries, line))
	}

	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	_, err = f.Write(append(enc, '\n'))
	return err
}

// rewriteHistory replaces the file at p with the newest entries that fit in
// historyTrimEntries and historyTrimBytes, so the next rewrite is at least 100
// appends away. It writes a private temp file and renames it into place.
func rewriteHistory(p string, entries []string) error {
	var lines [][]byte
	total := 0
	for i := len(entries) - 1; i >= 0 && len(lines) < historyTrimEntries; i-- {
		enc, err := json.Marshal(entries[i])
		if err != nil {
			return err
		}
		if total+len(enc)+1 > historyTrimBytes && len(lines) > 0 {
			break
		}
		total += len(enc) + 1
		lines = append(lines, enc)
	}
	var buf bytes.Buffer
	for i := len(lines) - 1; i >= 0; i-- {
		buf.Write(lines[i])
		buf.WriteByte('\n')
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".history-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once the rename has moved it
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}
