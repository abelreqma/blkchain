package engagement

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

const actionIndexSchema = `
CREATE TABLE IF NOT EXISTS action_record (
	id TEXT PRIMARY KEY,
	task_id TEXT NOT NULL,
	at TEXT NOT NULL,
	status TEXT NOT NULL,
	command TEXT NOT NULL,
	destination TEXT NOT NULL,
	exit_code INTEGER NOT NULL,
	reason TEXT NOT NULL,
	stdout_preview TEXT NOT NULL,
	stderr_preview TEXT NOT NULL,
	document TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS action_task ON action_record(task_id,at);
`

type actionFields struct {
	Task        string `json:"task"`
	At          string `json:"at"`
	Status      string `json:"status"`
	Command     string `json:"command"`
	Destination string `json:"destination"`
	ExitCode    int    `json:"exit_code"`
	Reason      string `json:"reason"`
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
}

func actionPreview(s string) string {
	if len(s) <= 1000 {
		return s
	}
	cut := 1000
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func actionDocument(line []byte) (string, actionFields, error) {
	if len(line) == 0 || len(line) > 128<<20 || !json.Valid(line) {
		return "", actionFields{}, errors.New("invalid action document")
	}
	var head actionFields
	if err := json.Unmarshal(line, &head); err != nil || head.At == "" || head.Status == "" {
		return "", actionFields{}, errors.New("invalid action fields")
	}
	hash := sha256.Sum256(line)
	return hex.EncodeToString(hash[:]), head, nil
}

// RecordActionDocument stores one exact action record as the engagement runs.
func (s *Store) RecordActionDocument(ctx context.Context, line []byte) error {
	id, head, err := actionDocument(line)
	if err != nil {
		return err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err = s.db.ExecContext(ctx, `INSERT OR IGNORE INTO action_record(id,task_id,at,status,command,destination,exit_code,reason,stdout_preview,stderr_preview,document) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, head.Task, head.At, head.Status, head.Command, head.Destination, head.ExitCode, head.Reason, actionPreview(head.Stdout), actionPreview(head.Stderr), string(line))
	return err
}

type ActionSummary struct {
	ID          string  `json:"id"`
	TaskID      string  `json:"task_id,omitempty"`
	Surface     Surface `json:"surface"`
	At          string  `json:"at"`
	Status      string  `json:"status"`
	Command     string  `json:"command"`
	Destination string  `json:"destination,omitempty"`
	ExitCode    int     `json:"exit_code"`
	Reason      string  `json:"reason,omitempty"`
	Stdout      string  `json:"stdout_preview,omitempty"`
	Stderr      string  `json:"stderr_preview,omitempty"`
}

func (s *Store) RecentActions(ctx context.Context, surface Surface, limit int) ([]ActionSummary, error) {
	if limit < 1 || limit > 100 || surface != "" && surface != "unclassified" && !surface.valid() {
		return nil, errors.New("invalid action summary query")
	}
	query := `SELECT a.id,a.task_id,a.at,a.status,a.command,a.destination,a.exit_code,a.reason,a.stdout_preview,a.stderr_preview,coalesce(nullif(t.surface,''),'unclassified')
		FROM action_record a LEFT JOIN task t ON t.id=a.task_id`
	args := []any{}
	if surface != "" {
		query += ` WHERE coalesce(nullif(t.surface,''),'unclassified')=?`
		args = append(args, string(surface))
	}
	query += ` ORDER BY a.rowid DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ActionSummary{}
	for rows.Next() {
		var a ActionSummary
		if err := rows.Scan(&a.ID, &a.TaskID, &a.At, &a.Status, &a.Command, &a.Destination, &a.ExitCode, &a.Reason, &a.Stdout, &a.Stderr, &a.Surface); err != nil {
			return nil, err
		}
		a.Command = strings.TrimSpace(a.Command)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ImportActionTranscript indexes complete transcript lines into SQLite. The
// original transcript remains the exact byte record; repeated imports are safe.
func (s *Store) ImportActionTranscript(ctx context.Context, path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 2<<30 {
		return errors.New("invalid action transcript file")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(st, opened) {
		return errors.New("action transcript changed during open")
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	reader := bufio.NewReaderSize(f, 64<<10)
	count := 0
	var consumed int64
	for {
		line, readErr := reader.ReadBytes('\n')
		consumed += int64(len(line))
		if consumed > 2<<30 {
			return errors.New("action transcript size limit exceeded")
		}
		if errors.Is(readErr, io.EOF) && len(line) == 0 {
			break
		}
		if len(line) > 128<<20 {
			return errors.New("action transcript line limit exceeded")
		}
		if errors.Is(readErr, io.EOF) {
			break // an active writer has not finished this line
		}
		if readErr != nil {
			return readErr
		}
		count++
		if count > 100000 {
			return errors.New("action transcript entry limit exceeded")
		}
		line = line[:len(line)-1]
		id, head, err := actionDocument(line)
		if err != nil {
			return fmt.Errorf("invalid action transcript entry %d", count)
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO action_record(id,task_id,at,status,command,destination,exit_code,reason,stdout_preview,stderr_preview,document) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, head.Task, head.At, head.Status, head.Command, head.Destination, head.ExitCode, head.Reason, actionPreview(head.Stdout), actionPreview(head.Stderr), string(line)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
