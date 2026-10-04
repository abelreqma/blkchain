package engagement

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"blkchain/cli/internal/webanalysis"
)

const webSchema = `CREATE TABLE IF NOT EXISTS web_record (kind TEXT NOT NULL, id TEXT NOT NULL, task_id TEXT NOT NULL, document TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY(kind,id)); CREATE INDEX IF NOT EXISTS web_task ON web_record(task_id,kind);`

var webHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (s *Store) EvidenceDir() string { return filepath.Join(filepath.Dir(s.path), "evidence") }
func (s *Store) PutWeb(ctx context.Context, kind, id, task string, v any) error {
	if !webHash.MatchString(id) {
		return errors.New("invalid web record id")
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("web metadata exceeds limit")
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if kind == "operation" {
		var old string
		err = s.db.QueryRowContext(ctx, `SELECT document FROM web_record WHERE kind=? AND id=?`, kind, id).Scan(&old)
		if err == nil {
			var a, b webanalysis.Operation
			if json.Unmarshal([]byte(old), &a) == nil && json.Unmarshal(data, &b) == nil {
				data, err = json.Marshal(webanalysis.MergeOperation(a, b))
				if err != nil {
					return err
				}
			}
		}
	}
	if len(data) > 1<<20 {
		return errors.New("merged web metadata exceeds limit")
	}
	var total, previous int
	if err = s.db.QueryRowContext(ctx, `SELECT coalesce(sum(length(cast(document AS BLOB))),0) FROM web_record`).Scan(&total); err != nil {
		return err
	}
	if err = s.db.QueryRowContext(ctx, `SELECT coalesce((SELECT length(cast(document AS BLOB)) FROM web_record WHERE kind=? AND id=?),0)`, kind, id).Scan(&previous); err != nil {
		return err
	}
	if total-previous+len(data) > 32<<20 {
		return errors.New("web metadata storage limit exhausted")
	}
	var count int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM web_record`).Scan(&count); err != nil {
		return err
	}
	if count >= webanalysis.MaxRecords {
		var n int
		if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM web_record WHERE kind=? AND id=?`, kind, id).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return errors.New("web record limit exhausted")
		}
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO web_record(kind,id,task_id,document,at) VALUES(?,?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET document=excluded.document,at=excluded.at`, kind, id, task, string(data), webanalysis.Now())
	return err
}
func (s *Store) WebSnapshot(ctx context.Context) (webanalysis.Snapshot, error) {
	out := webanalysis.Snapshot{}
	rows, err := s.db.QueryContext(ctx, `SELECT kind,document FROM web_record ORDER BY kind,id LIMIT ?`, webanalysis.MaxRecords)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	total := 0
	for rows.Next() {
		var k, d string
		if err = rows.Scan(&k, &d); err != nil {
			return out, err
		}
		total += len(d)
		if total > 32<<20 {
			return out, errors.New("web snapshot exceeds limit")
		}
		switch k {
		case "request":
			var v webanalysis.RequestExample
			err = json.Unmarshal([]byte(d), &v)
			out.Requests = append(out.Requests, v)
		case "export":
			var v webanalysis.Template
			err = json.Unmarshal([]byte(d), &v)
			out.Exports = append(out.Exports, v)
		case "artifact":
			var v webanalysis.Artifact
			err = json.Unmarshal([]byte(d), &v)
			out.Artifacts = append(out.Artifacts, v)
		case "unit":
			var v webanalysis.SourceUnit
			err = json.Unmarshal([]byte(d), &v)
			out.Units = append(out.Units, v)
		case "function":
			var v webanalysis.Function
			err = json.Unmarshal([]byte(d), &v)
			out.Functions = append(out.Functions, v)
		case "call":
			var v webanalysis.Call
			err = json.Unmarshal([]byte(d), &v)
			out.Calls = append(out.Calls, v)
		case "operation":
			var v webanalysis.Operation
			err = json.Unmarshal([]byte(d), &v)
			out.Operations = append(out.Operations, v)
		case "relationship":
			var v webanalysis.Relationship
			err = json.Unmarshal([]byte(d), &v)
			out.Relationships = append(out.Relationships, v)
		case "finding":
			var v webanalysis.Finding
			err = json.Unmarshal([]byte(d), &v)
			out.Findings = append(out.Findings, v)
		case "feature":
			var v webanalysis.Feature
			err = json.Unmarshal([]byte(d), &v)
			out.Features = append(out.Features, v)
		case "coverage":
			var v webanalysis.Coverage
			err = json.Unmarshal([]byte(d), &v)
			out.Coverage = append(out.Coverage, v)
		}
		if err != nil {
			return out, err
		}
	}
	return out, rows.Err()
}
func (s *Store) SaveWebArtifact(ctx context.Context, a webanalysis.Artifact, body []byte) (webanalysis.Artifact, error) {
	if len(body) > webanalysis.MaxSource {
		return a, errors.New("artifact exceeds body limit")
	}
	a.Hash = webanalysis.Hash(body)
	a.Size = len(body)
	if a.RetrievedAt == "" {
		a.RetrievedAt = webanalysis.Now()
	}
	if a.FinalURL == "" {
		a.FinalURL = a.URL
	}
	if a.ID == "" {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return a, err
		}
		a.ID = webanalysis.ID(a.Hash, a.URL, a.FinalURL, a.Role, a.CapturedAt, a.RetrievedAt, a.Kind, a.TaskID, hex.EncodeToString(nonce))
	}
	dir := filepath.Join(s.EvidenceDir(), "web", "blobs")
	if err := s.webBlobDir(); err != nil {
		return a, err
	}
	path := filepath.Join(dir, a.Hash)
	s.bmu.Lock()
	defer s.bmu.Unlock()
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return a, err
		}
		var total int64
		if len(entries) >= webanalysis.MaxRecords {
			return a, errors.New("web blob count limit exhausted")
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				return a, err
			}
			if !info.Mode().IsRegular() {
				return a, errors.New("invalid blob storage entry")
			}
			total += info.Size()
		}
		if total+int64(len(body)) > 256<<20 {
			return a, errors.New("web blob storage limit exhausted")
		}
		f, err := os.CreateTemp(dir, ".blob-")
		if err != nil {
			return a, err
		}
		tmp := f.Name()
		defer os.Remove(tmp)
		if _, err = f.Write(body); err != nil {
			f.Close()
			return a, err
		}
		if err = f.Close(); err != nil {
			return a, err
		}
		if err = os.Link(tmp, path); err != nil && !os.IsExist(err) {
			return a, err
		}
	} else if e != nil {
		return a, e
	}
	if _, err := s.WebBlob(a.Hash); err != nil {
		return a, err
	}
	return a, s.PutWeb(ctx, "artifact", a.ID, a.TaskID, a)
}
func (s *Store) WebBlob(hash string) ([]byte, error) {
	if !webHash.MatchString(hash) {
		return nil, errors.New("invalid artifact hash")
	}
	if err := s.webBlobDir(); err != nil {
		return nil, err
	}
	path := filepath.Join(s.EvidenceDir(), "web", "blobs", hash)
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > webanalysis.MaxSource {
		return nil, errors.New("invalid artifact file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return nil, errors.New("artifact changed during read")
	}
	b, err := io.ReadAll(io.LimitReader(f, webanalysis.MaxSource+1))
	if err != nil {
		return nil, err
	}
	if webanalysis.Hash(b) != hash {
		return nil, fmt.Errorf("artifact %s fails integrity check", hash)
	}
	return b, nil
}

func (s *Store) webBlobDir() error {
	p := s.EvidenceDir()
	for _, part := range []string{"", "web", "blobs"} {
		p = filepath.Join(p, part)
		if err := os.MkdirAll(p, 0700); err != nil {
			return err
		}
		st, err := os.Lstat(p)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("invalid artifact directory")
		}
		if err = os.Chmod(p, 0700); err != nil {
			return err
		}
	}
	return nil
}
