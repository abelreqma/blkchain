package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// session.go implements per-session transcript persistence.
// Each session is one append-only JSONL file, `<id>.jsonl`, under the blk data
// dir; a sidecar index.json holds one lightweight sessionMeta per session so the
// /resume picker can list sessions without reading every transcript. All IO is
// driven from the Bubble Tea main goroutine (tui.go message handlers), so no
// locking is needed; the package is otherwise pure enough to unit test by
// pointing XDG_DATA_HOME at a temp dir.

const (
	// sessionExt is the per-session transcript file extension.
	sessionExt = ".jsonl"
	// indexName is the sidecar index file listing all sessions.
	indexName = "index.json"
	// titleMaxLen bounds an auto-derived session title (runes).
	titleMaxLen = 40
	// maxSessionBytes bounds one transcript file so a runaway session can't grow
	// without limit (resource-limits). Past this, appendTurn refuses to write.
	maxSessionBytes = 4 << 20 // 4 MiB
)

// Turn roles. roleTombstone marks an /undo: on replay it drops the preceding
// user+assistant pair (see applyTombstones).
const (
	roleUser      = "user"
	roleAssistant = "assistant"
	roleTombstone = "tombstone"
)

// errSessionFull is returned by appendTurn when the transcript file has reached
// maxSessionBytes, so the caller can surface a one-line warning and stop.
var errSessionFull = errors.New("session transcript reached its size cap")

// turnRecord is one JSONL line in a session file.
type turnRecord struct {
	Role    string `json:"role"`
	Content string `json:"content"`
	Model   string `json:"model,omitempty"`
	Mode    string `json:"mode,omitempty"`
	TS      int64  `json:"ts"`
	Tokens  int    `json:"tokens,omitempty"`
}

// sessionMeta is one entry in index.json: enough to render the resume picker
// without opening the transcript.
type sessionMeta struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	MsgCount  int    `json:"msg_count"`
	UpdatedAt int64  `json:"updated_at"`
	Model     string `json:"model"`
	Mode      string `json:"mode"`
}

// session is a live handle to one transcript. The file and its index entry are
// created lazily on the first appendTurn, so launching blk (which calls
// newSession on start) never litters empty transcripts on disk.
type session struct {
	id    string
	dir   string
	title string
	count int
	model string
	mode  string
}

// sessionsDir resolves $XDG_DATA_HOME/blk/sessions, falling back to
// ~/.local/share/blk/sessions when XDG_DATA_HOME is unset.
func sessionsDir() (string, error) {
	base := strings.TrimSpace(os.Getenv("XDG_DATA_HOME"))
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	dir := filepath.Join(base, "blk", "sessions")
	if err := privateDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// newSessionID builds a sortable, collision-resistant id: a UTC timestamp
// (lexically sortable) plus 3 random bytes of hex.
func newSessionID() string {
	ts := time.Now().UTC().Format("20060102T150405")
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return ts + "-" + fmt.Sprintf("%06x", time.Now().UnixNano()&0xffffff)
	}
	return ts + "-" + hex.EncodeToString(b)
}

// newSession creates the private sessions dir and returns a fresh handle. The
// transcript file is written lazily on the first appendTurn.
func newSession() (*session, error) {
	dir, err := sessionsDir()
	if err != nil {
		return nil, err
	}
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	return &session{id: newSessionID(), dir: dir}, nil
}

// openSession returns a handle to an existing session, hydrated from index.json.
// It errors if the transcript file does not exist.
func openSession(id string) (*session, error) {
	if !validSessionID(id) {
		return nil, fmt.Errorf("invalid session id %q", id)
	}
	dir, err := sessionsDir()
	if err != nil {
		return nil, err
	}
	s := &session{id: id, dir: dir}
	metas, _ := readIndexRaw(dir)
	for _, m := range metas {
		if m.ID == id {
			s.title, s.count, s.model, s.mode = m.Title, m.MsgCount, m.Model, m.Mode
			break
		}
	}
	if _, err := os.Stat(s.filePath()); err != nil {
		return nil, fmt.Errorf("session %s not found", id)
	}
	if err := os.Chmod(s.filePath(), 0o600); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *session) filePath() string { return filepath.Join(s.dir, s.id+sessionExt) }

// validSessionID reports whether id is safe to use as the bare filename
// component of a session transcript path. index.json is untrusted (it's a
// file on disk, not something the program itself constrained at write time),
// so any id read back from it must be rejected before it reaches
// filepath.Join: no separators, and no "..".
func validSessionID(id string) bool {
	if id == "" || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return false
	}
	return id == filepath.Base(id)
}

// appendTurn appends one record to the transcript (creating the file 0644 on
// first write) and updates the sidecar index. A user record with no title yet
// seeds the auto title from its content. It refuses to write past
// maxSessionBytes (errSessionFull).
func (s *session) appendTurn(rec turnRecord) error {
	if rec.TS == 0 {
		rec.TS = time.Now().Unix()
	}
	path := s.filePath()
	if fi, err := os.Stat(path); err == nil && fi.Size() >= maxSessionBytes {
		return errSessionFull
	}
	if err := privateDir(s.dir); err != nil {
		return err
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	switch rec.Role {
	case roleUser:
		s.count++
		if s.title == "" {
			s.title = slugTitle(rec.Content)
		}
	case roleAssistant:
		s.count++
	case roleTombstone:
		s.count -= 2
		if s.count < 0 {
			s.count = 0
		}
	}
	if rec.Model != "" {
		s.model = rec.Model
	}
	if rec.Mode != "" {
		s.mode = rec.Mode
	}
	return s.syncIndex()
}

// meta snapshots the session's current index entry.
func (s *session) meta() sessionMeta {
	return sessionMeta{
		ID:        s.id,
		Title:     s.title,
		MsgCount:  s.count,
		UpdatedAt: time.Now().Unix(),
		Model:     s.model,
		Mode:      s.mode,
	}
}

// syncIndex upserts this session's entry in index.json.
func (s *session) syncIndex() error {
	metas, err := readIndexRaw(s.dir)
	if err != nil {
		return err
	}
	m := s.meta()
	found := false
	for i := range metas {
		if metas[i].ID == s.id {
			metas[i] = m
			found = true
			break
		}
	}
	if !found {
		metas = append(metas, m)
	}
	return writeIndex(s.dir, metas)
}

// listSessions returns every session's meta, newest first.
func listSessions() ([]sessionMeta, error) {
	dir, err := sessionsDir()
	if err != nil {
		return nil, err
	}
	metas, err := readIndexRaw(dir)
	if err != nil {
		return nil, err
	}
	out := metas[:0]
	for _, m := range metas {
		if validSessionID(m.ID) {
			out = append(out, m)
		}
	}
	metas = out
	sort.SliceStable(metas, func(i, j int) bool { return metas[i].UpdatedAt > metas[j].UpdatedAt })
	return metas, nil
}

// loadMessages reads a session transcript in order, with /undo tombstones
// applied so replay shows only the surviving turns.
func loadMessages(id string) ([]turnRecord, error) {
	if !validSessionID(id) {
		return nil, fmt.Errorf("invalid session id %q", id)
	}
	dir, err := sessionsDir()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(dir, id+sessionExt))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return nil, err
	}

	var recs []turnRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec turnRecord
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue // skip a corrupt line rather than fail the whole load
		}
		recs = append(recs, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return applyTombstones(recs), nil
}

// applyTombstones removes, for each roleTombstone record, the most recent
// surviving assistant then user record before it (the last exchange). It is pure
// so it can be unit tested directly.
func applyTombstones(recs []turnRecord) []turnRecord {
	out := make([]turnRecord, 0, len(recs))
	for _, r := range recs {
		if r.Role == roleTombstone {
			out = dropLastPair(out)
			continue
		}
		out = append(out, r)
	}
	return out
}

// dropLastPair pops a trailing assistant record then a trailing user record.
func dropLastPair(recs []turnRecord) []turnRecord {
	if n := len(recs); n > 0 && recs[n-1].Role == roleAssistant {
		recs = recs[:n-1]
	}
	if n := len(recs); n > 0 && recs[n-1].Role == roleUser {
		recs = recs[:n-1]
	}
	return recs
}

// deleteSession removes a session's transcript and its index entry.
func deleteSession(id string) error {
	if !validSessionID(id) {
		return fmt.Errorf("invalid session id %q", id)
	}
	dir, err := sessionsDir()
	if err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(dir, id+sessionExt))
	metas, err := readIndexRaw(dir)
	if err != nil {
		return err
	}
	out := metas[:0]
	for _, m := range metas {
		if m.ID != id {
			out = append(out, m)
		}
	}
	return writeIndex(dir, out)
}

// renameSession overrides a session's title in the index.
func renameSession(id, title string) error {
	if !validSessionID(id) {
		return fmt.Errorf("invalid session id %q", id)
	}
	dir, err := sessionsDir()
	if err != nil {
		return err
	}
	metas, err := readIndexRaw(dir)
	if err != nil {
		return err
	}
	title = strings.TrimSpace(title)
	for i := range metas {
		if metas[i].ID == id {
			metas[i].Title = title
			metas[i].UpdatedAt = time.Now().Unix()
			return writeIndex(dir, metas)
		}
	}
	return fmt.Errorf("session %s not found", id)
}

// slugTitle derives a short, single-line title from the first user message:
// whitespace collapsed, capped at titleMaxLen runes.
func slugTitle(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > titleMaxLen {
		return strings.TrimSpace(string(r[:titleMaxLen]))
	}
	return s
}

// readIndexRaw reads index.json unsorted, treating a missing file as empty.
func readIndexRaw(dir string) ([]sessionMeta, error) {
	data, err := os.ReadFile(filepath.Join(dir, indexName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if err := os.Chmod(filepath.Join(dir, indexName), 0o600); err != nil {
		return nil, err
	}
	var metas []sessionMeta
	if err := json.Unmarshal(data, &metas); err != nil {
		return nil, err
	}
	return metas, nil
}

// writeIndex writes index.json atomically (temp file + rename).
func writeIndex(dir string, metas []sessionMeta) error {
	if err := privateDir(dir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(metas, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, indexName+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, indexName))
}
