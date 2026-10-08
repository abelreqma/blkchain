package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"blkchain/cli/internal/histstore"
)

// session.go implements per-session transcript persistence.
// Each session is one append-only JSONL file, `<id>.jsonl`, under the blk data
// dir. The listing the /resume picker reads lives in the history database, so
// the picker does not have to open every transcript.
//
// The sessions directory is shared by every blk process, and the TUI and the
// plain REPL both create and open sessions in it, so the writes here are
// cross-process. They used to assume one process: the listing was a sidecar
// index.json that each writer read, changed and wrote back in full, which lost
// an entry whenever two processes read before either wrote, through one shared
// temp filename that concurrent writers could splice. The listing is now a row
// per session in the history database, where the row is the unit of update and
// SQLite serializes writers across processes. An index.json left by an older
// version is imported once (see importLegacyIndex) and then set aside.
//
// A turn's two stores are tied together by a watermark, the transcript length
// the committed memory rows account for: appendTurn writes the transcript and
// commitTurn commits the memory rows and that length in one transaction, which
// is the turn's only commit point. A process interrupted between the two leaves
// a transcript tail past the last committed watermark, and reconcileTranscript
// removes it when the session is next opened, so the two stores always converge.

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
	s.hydrate()
	if _, err := os.Stat(s.filePath()); err != nil {
		return nil, fmt.Errorf("session %s not found", id)
	}
	if err := os.Chmod(s.filePath(), 0o600); err != nil {
		return nil, err
	}
	if err := s.reconcileTranscript(); err != nil {
		return nil, err
	}
	return s, nil
}

// hydrate fills the handle's listing fields from the stored row, leaving them
// zero when there is no store or no row yet.
func (s *session) hydrate() {
	store := openSessionStore()
	if store == nil {
		return
	}
	m, ok, err := store.GetSessionRow(context.Background(), s.id)
	if err != nil || !ok {
		return
	}
	s.title, s.count, s.model, s.mode = m.Title, m.MsgCount, m.Model, m.Mode
}

// reconcileTranscript drops a transcript tail that no commit accounts for. A
// turn appends its lines and then commits the memory rows with the resulting
// length, so bytes past the committed watermark belong to a turn interrupted
// between the two and were never committed to memory. Removing them is what
// makes the two stores converge, so /undo compares equal instead of refusing
// for the life of the session.
//
// It never truncates when the length is unknown: no store, no row, or a row
// imported from the sidecar index, where the whole transcript counts as
// committed. Truncation is to a byte offset the writer recorded at a line
// boundary, and the transcript is append-only, so no surviving line is cut.
func (s *session) reconcileTranscript() error {
	store := openSessionStore()
	if store == nil {
		return nil
	}
	m, ok, err := store.GetSessionRow(context.Background(), s.id)
	if err != nil || !ok || !m.Watermark.Valid {
		return err
	}
	fi, err := os.Stat(s.filePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Size() <= m.Watermark.Int64 {
		return nil
	}
	return os.Truncate(s.filePath(), m.Watermark.Int64)
}

func (s *session) filePath() string { return filepath.Join(s.dir, s.id+sessionExt) }

// sessionExists reports whether a JSONL transcript file exists for id, so a
// caller can prefer the rich transcript replay (which honors /undo) over the
// langchaingo memory. An invalid id is treated as not present.
func sessionExists(id string) bool {
	if !validSessionID(id) {
		return false
	}
	dir, err := sessionsDir()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, id+sessionExt))
	return err == nil
}

func attachSession(id string) (*session, error) {
	if !validSessionID(id) {
		return nil, fmt.Errorf("invalid session id %q", id)
	}
	dir, err := sessionsDir()
	if err != nil {
		return nil, err
	}
	s := &session{id: id, dir: dir}
	s.hydrate()
	return s, nil
}

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

// appendTurn appends one record to the transcript, creating the file on first
// write, and records the session in the listing so a turn always makes it
// visible. A user record with no title yet seeds the auto title from its
// content. It refuses to write past maxSessionBytes (errSessionFull).
//
// The listing write says nothing is committed yet; the watermark moves only at a
// commit point. appendTombstone is the variant without it, for the one caller
// that appends from inside a store transaction.
func (s *session) appendTurn(rec turnRecord) error {
	if err := s.appendTombstone(rec); err != nil {
		return err
	}
	return s.ensureListed()
}

// appendTombstone appends one record to the transcript and writes no listing
// row. Undo calls it for the tombstone from inside the transaction
// UndoLastExchange holds: a listing write there would reach the same database on
// a second handle and wait out its busy timeout against that transaction's own
// write lock. UndoLastExchange writes the listing row itself, in the same
// transaction as the row deletions.
func (s *session) appendTombstone(rec turnRecord) error {
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
	return nil
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

// ensureListed records the session in the listing before its transcript grows,
// with nothing committed yet, so an interrupted turn leaves a row that says so
// and reconcileTranscript can tell the uncommitted tail from a transcript whose
// committed length is simply unknown. It leaves an existing row's watermark
// alone, so it is safe to call before every turn.
//
// It must not be called from inside a store transaction; see appendTurn.
func (s *session) ensureListed() error {
	store := openSessionStore()
	if store == nil {
		return nil
	}
	m := storeMeta(s.meta())
	m.Watermark = sql.NullInt64{Int64: 0, Valid: true}
	return store.UpsertSessionRow(context.Background(), m)
}

// syncIndex upserts this session's listing row after the transcript was rolled
// back, so the row matches the file again.
func (s *session) syncIndex() error { return s.ensureListed() }

// commitTurn is the commit point for one completed exchange: it records both
// memory rows and the transcript length they account for in one transaction,
// after the caller has appended both lines. Until it returns, the appended
// lines are uncommitted and reconcileTranscript will remove them.
func (s *session) commitTurn(user, ai string) error {
	store := openSessionStore()
	if store == nil {
		return nil
	}
	size, err := s.transcriptSize()
	if err != nil {
		return err
	}
	m := storeMeta(s.meta())
	m.Watermark = sql.NullInt64{Int64: size, Valid: size > 0}
	return store.CommitTurn(context.Background(), user, ai, m)
}

// transcriptSize is the transcript's current length, 0 when it does not exist.
func (s *session) transcriptSize() (int64, error) {
	fi, err := os.Stat(s.filePath())
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return fi.Size(), nil
}

// listSessions returns every session's meta, newest first. With no history
// database it derives the listing from the transcripts instead, which is the
// degraded path: correct, but it opens every file, which is what the listing
// table exists to avoid.
func listSessions() ([]sessionMeta, error) {
	dir, err := sessionsDir()
	if err != nil {
		return nil, err
	}
	store := openSessionStore()
	if store == nil {
		return scanSessions(dir)
	}
	rows, err := store.SessionRows(context.Background())
	if err != nil {
		return nil, err
	}
	metas := make([]sessionMeta, 0, len(rows))
	for _, r := range rows {
		if validSessionID(r.ID) {
			metas = append(metas, localMeta(r))
		}
	}
	sort.SliceStable(metas, func(i, j int) bool { return metas[i].UpdatedAt > metas[j].UpdatedAt })
	return metas, nil
}

// scanSessions derives the listing by reading each transcript: the title from
// the first surviving user turn, the count from the surviving turns, and the
// timestamp from the file. A transcript that cannot be read is skipped rather
// than failing the whole listing.
func scanSessions(dir string) ([]sessionMeta, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var metas []sessionMeta
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), sessionExt) {
			continue
		}
		id := strings.TrimSuffix(e.Name(), sessionExt)
		if !validSessionID(id) {
			continue
		}
		recs, err := loadMessages(id)
		if err != nil {
			continue
		}
		m := sessionMeta{ID: id, MsgCount: len(recs)}
		if info, err := e.Info(); err == nil {
			m.UpdatedAt = info.ModTime().Unix()
		}
		for _, r := range recs {
			if m.Title == "" && r.Role == roleUser {
				m.Title = slugTitle(r.Content)
			}
			if r.Model != "" {
				m.Model = r.Model
			}
			if r.Mode != "" {
				m.Mode = r.Mode
			}
		}
		metas = append(metas, m)
	}
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
	store := openSessionStore()
	if store == nil {
		return nil
	}
	return store.DeleteSessionRow(context.Background(), id)
}

// deleteAllSessions removes every session transcript and the sidecar index, so
// the JSONL side of the store is wiped. Missing files are ignored.
func deleteAllSessions() error {
	dir, err := sessionsDir()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if name == indexName || strings.HasSuffix(name, sessionExt) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
	store := openSessionStore()
	if store == nil {
		return nil
	}
	return store.DeleteAllSessionRows(context.Background())
}

// renameSession overrides a session's title in the listing. It changes only the
// title, so a concurrent writer's turn cannot be undone by the rename.
func renameSession(id, title string) error {
	if !validSessionID(id) {
		return fmt.Errorf("invalid session id %q", id)
	}
	store := openSessionStore()
	if store == nil {
		return errors.New("rename needs the history database, which is unavailable")
	}
	m, ok, err := store.GetSessionRow(context.Background(), id)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("session %s not found", id)
	}
	m.Title = strings.TrimSpace(title)
	m.UpdatedAt = time.Now().Unix()
	return store.UpsertSessionRow(context.Background(), m)
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

// readIndexRaw reads a legacy index.json unsorted, treating a missing file as
// empty. It is only the source for importLegacyIndex; nothing writes this file.
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

// The handle to the history database the session listing lives in, cached per
// resolved database path. The path is keyed rather than opened once because it
// derives from the environment, which a test repoints per case; a cache that
// ignored it would answer later cases from the first case's database.
var (
	sessionStoreMu   sync.Mutex
	sessionStorePath string
	sessionStoreVal  *histstore.Store
	sessionStoreOpen bool
)

// openSessionStore returns the handle to the history database the session
// listing lives in, opening it on first use for a given path. It returns nil
// when the database cannot be opened, which is the degraded mode the REPL
// already has for conversation memory: transcripts keep working and
// listSessions derives the listing from them instead.
func openSessionStore() *histstore.Store {
	path, err := histstore.DBPath()
	if err != nil {
		return nil
	}
	sessionStoreMu.Lock()
	defer sessionStoreMu.Unlock()
	if sessionStoreOpen && sessionStorePath == path {
		return sessionStoreVal
	}
	if sessionStoreVal != nil {
		_ = sessionStoreVal.Close()
	}
	sessionStoreOpen, sessionStorePath = true, path
	sessionStoreVal = histstore.OpenDefault()
	if sessionStoreVal != nil {
		importLegacyIndex(sessionStoreVal)
	}
	return sessionStoreVal
}

// importLegacyIndex folds a sidecar index.json written by an older version into
// the listing table, then renames it aside so it is imported once. An existing
// row always wins, so this cannot overwrite live state, and imported rows carry
// no watermark, so their transcripts count as committed in full and are never
// truncated. Best-effort: a failure leaves the file in place for the next run
// rather than failing the session.
func importLegacyIndex(store *histstore.Store) {
	dir, err := sessionsDir()
	if err != nil {
		return
	}
	metas, err := readIndexRaw(dir)
	if err != nil || len(metas) == 0 {
		return
	}
	rows := make([]histstore.SessionRow, 0, len(metas))
	for _, m := range metas {
		if validSessionID(m.ID) {
			rows = append(rows, storeMeta(m))
		}
	}
	if err := store.ImportSessionRows(context.Background(), rows); err != nil {
		return
	}
	_ = os.Rename(filepath.Join(dir, indexName), filepath.Join(dir, indexName+".imported"))
}

// storeMeta converts a listing entry to its stored form, carrying no watermark.
func storeMeta(m sessionMeta) histstore.SessionRow {
	return histstore.SessionRow{
		ID: m.ID, Title: m.Title, MsgCount: m.MsgCount,
		UpdatedAt: m.UpdatedAt, Model: m.Model, Mode: m.Mode,
	}
}

// localMeta converts a stored listing row back to the in-process form.
func localMeta(m histstore.SessionRow) sessionMeta {
	return sessionMeta{
		ID: m.ID, Title: m.Title, MsgCount: m.MsgCount,
		UpdatedAt: m.UpdatedAt, Model: m.Model, Mode: m.Mode,
	}
}
