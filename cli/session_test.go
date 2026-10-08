package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"blkchain/cli/internal/histstore"
)

// tempSessions points the session store at a temp dir for the duration of a
// test, so nothing touches the real ~/.local/share.
func tempSessions(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir)
	return filepath.Join(dir, "blk", "sessions")
}

func TestNewSessionLazyFileAndAppend(t *testing.T) {
	tempSessions(t)

	s, err := newSession()
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	if s.id == "" {
		t.Fatal("newSession returned empty id")
	}
	// File is created lazily: nothing on disk before the first append.
	if _, err := os.Stat(s.filePath()); !os.IsNotExist(err) {
		t.Fatalf("transcript should not exist before first append, stat err = %v", err)
	}

	if err := s.appendTurn(turnRecord{Role: roleUser, Content: "how do I tune HNSW recall for my index quickly?"}); err != nil {
		t.Fatalf("appendTurn user: %v", err)
	}
	if err := s.appendTurn(turnRecord{Role: roleAssistant, Content: "Raise ef_search."}); err != nil {
		t.Fatalf("appendTurn assistant: %v", err)
	}

	if fi, err := os.Stat(s.filePath()); err != nil {
		t.Fatalf("transcript should exist after append: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("transcript perm = %v, want 0600", fi.Mode().Perm())
	}
	// The listing lives in the history database, not beside the transcripts, so
	// nothing writes a sidecar index any more.
	if _, err := os.Stat(filepath.Join(s.dir, indexName)); !os.IsNotExist(err) {
		t.Errorf("a sidecar index was written: %v", err)
	}
	if err := s.commitTurn("how do I tune HNSW recall for my index quickly?", "Raise ef_search."); err != nil {
		t.Fatalf("commitTurn: %v", err)
	}
	if store := openSessionStore(); store != nil {
		row, ok, err := store.GetSessionRow(context.Background(), s.id)
		if err != nil || !ok {
			t.Fatalf("listing row missing after a committed turn: %v %v", ok, err)
		}
		if row.MsgCount != 2 || !row.Watermark.Valid || row.Watermark.Int64 == 0 {
			t.Errorf("listing row = %+v, want 2 messages and a committed length", row)
		}
	}
	if fi, err := os.Stat(s.dir); err != nil {
		t.Fatalf("sessions directory should exist: %v", err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Errorf("sessions dir perm = %v, want 0700", fi.Mode().Perm())
	}

	// Title is the first user message, capped at titleMaxLen runes.
	if want := slugTitle("how do I tune HNSW recall for my index quickly?"); s.title != want {
		t.Errorf("auto title = %q, want %q", s.title, want)
	}
	if len([]rune(s.title)) > titleMaxLen {
		t.Errorf("title exceeds cap: %q", s.title)
	}
	if s.count != 2 {
		t.Errorf("count = %d, want 2", s.count)
	}
}

func TestListLoadRenameDelete(t *testing.T) {
	tempSessions(t)

	s, err := newSession()
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	// MsgCount counts committed turns, so it is read back from the memory rows.
	_ = s.appendTurn(turnRecord{Role: roleUser, Content: "first question"})
	_ = s.appendTurn(turnRecord{Role: roleAssistant, Content: "an answer"})
	if err := s.commitTurn("first question", "an answer"); err != nil {
		t.Fatalf("commitTurn: %v", err)
	}

	metas, err := listSessions()
	if err != nil {
		t.Fatalf("listSessions: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("listSessions len = %d, want 1", len(metas))
	}
	if metas[0].Title != "first question" || metas[0].MsgCount != 2 {
		t.Errorf("meta = %+v", metas[0])
	}

	recs, err := loadMessages(s.id)
	if err != nil {
		t.Fatalf("loadMessages: %v", err)
	}
	if len(recs) != 2 || recs[0].Role != roleUser || recs[1].Role != roleAssistant {
		t.Fatalf("loadMessages = %+v", recs)
	}

	if err := renameSession(s.id, "custom name"); err != nil {
		t.Fatalf("renameSession: %v", err)
	}
	metas, _ = listSessions()
	if metas[0].Title != "custom name" {
		t.Errorf("after rename title = %q", metas[0].Title)
	}

	if err := deleteSession(s.id); err != nil {
		t.Fatalf("deleteSession: %v", err)
	}
	if metas, _ := listSessions(); len(metas) != 0 {
		t.Errorf("after delete listSessions len = %d, want 0", len(metas))
	}
	if _, err := os.Stat(s.filePath()); !os.IsNotExist(err) {
		t.Errorf("transcript should be gone after delete, stat err = %v", err)
	}
}

func TestListSessionsNewestFirst(t *testing.T) {
	tempSessions(t)
	store := openSessionStore()
	if store == nil {
		t.Fatal("session store unavailable")
	}
	for _, m := range []histstore.SessionRow{
		{ID: "old", Title: "old", UpdatedAt: 100},
		{ID: "new", Title: "new", UpdatedAt: 300},
		{ID: "mid", Title: "mid", UpdatedAt: 200},
	} {
		if err := store.UpsertSessionRow(context.Background(), m); err != nil {
			t.Fatalf("UpsertSessionRow: %v", err)
		}
	}
	metas, err := listSessions()
	if err != nil {
		t.Fatalf("listSessions: %v", err)
	}
	got := []string{metas[0].ID, metas[1].ID, metas[2].ID}
	want := []string{"new", "mid", "old"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestLoadMessagesAppliesTombstone(t *testing.T) {
	tempSessions(t)
	s, _ := newSession()
	_ = s.appendTurn(turnRecord{Role: roleUser, Content: "q1"})
	_ = s.appendTurn(turnRecord{Role: roleAssistant, Content: "a1"})
	_ = s.appendTurn(turnRecord{Role: roleUser, Content: "q2"})
	_ = s.appendTurn(turnRecord{Role: roleAssistant, Content: "a2"})
	_ = s.appendTurn(turnRecord{Role: roleTombstone})

	recs, err := loadMessages(s.id)
	if err != nil {
		t.Fatalf("loadMessages: %v", err)
	}
	if len(recs) != 2 || recs[0].Content != "q1" || recs[1].Content != "a1" {
		t.Fatalf("after tombstone recs = %+v, want q1/a1", recs)
	}
	if s.count != 2 {
		t.Errorf("count after tombstone = %d, want 2", s.count)
	}
}

func TestAppendTurnSizeCap(t *testing.T) {
	tempSessions(t)
	s, _ := newSession()
	// Write a record and then force the file over the cap by padding on disk.
	_ = s.appendTurn(turnRecord{Role: roleUser, Content: "seed"})
	big := make([]byte, maxSessionBytes)
	if err := os.WriteFile(s.filePath(), big, 0o644); err != nil {
		t.Fatalf("pad file: %v", err)
	}
	if err := s.appendTurn(turnRecord{Role: roleAssistant, Content: "over cap"}); err != errSessionFull {
		t.Fatalf("appendTurn past cap err = %v, want errSessionFull", err)
	}
}

func TestSlugTitle(t *testing.T) {
	cases := []struct{ in, want string }{
		{"  hello   world  ", "hello world"},
		{"line one\nline two", "line one line two"},
		{strings.Repeat("a", 50), strings.Repeat("a", titleMaxLen)},
	}
	for _, tc := range cases {
		if got := slugTitle(tc.in); got != tc.want {
			t.Errorf("slugTitle(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestApplyTombstonesUnbalanced(t *testing.T) {
	// A tombstone with only a user record (no assistant) drops just the operator.
	recs := []turnRecord{{Role: roleUser, Content: "q"}, {Role: roleTombstone}}
	if got := applyTombstones(recs); len(got) != 0 {
		t.Errorf("applyTombstones dropped %d, want 0 remaining", len(got))
	}
	// A leading tombstone with nothing before it is a no-op.
	if got := applyTombstones([]turnRecord{{Role: roleTombstone}}); len(got) != 0 {
		t.Errorf("leading tombstone left %d records", len(got))
	}
}

func TestValidSessionID(t *testing.T) {
	bad := []string{"../x", "a/b", "a\\b", "..", "", "foo/../bar"}
	for _, id := range bad {
		if validSessionID(id) {
			t.Errorf("validSessionID(%q) = true, want false", id)
		}
	}
	good := newSessionID()
	if !validSessionID(good) {
		t.Errorf("validSessionID(%q) = false, want true", good)
	}
}

func TestEnsureFirst(t *testing.T) {
	got := ensureFirst([]string{"b", "a", "b"}, "a")
	want := []string{"a", "b"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("ensureFirst = %v, want %v", got, want)
	}
	// "unknown"/empty current is dropped, models deduped.
	got = ensureFirst([]string{"x", "x", "y"}, "unknown")
	if strings.Join(got, ",") != "x,y" {
		t.Errorf("ensureFirst(unknown) = %v, want [x y]", got)
	}
}

// Two blk processes share the sessions directory, and each holds its own handle.
// Interleaving their metadata writes the way two processes do must not lose
// either session: a whole-store read-modify-write drops whichever entry was
// written first, leaving a transcript on disk that no picker lists.
func TestConcurrentHandlesKeepBothSessions(t *testing.T) {
	tempSessions(t)

	first, err := newSession()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newSession()
	if err != nil {
		t.Fatal(err)
	}
	if first.id == second.id {
		t.Fatal("two sessions share an id")
	}

	// Each handle writes its transcript before either records its metadata,
	// which is the interleaving two processes produce.
	for _, s := range []*session{first, second} {
		if err := s.appendTurn(turnRecord{Role: roleUser, Content: "question for " + s.id}); err != nil {
			t.Fatal(err)
		}
	}

	metas, err := listSessions()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, m := range metas {
		seen[m.ID] = true
	}
	if !seen[first.id] || !seen[second.id] {
		t.Fatalf("a session was lost: listed %+v, want both %s and %s", metas, first.id, second.id)
	}
}

// A turn appends to the transcript and only then commits the memory rows, so an
// interrupted turn leaves transcript lines that were never committed. Reopening
// the session reconciles them away, so the two stores agree and undo works
// instead of refusing for the life of the session.
func TestUncommittedTranscriptTailIsReconciledOnOpen(t *testing.T) {
	tempSessions(t)
	store := openSessionStore()
	if store == nil {
		t.Fatal("session store unavailable")
	}

	s, err := newSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.appendTurn(turnRecord{Role: roleUser, Content: "committed question"}); err != nil {
		t.Fatal(err)
	}
	if err := s.appendTurn(turnRecord{Role: roleAssistant, Content: "committed answer"}); err != nil {
		t.Fatal(err)
	}
	if err := s.commitTurn("committed question", "committed answer"); err != nil {
		t.Fatalf("commitTurn: %v", err)
	}
	committed, err := os.Stat(s.filePath())
	if err != nil {
		t.Fatal(err)
	}

	// An interrupted turn: the transcript grows, nothing commits.
	if err := s.appendTurn(turnRecord{Role: roleUser, Content: "interrupted question"}); err != nil {
		t.Fatal(err)
	}
	if err := s.appendTurn(turnRecord{Role: roleAssistant, Content: "interrupted answer"}); err != nil {
		t.Fatal(err)
	}

	reopened, err := openSession(s.id)
	if err != nil {
		t.Fatalf("openSession: %v", err)
	}
	fi, err := os.Stat(reopened.filePath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != committed.Size() {
		t.Errorf("transcript size after reconcile = %d, want the committed %d", fi.Size(), committed.Size())
	}
	recs, err := loadMessages(s.id)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Content != "committed question" {
		t.Fatalf("replay kept the uncommitted tail: %+v", recs)
	}
}

// A sidecar index.json written by an older version is imported into the listing
// once and then set aside. An imported row carries no watermark, so its
// transcript counts as committed in full, and a row already in the table wins so
// the import cannot overwrite live state.
func TestLegacyIndexIsImportedOnceAndNeverOverwritesLiveRows(t *testing.T) {
	dir := tempSessions(t)
	if err := privateDir(dir); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal([]sessionMeta{
		{ID: "legacy-a", Title: "from the sidecar", MsgCount: 4, UpdatedAt: 100},
		{ID: "legacy-b", Title: "also from the sidecar", MsgCount: 2, UpdatedAt: 200},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, indexName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	// Opening the store imports the sidecar and sets it aside.
	store := openSessionStore()
	if store == nil {
		t.Fatal("session store unavailable")
	}
	titles := func() map[string]string {
		t.Helper()
		metas, err := listSessions()
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, m := range metas {
			out[m.ID] = m.Title
		}
		return out
	}
	if got := titles(); got["legacy-a"] != "from the sidecar" || got["legacy-b"] != "also from the sidecar" {
		t.Fatalf("sidecar was not imported: %v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, indexName)); !os.IsNotExist(err) {
		t.Errorf("sidecar was not set aside after the import: %v", err)
	}

	// A second import, which is what another process racing the first one does,
	// must not overwrite a row that is now live.
	if err := store.UpsertSessionRow(context.Background(), histstore.SessionRow{
		ID: "legacy-b", Title: "live title", UpdatedAt: 500,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, indexName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	importLegacyIndex(store)
	if got := titles(); got["legacy-b"] != "live title" {
		t.Errorf("legacy-b title = %q, want the live row to win over a re-import", got["legacy-b"])
	}
	// Nothing writes the sidecar any more, so a later turn must not recreate it.
	s, err := newSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.appendTurn(turnRecord{Role: roleUser, Content: "a question"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{indexName, indexName + ".tmp"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s was written again: %v", name, err)
		}
	}
}

// A transcript written before the watermark existed has no committed length
// recorded, which is what an imported row carries. Its whole transcript counts
// as committed, so reconciling must never truncate it: a length we cannot prove
// is uncommitted is left alone.
func TestSessionWithoutAWatermarkIsNotTruncated(t *testing.T) {
	dir := tempSessions(t)
	store := openSessionStore()
	if store == nil {
		t.Fatal("session store unavailable")
	}

	// A transcript on disk with no listing row, as an older version left it.
	id := "20260101T000000-abcdef"
	body := `{"role":"user","content":"pre-existing question","ts":1}` + "\n" +
		`{"role":"assistant","content":"pre-existing answer","ts":2}` + "\n"
	if err := privateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+sessionExt), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.ImportSessionRows(context.Background(), []histstore.SessionRow{
		{ID: id, Title: "pre-existing question", MsgCount: 2, UpdatedAt: 10},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := openSession(id); err != nil {
		t.Fatalf("openSession: %v", err)
	}
	after, err := os.Stat(filepath.Join(dir, id+sessionExt))
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != int64(len(body)) {
		t.Errorf("transcript truncated from %d to %d with no watermark recorded", len(body), after.Size())
	}
	recs, err := loadMessages(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Errorf("replay lost turns: %+v", recs)
	}
}

// The condition the single-process assumption failed under: several real blk
// processes writing sessions into one shared data directory at the same time.
// Each child commits one session, and every one of them must be listed
// afterwards. A whole-store read-modify-write loses the sessions whose writes
// were overtaken, so this counts them.
//
// The child half re-runs this same test in a subprocess, which is why it is
// keyed on an environment variable; it repoints XDG_DATA_HOME itself because
// TestMain gives every process its own hermetic root.
func TestCrossProcessSessionWritesAllSurvive(t *testing.T) {
	const children = 6

	if shared := os.Getenv("BLK_XPROC_DIR"); shared != "" {
		t.Setenv("XDG_DATA_HOME", shared)
		if openSessionStore() == nil {
			t.Fatal("the shared history database could not be opened")
		}
		s, err := newSession()
		if err != nil {
			t.Fatal(err)
		}
		q, a := "question from "+s.id, "answer for "+s.id
		if err := s.appendTurn(turnRecord{Role: roleUser, Content: q}); err != nil {
			t.Fatal(err)
		}
		if err := s.appendTurn(turnRecord{Role: roleAssistant, Content: a}); err != nil {
			t.Fatal(err)
		}
		if err := s.commitTurn(q, a); err != nil {
			t.Fatal(err)
		}
		return
	}

	shared := t.TempDir()
	var wg sync.WaitGroup
	failures := make([]string, children)
	for i := range children {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestCrossProcessSessionWritesAllSurvive$")
			cmd.Env = append(os.Environ(), "BLK_XPROC_DIR="+shared)
			if out, err := cmd.CombinedOutput(); err != nil {
				failures[i] = err.Error() + ": " + string(out)
			}
		}(i)
	}
	wg.Wait()
	for i, f := range failures {
		if f != "" {
			t.Fatalf("child %d failed: %s", i, f)
		}
	}

	t.Setenv("XDG_DATA_HOME", shared)
	metas, err := listSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != children {
		t.Fatalf("listed %d of %d sessions written by separate processes: %+v", len(metas), children, metas)
	}
	for _, m := range metas {
		if m.MsgCount != 2 {
			t.Errorf("session %s committed %d messages, want 2", m.ID, m.MsgCount)
		}
	}
}

// With no history database the listing is derived from the transcripts, so a
// session is still visible and resumable. This is the mode the REPL already has
// for conversation memory, and moving the listing into the database must not
// make sessions disappear in it.
func TestListingFallsBackToTheTranscriptsWithoutADatabase(t *testing.T) {
	dir := tempSessions(t)
	if err := privateDir(dir); err != nil {
		t.Fatal(err)
	}
	// A directory where the database file belongs, so it cannot be opened.
	base := filepath.Dir(dir)
	if err := os.MkdirAll(filepath.Join(base, "history.db"), 0o700); err != nil {
		t.Fatal(err)
	}
	if store := openSessionStore(); store != nil {
		t.Fatal("fixture did not make the database unopenable")
	}

	id := "20260101T010101-aaaaaa"
	body := `{"role":"user","content":"a degraded question","ts":1}` + "\n" +
		`{"role":"assistant","content":"a degraded answer","ts":2}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, id+sessionExt), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	metas, err := listSessions()
	if err != nil {
		t.Fatalf("listSessions: %v", err)
	}
	if len(metas) != 1 || metas[0].ID != id {
		t.Fatalf("listed %+v, want the session derived from its transcript", metas)
	}
	if metas[0].Title != "a degraded question" || metas[0].MsgCount != 2 {
		t.Errorf("derived meta = %+v, want the title and count from the transcript", metas[0])
	}
	// A turn still appends, and reconciling never truncates what it cannot judge.
	s, err := openSession(id)
	if err != nil {
		t.Fatalf("openSession: %v", err)
	}
	if err := s.appendTurn(turnRecord{Role: roleUser, Content: "another question"}); err != nil {
		t.Fatalf("appendTurn: %v", err)
	}
	recs, err := loadMessages(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Errorf("transcript lost turns without a database: %+v", recs)
	}
}

// A turn that appended its transcript lines but never reached its commit is
// uncommitted, so reopening removes the tail. This is the same mechanism as the
// reconcile test above, stated from the writer's side: a listing row that
// records nothing committed must not keep an unexplained transcript alive.
func TestAppendWithoutACommitIsNotTreatedAsCommitted(t *testing.T) {
	tempSessions(t)

	s, err := newSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.appendTurn(turnRecord{Role: roleUser, Content: "interrupted question"}); err != nil {
		t.Fatal(err)
	}
	if err := s.appendTurn(turnRecord{Role: roleAssistant, Content: "interrupted answer"}); err != nil {
		t.Fatal(err)
	}

	if _, err := openSession(s.id); err != nil {
		t.Fatalf("openSession: %v", err)
	}
	recs, err := loadMessages(s.id)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Errorf("uncommitted turn survived the reopen: %+v", recs)
	}
}
