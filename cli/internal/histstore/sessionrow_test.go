package histstore

import (
	"context"
	"database/sql"
	"testing"
)

func watermark(n int64) sql.NullInt64 { return sql.NullInt64{Int64: n, Valid: true} }

func getRow(t *testing.T, s *Store, id string) SessionRow {
	t.Helper()
	m, ok, err := s.GetSessionRow(context.Background(), id)
	if err != nil {
		t.Fatalf("GetSessionRow(%q): %v", id, err)
	}
	if !ok {
		t.Fatalf("GetSessionRow(%q): no row", id)
	}
	return m
}

func TestSessionRowRoundTrip(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()

	in := SessionRow{ID: "s1", Title: "ssrf chain", UpdatedAt: 100, Model: "m", Mode: "rag", Watermark: watermark(512)}
	if err := s.UpsertSessionRow(ctx, in); err != nil {
		t.Fatalf("UpsertSessionRow: %v", err)
	}

	got := getRow(t, s, "s1")
	if got.ID != in.ID || got.Title != in.Title || got.UpdatedAt != in.UpdatedAt ||
		got.Model != in.Model || got.Mode != in.Mode || got.Watermark != in.Watermark {
		t.Errorf("row = %+v, want %+v", got, in)
	}
}

func TestGetSessionRowUnknownSessionIsNotAnError(t *testing.T) {
	s := newTestHistStore(t)

	m, ok, err := s.GetSessionRow(context.Background(), "absent")
	if err != nil {
		t.Fatalf("GetSessionRow: %v", err)
	}
	if ok {
		t.Errorf("ok = true for an unknown session, got row %+v", m)
	}
}

func TestSessionRowMsgCountComesFromTheMemoryRows(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()

	if err := s.AppendUser(ctx, "s1", "q"); err != nil {
		t.Fatalf("AppendUser: %v", err)
	}
	if err := s.AppendAI(ctx, "s1", "a"); err != nil {
		t.Fatalf("AppendAI: %v", err)
	}

	if err := s.UpsertSessionRow(ctx, SessionRow{ID: "s1", MsgCount: 99}); err != nil {
		t.Fatalf("UpsertSessionRow: %v", err)
	}
	if got := getRow(t, s, "s1").MsgCount; got != 2 {
		t.Errorf("MsgCount = %d, want 2", got)
	}
}

func TestSessionRowUpdatedAtOnlyMovesForward(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()

	if err := s.UpsertSessionRow(ctx, SessionRow{ID: "s1", UpdatedAt: 200}); err != nil {
		t.Fatalf("UpsertSessionRow: %v", err)
	}
	if err := s.UpsertSessionRow(ctx, SessionRow{ID: "s1", UpdatedAt: 100}); err != nil {
		t.Fatalf("UpsertSessionRow: %v", err)
	}
	if got := getRow(t, s, "s1").UpdatedAt; got != 200 {
		t.Errorf("UpdatedAt = %d after a stale write, want 200", got)
	}
}

func TestSessionRowWatermarkOnlyMovesForward(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()

	if err := s.UpsertSessionRow(ctx, SessionRow{ID: "s1", Watermark: watermark(900)}); err != nil {
		t.Fatalf("UpsertSessionRow: %v", err)
	}
	if err := s.UpsertSessionRow(ctx, SessionRow{ID: "s1", Watermark: watermark(300)}); err != nil {
		t.Fatalf("UpsertSessionRow: %v", err)
	}
	if got := getRow(t, s, "s1").Watermark; got != watermark(900) {
		t.Errorf("Watermark = %+v after a stale write, want 900", got)
	}
}

func TestSessionRowUnrecordedWatermarkStaysUnrecorded(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()

	if err := s.UpsertSessionRow(ctx, SessionRow{ID: "s1"}); err != nil {
		t.Fatalf("UpsertSessionRow: %v", err)
	}
	if err := s.UpsertSessionRow(ctx, SessionRow{ID: "s1", Watermark: watermark(64)}); err != nil {
		t.Fatalf("UpsertSessionRow: %v", err)
	}
	if got := getRow(t, s, "s1").Watermark; got.Valid {
		t.Errorf("Watermark = %+v, want it to stay unrecorded", got)
	}
}

func TestSessionRowIncomingUnrecordedWatermarkKeepsTheKnownOne(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()

	if err := s.UpsertSessionRow(ctx, SessionRow{ID: "s1", Watermark: watermark(700)}); err != nil {
		t.Fatalf("UpsertSessionRow: %v", err)
	}
	if err := s.UpsertSessionRow(ctx, SessionRow{ID: "s1", Title: "renamed"}); err != nil {
		t.Fatalf("UpsertSessionRow: %v", err)
	}
	got := getRow(t, s, "s1")
	if got.Watermark != watermark(700) {
		t.Errorf("Watermark = %+v, want 700", got.Watermark)
	}
	if got.Title != "renamed" {
		t.Errorf("Title = %q, want the rename to apply", got.Title)
	}
}

func TestSessionRowsNewestUpdatedFirst(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()

	// "b" and "c" share an updated_at, so id descending breaks the tie.
	for _, m := range []SessionRow{
		{ID: "a", UpdatedAt: 10},
		{ID: "b", UpdatedAt: 30},
		{ID: "c", UpdatedAt: 30},
	} {
		if err := s.UpsertSessionRow(ctx, m); err != nil {
			t.Fatalf("UpsertSessionRow(%q): %v", m.ID, err)
		}
	}

	rows, err := s.SessionRows(ctx)
	if err != nil {
		t.Fatalf("SessionRows: %v", err)
	}
	var ids []string
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	want := []string{"c", "b", "a"}
	if len(ids) != len(want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids = %v, want %v", ids, want)
		}
	}
}

func TestDeleteSessionRowLeavesTheOthers(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()

	for _, id := range []string{"s1", "s2"} {
		if err := s.UpsertSessionRow(ctx, SessionRow{ID: id}); err != nil {
			t.Fatalf("UpsertSessionRow(%q): %v", id, err)
		}
	}
	if err := s.DeleteSessionRow(ctx, "s1"); err != nil {
		t.Fatalf("DeleteSessionRow: %v", err)
	}
	if err := s.DeleteSessionRow(ctx, "absent"); err != nil {
		t.Fatalf("DeleteSessionRow(absent): %v", err)
	}

	rows, err := s.SessionRows(ctx)
	if err != nil {
		t.Fatalf("SessionRows: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "s2" {
		t.Errorf("rows = %+v, want only s2", rows)
	}
}

func TestDeleteAllSessionRowsEmptiesTheListing(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()

	for _, id := range []string{"s1", "s2"} {
		if err := s.UpsertSessionRow(ctx, SessionRow{ID: id}); err != nil {
			t.Fatalf("UpsertSessionRow(%q): %v", id, err)
		}
	}
	if err := s.DeleteAllSessionRows(ctx); err != nil {
		t.Fatalf("DeleteAllSessionRows: %v", err)
	}

	rows, err := s.SessionRows(ctx)
	if err != nil {
		t.Fatalf("SessionRows: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("rows = %+v, want none", rows)
	}
}

func TestImportSessionRowsNeverOverwritesALiveRow(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()

	if err := s.UpsertSessionRow(ctx, SessionRow{ID: "s1", Title: "live", UpdatedAt: 500, Watermark: watermark(128)}); err != nil {
		t.Fatalf("UpsertSessionRow: %v", err)
	}
	in := []SessionRow{
		{ID: "s1", Title: "from the sidecar", UpdatedAt: 1},
		{ID: "s2", Title: "new", UpdatedAt: 2, MsgCount: 4},
	}
	if err := s.ImportSessionRows(ctx, in); err != nil {
		t.Fatalf("ImportSessionRows: %v", err)
	}
	if err := s.ImportSessionRows(ctx, in); err != nil {
		t.Fatalf("ImportSessionRows again: %v", err)
	}

	live := getRow(t, s, "s1")
	if live.Title != "live" || live.UpdatedAt != 500 || live.Watermark != watermark(128) {
		t.Errorf("live row = %+v, want the upserted values untouched", live)
	}
	added := getRow(t, s, "s2")
	if added.Title != "new" || added.MsgCount != 4 {
		t.Errorf("imported row = %+v, want title new and count 4", added)
	}
	if added.Watermark.Valid {
		t.Errorf("imported Watermark = %+v, want unrecorded", added.Watermark)
	}
}

func TestCommitTurnWritesBothMessagesAndTheRowTogether(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()

	meta := SessionRow{ID: "s1", Title: "t", UpdatedAt: 42, Model: "m", Mode: "rag", Watermark: watermark(256)}
	if err := s.CommitTurn(ctx, "a question", "an answer", meta); err != nil {
		t.Fatalf("CommitTurn: %v", err)
	}

	msgs, err := s.Messages(ctx, "s1")
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	want := []Turn{{Role: RoleUser, Content: "a question"}, {Role: RoleAI, Content: "an answer"}}
	if len(msgs) != len(want) {
		t.Fatalf("messages = %+v, want %+v", msgs, want)
	}
	for i, w := range want {
		if msgs[i] != w {
			t.Errorf("msg[%d] = %+v, want %+v", i, msgs[i], w)
		}
	}

	row := getRow(t, s, "s1")
	if row.MsgCount != 2 {
		t.Errorf("MsgCount = %d, want 2", row.MsgCount)
	}
	if row.Watermark != watermark(256) {
		t.Errorf("Watermark = %+v, want 256", row.Watermark)
	}
	if row.UpdatedAt != 42 {
		t.Errorf("UpdatedAt = %d, want 42", row.UpdatedAt)
	}
}

func TestCommitTurnRollsBackTheMessagesWhenTheRowWriteFails(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()

	// Dropping the listing table makes the upsert inside the transaction fail.
	if _, err := s.DB().Exec("DROP TABLE " + sessionRowTable + ";"); err != nil {
		t.Fatalf("DROP TABLE: %v", err)
	}

	if err := s.CommitTurn(ctx, "a question", "an answer", SessionRow{ID: "s1"}); err == nil {
		t.Fatal("CommitTurn succeeded with no listing table, want an error")
	}

	msgs, err := s.Messages(ctx, "s1")
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("messages = %+v, want none: the failed turn left memory rows behind", msgs)
	}
}

func TestSessionRowMethodsOnANilStoreReportUnavailable(t *testing.T) {
	ctx := context.Background()
	var s *Store

	// OpenDefault returns nil rather than an error, so a caller can reach these
	// on a nil store.
	if err := s.UpsertSessionRow(ctx, SessionRow{ID: "s1"}); err == nil {
		t.Error("UpsertSessionRow on a nil store returned no error")
	}
	if _, _, err := s.GetSessionRow(ctx, "s1"); err == nil {
		t.Error("GetSessionRow on a nil store returned no error")
	}
	if _, err := s.SessionRows(ctx); err == nil {
		t.Error("SessionRows on a nil store returned no error")
	}
	if err := s.DeleteSessionRow(ctx, "s1"); err == nil {
		t.Error("DeleteSessionRow on a nil store returned no error")
	}
	if err := s.DeleteAllSessionRows(ctx); err == nil {
		t.Error("DeleteAllSessionRows on a nil store returned no error")
	}
	if err := s.ImportSessionRows(ctx, nil); err == nil {
		t.Error("ImportSessionRows on a nil store returned no error")
	}
	if err := s.CommitTurn(ctx, "q", "a", SessionRow{ID: "s1"}); err == nil {
		t.Error("CommitTurn on a nil store returned no error")
	}
}
