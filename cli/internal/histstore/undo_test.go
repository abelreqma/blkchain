package histstore

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func appendExchange(t *testing.T, s *Store, session, q, a string) {
	t.Helper()
	ctx := context.Background()
	if err := s.AppendUser(ctx, session, q); err != nil {
		t.Fatalf("AppendUser: %v", err)
	}
	if err := s.AppendAI(ctx, session, a); err != nil {
		t.Fatalf("AppendAI: %v", err)
	}
}

func TestUndoRemovesOnlyTheLastExchange(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()
	appendExchange(t, s, "s1", "first q", "first a")
	appendExchange(t, s, "s1", "second q", "second a")

	ok, err := s.UndoLastExchange(ctx, "s1", SessionRow{}, func() (int64, error) { return 64, nil })
	if err != nil {
		t.Fatalf("UndoLastExchange: %v", err)
	}
	if !ok {
		t.Fatal("UndoLastExchange reported nothing to undo")
	}

	msgs, err := s.Messages(ctx, "s1")
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	want := []Turn{{Role: RoleUser, Content: "first q"}, {Role: RoleAI, Content: "first a"}}
	if len(msgs) != len(want) {
		t.Fatalf("messages = %+v, want %+v", msgs, want)
	}
	for i, w := range want {
		if msgs[i] != w {
			t.Errorf("msg[%d] = %+v, want %+v", i, msgs[i], w)
		}
	}
}

func TestUndoCommitsTheReportedTranscriptLength(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()
	appendExchange(t, s, "s1", "q", "a")

	// The reported length wins over meta.Watermark.
	meta := SessionRow{ID: "ignored", Title: "t", Watermark: watermark(9999)}
	if _, err := s.UndoLastExchange(ctx, "s1", meta, func() (int64, error) { return 128, nil }); err != nil {
		t.Fatalf("UndoLastExchange: %v", err)
	}

	row := getRow(t, s, "s1")
	if row.Watermark != watermark(128) {
		t.Errorf("Watermark = %+v, want 128", row.Watermark)
	}
	if row.MsgCount != 0 {
		t.Errorf("MsgCount = %d, want 0", row.MsgCount)
	}
}

func TestUndoLeavesTheWatermarkAloneWhenNoTranscriptWasWritten(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()
	appendExchange(t, s, "s1", "q", "a")

	if _, err := s.UndoLastExchange(ctx, "s1", SessionRow{}, func() (int64, error) { return 0, nil }); err != nil {
		t.Fatalf("UndoLastExchange: %v", err)
	}

	if got := getRow(t, s, "s1").Watermark; got.Valid {
		t.Errorf("Watermark = %+v, want unrecorded", got)
	}
}

func TestUndoOnAnEmptySessionReportsNothingToUndo(t *testing.T) {
	s := newTestHistStore(t)

	called := false
	ok, err := s.UndoLastExchange(context.Background(), "absent", SessionRow{}, func() (int64, error) {
		called = true
		return 10, nil
	})
	if err != nil {
		t.Fatalf("UndoLastExchange: %v", err)
	}
	if ok {
		t.Error("ok = true for a session with no messages")
	}
	if called {
		t.Error("updateTranscript ran for a session with no messages")
	}
}

func TestUndoRefusesAnIncompleteExchange(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()
	appendExchange(t, s, "s1", "q", "a")
	if err := s.AppendUser(ctx, "s1", "unanswered"); err != nil {
		t.Fatalf("AppendUser: %v", err)
	}

	ok, err := s.UndoLastExchange(ctx, "s1", SessionRow{}, func() (int64, error) { return 10, nil })
	if err == nil {
		t.Fatal("UndoLastExchange accepted an incomplete exchange")
	}
	if ok {
		t.Error("ok = true for an incomplete exchange")
	}

	msgs, err := s.Messages(ctx, "s1")
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 3 {
		t.Errorf("messages = %d, want the 3 originals left untouched", len(msgs))
	}
}

func TestUndoRollsBackWhenTheTranscriptUpdateFails(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()
	appendExchange(t, s, "s1", "q", "a")

	wantErr := errors.New("transcript write failed")
	ok, err := s.UndoLastExchange(ctx, "s1", SessionRow{}, func() (int64, error) { return 0, wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if ok {
		t.Error("ok = true after a failed transcript update")
	}

	msgs, err := s.Messages(ctx, "s1")
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 2 {
		t.Errorf("messages = %d, want the exchange still present", len(msgs))
	}
}

func TestUndoWithNoTranscriptCallbackStillRemovesTheExchange(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()
	appendExchange(t, s, "s1", "q", "a")

	ok, err := s.UndoLastExchange(ctx, "s1", SessionRow{}, nil)
	if err != nil {
		t.Fatalf("UndoLastExchange: %v", err)
	}
	if !ok {
		t.Fatal("UndoLastExchange reported nothing to undo")
	}

	msgs, err := s.Messages(ctx, "s1")
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("messages = %+v, want none", msgs)
	}
}

func TestLastQuestionReturnsTheMostRecentUserMessage(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()
	appendExchange(t, s, "s1", "first q", "first a")
	appendExchange(t, s, "s1", "second q", "second a")

	got, err := s.LastQuestion(ctx, "s1")
	if err != nil {
		t.Fatalf("LastQuestion: %v", err)
	}
	if got != "second q" {
		t.Errorf("LastQuestion = %q, want %q", got, "second q")
	}
}

func TestLastQuestionIsEmptyForAnUnknownSession(t *testing.T) {
	s := newTestHistStore(t)

	got, err := s.LastQuestion(context.Background(), "absent")
	if err != nil {
		t.Fatalf("LastQuestion: %v", err)
	}
	if got != "" {
		t.Errorf("LastQuestion = %q, want empty", got)
	}
}

func TestLastQuestionIsCappedForThePreview(t *testing.T) {
	s := newTestHistStore(t)
	ctx := context.Background()
	long := strings.Repeat("x", 2000)
	if err := s.AppendUser(ctx, "s1", long); err != nil {
		t.Fatalf("AppendUser: %v", err)
	}

	got, err := s.LastQuestion(ctx, "s1")
	if err != nil {
		t.Fatalf("LastQuestion: %v", err)
	}
	if len(got) != 1024 {
		t.Errorf("len(LastQuestion) = %d, want it capped at 1024", len(got))
	}
}
