package engagement

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

const truncMarker = "...[truncated]"

func TestRecordEvidenceShortVerbatim(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)

	id, err := s.RecordEvidence("A", "HTTP/1.1 200 OK")
	if err != nil {
		t.Fatalf("RecordEvidence: %v", err)
	}
	if id <= 0 {
		t.Fatalf("id = %d, want > 0", id)
	}
	got, err := s.EvidenceFor("A")
	if err != nil {
		t.Fatalf("EvidenceFor: %v", err)
	}
	if len(got) != 1 || got[0] != "HTTP/1.1 200 OK" {
		t.Fatalf("EvidenceFor = %q", got)
	}
}

func TestEvidenceListenerRunsAfterWriteAndCanUseStore(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	calls := 0
	remove := s.AddOnEvidence(func() {
		quotes, err := s.EvidenceFor("A")
		if err != nil || len(quotes) != 1 || quotes[0] != "observed" {
			t.Errorf("listener saw quotes=%q err=%v", quotes, err)
		}
		calls++
	})
	if _, err := s.RecordEvidence("A", "observed"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("listener calls=%d", calls)
	}
	remove()
	if _, err := s.RecordEvidence("B", "other"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("removed listener calls=%d", calls)
	}
}

func TestRecordEvidenceOrderedByID(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)

	for _, q := range []string{"one", "two", "three"} {
		if _, err := s.RecordEvidence("A", q); err != nil {
			t.Fatalf("RecordEvidence %q: %v", q, err)
		}
	}
	if _, err := s.RecordEvidence("B", "other"); err != nil {
		t.Fatalf("RecordEvidence B: %v", err)
	}
	got, err := s.EvidenceFor("A")
	if err != nil {
		t.Fatalf("EvidenceFor: %v", err)
	}
	if strings.Join(got, ",") != "one,two,three" {
		t.Fatalf("EvidenceFor(A) = %q", got)
	}
}

func TestRecordEvidenceAtCapNotTruncated(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)

	q := strings.Repeat("a", EvidenceCap)
	if _, err := s.RecordEvidence("A", q); err != nil {
		t.Fatalf("RecordEvidence: %v", err)
	}
	got, _ := s.EvidenceFor("A")
	if len(got) != 1 || got[0] != q {
		t.Fatalf("quote at exactly the cap must be stored verbatim")
	}
}

func TestRecordEvidenceTruncatesLong(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)

	if _, err := s.RecordEvidence("A", strings.Repeat("a", EvidenceCap+500)); err != nil {
		t.Fatalf("RecordEvidence: %v", err)
	}
	got, _ := s.EvidenceFor("A")
	if len(got) != 1 {
		t.Fatalf("EvidenceFor = %d rows, want 1", len(got))
	}
	if n := utf8.RuneCountInString(got[0]); n > EvidenceCap+len([]rune(truncMarker)) {
		t.Fatalf("stored length %d runes exceeds cap+marker", n)
	}
	if !strings.HasSuffix(got[0], truncMarker) {
		t.Fatalf("stored value does not end with marker")
	}
	if !strings.HasPrefix(got[0], strings.Repeat("a", EvidenceCap)) {
		t.Fatalf("stored value lost the first %d runes", EvidenceCap)
	}
}

func TestRecordEvidenceMultibyteNotSplit(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)

	// 3-byte runes: a byte-based cut at 4000 would land mid-rune.
	q := strings.Repeat("日", EvidenceCap+10)
	if _, err := s.RecordEvidence("A", q); err != nil {
		t.Fatalf("RecordEvidence: %v", err)
	}
	got, _ := s.EvidenceFor("A")
	if len(got) != 1 {
		t.Fatalf("EvidenceFor = %d rows, want 1", len(got))
	}
	if !utf8.ValidString(got[0]) {
		t.Fatalf("stored value is not valid UTF-8")
	}
	want := strings.Repeat("日", EvidenceCap) + truncMarker
	if got[0] != want {
		t.Fatalf("multibyte truncation wrong: got %d runes", utf8.RuneCountInString(got[0]))
	}
}

func TestRecordEvidenceUnknownTask(t *testing.T) {
	s := openTemp(t)

	_, err := s.RecordEvidence("nope", "x")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if n := countRows(t, s, "SELECT COUNT(*) FROM evidence"); n != 0 {
		t.Fatalf("evidence rows = %d, want 0", n)
	}
}

func TestEvidenceRowsForReturnsIDsAndQuotes(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)

	for _, q := range []string{"first", "second"} {
		if _, err := s.RecordEvidence("A", q); err != nil {
			t.Fatalf("RecordEvidence %q: %v", q, err)
		}
	}
	rows, err := s.EvidenceRowsFor("A")
	if err != nil {
		t.Fatalf("EvidenceRowsFor: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("EvidenceRowsFor = %d rows, want 2", len(rows))
	}
	if rows[0].Quote != "first" || rows[1].Quote != "second" {
		t.Fatalf("quotes out of order: %q, %q", rows[0].Quote, rows[1].Quote)
	}
	if rows[0].ID <= 0 || rows[1].ID <= 0 {
		t.Fatalf("ids must be positive: %d, %d", rows[0].ID, rows[1].ID)
	}
	if rows[1].ID <= rows[0].ID {
		t.Fatalf("ids must be ascending: %d then %d", rows[0].ID, rows[1].ID)
	}
}

func TestEvidenceRowsForEmpty(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)

	rows, err := s.EvidenceRowsFor("A")
	if err != nil {
		t.Fatalf("EvidenceRowsFor: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("EvidenceRowsFor = %d rows, want 0", len(rows))
	}
}

func TestEvidenceForEmpty(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)

	got, err := s.EvidenceFor("A")
	if err != nil {
		t.Fatalf("EvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("EvidenceFor = %q, want empty", got)
	}
}
