package main

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"blkchain/cli/internal/engagement"
)

func TestEngageEvidenceBounded(t *testing.T) {
	t.Cleanup(func() { SetEngageEvidenceSource(nil) })
	big := strings.Repeat("A", maxEvidenceQuoteBytes+500)
	rows := make([]engagement.EvidenceRow, maxEvidenceRows+10)
	for i := range rows {
		rows[i] = engagement.EvidenceRow{ID: int64(i + 1), Quote: "q"}
	}
	rows[0].Quote = big
	SetEngageEvidenceSource(func(taskID string) ([]engagement.EvidenceRow, error) {
		if taskID != "t1" {
			t.Errorf("accessor got taskID %q, want t1", taskID)
		}
		return rows, nil
	})
	got, capped := EngageEvidence("t1")
	if len(got) != maxEvidenceRows {
		t.Fatalf("rows = %d, want capped to %d", len(got), maxEvidenceRows)
	}
	if !capped {
		t.Fatal("capped = false, want true (rows dropped and a quote truncated)")
	}
	if len(got[0].Quote) > maxEvidenceQuoteBytes {
		t.Fatalf("quote len = %d, want <= %d", len(got[0].Quote), maxEvidenceQuoteBytes)
	}
	if !got[0].Truncated {
		t.Fatal("oversized quote row not marked Truncated")
	}
}

func TestEngageEvidenceNoSource(t *testing.T) {
	SetEngageEvidenceSource(nil)
	if got, capped := EngageEvidence("t1"); got != nil || capped {
		t.Fatalf("no source must return (nil,false), got (%v,%v)", got, capped)
	}
}

func TestEngageEvidenceSourceError(t *testing.T) {
	t.Cleanup(func() { SetEngageEvidenceSource(nil) })
	SetEngageEvidenceSource(func(string) ([]engagement.EvidenceRow, error) {
		return nil, errors.New("boom")
	})
	if got, capped := EngageEvidence("t1"); got != nil || capped {
		t.Fatalf("source error must return (nil,false), got (%v,%v)", got, capped)
	}
}

func TestCapQuoteRuneSafe(t *testing.T) {
	// 'e'*10 then 'e-acute' (2 bytes each) *10; a cut at 15 bytes lands mid-rune.
	s := strings.Repeat("e", 10) + strings.Repeat("é", 10)
	q, truncated := capQuote(s, 15)
	if !truncated {
		t.Fatal("expected truncation")
	}
	if !utf8.ValidString(q) {
		t.Fatalf("capQuote split a rune: %q", q)
	}
	if len(q) > 15 {
		t.Fatalf("capQuote returned %d bytes, want <= 15", len(q))
	}
	if q2, tr := capQuote("short", 100); tr || q2 != "short" {
		t.Fatalf("capQuote under cap = (%q,%v), want (short,false)", q2, tr)
	}
}
