package main

import (
	"context"

	"blkchain/cli/internal/histstore"
)

// histpicker.go adapts the langchaingo history store to the /history picker,
// which reuses the resume picker UI. mergeHistoryMetas turns the store's
// session list into the sessionMeta rows the picker renders, borrowing titles
// from the JSONL index (session.go) by id so /history shows the same friendly
// names as /resume; a session with no indexed title falls back to its id.

func mergeHistoryMetas(hs []histstore.SessionMeta, details map[string]sessionMeta) []sessionMeta {
	out := make([]sessionMeta, 0, len(hs))
	for _, h := range hs {
		meta := details[h.ID]
		meta.ID, meta.MsgCount = h.ID, h.Count
		if meta.Title == "" {
			meta.Title = h.ID
		}
		out = append(out, meta)
	}
	return out
}

// purgeHistorySession erases one session from both stores: its langchaingo rows
// (blk_sessions) and its JSONL transcript. Best-effort on each side.
func purgeHistorySession(h *histstore.Store, id string) {
	if h != nil {
		_ = h.EraseSession(context.Background(), id)
	}
	_ = deleteSession(id)
}

// purgeAllHistory erases every session from both stores.
func purgeAllHistory(h *histstore.Store) {
	if h != nil {
		_ = h.EraseAll(context.Background())
	}
	_ = deleteAllSessions()
}
