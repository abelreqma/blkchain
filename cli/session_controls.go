package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"blkchain/cli/internal/histstore"
)

// reconcileConversationContext drops the in-memory state that does not follow
// m.sess and names what it dropped, so a caller can report it. The gateway
// conversation handle is the load-bearing one: a reopened or undone transcript
// no longer matches the server-side history that handle points at, so the next
// agent turn starts a new conversation rather than continuing one whose
// contents no longer match this session.
//
// switching is true when the session itself changes, which also invalidates the
// context staged for the conversation being left. An undo stays in the same
// session, where attachments and the queue are pending work rather than part of
// the removed exchange: a sent turn consumes its attachments, so anything
// staged at undo time was staged afterwards.
func (m *model) reconcileConversationContext(switching bool) []string {
	var dropped []string
	if m.agentSession != "" {
		m.agentSession = ""
		dropped = append(dropped, "agent conversation restarted")
	}
	m.lastAnswer, m.lastQuery = "", ""
	m.lastResults, m.openTargets = nil, nil
	m.lastCostSet = false
	if switching {
		if n := len(m.attachments); n > 0 {
			m.attachments = nil
			dropped = append(dropped, fmt.Sprintf("%d %s cleared", n, plural(n, "attachment")))
		}
		m.pendingQ = ""
		m.queue = nil
	}
	return dropped
}

// reconciledNote renders the muted line naming what reconcileConversationContext
// dropped, or "" when it dropped nothing worth saying.
func reconciledNote(dropped []string) string {
	if len(dropped) == 0 {
		return ""
	}
	return "   " + Meta.Render(Glyph(GlyphBullet)+" "+joinSep(dropped...))
}

func (m *model) resetConversation() error {
	if m.working {
		return fmt.Errorf("cancel the current turn before starting fresh")
	}
	s, err := newSession()
	if err != nil {
		return err
	}
	m.sess, m.sessTitle = s, "new session"
	m.reconcileConversationContext(true)
	m.queuePaused = false
	m.ta.Reset()
	m.draftTruncated, m.draftTop, m.draftVertical = false, 0, false
	m.ta.SetHeight(1)
	m.pal = palette{}
	return nil
}

func (m *model) undoConversation() error {
	_, err := m.undoConversationContext()
	return err
}

// undoConversationContext is undoConversation plus the reconciliation report:
// the state the removed exchange invalidated, named for the caller to print.
func (m *model) undoConversationContext() ([]string, error) {
	if m.working {
		return nil, fmt.Errorf("cancel the current turn before undoing")
	}
	if m.sess == nil {
		return nil, fmt.Errorf("no active session")
	}
	saved := *m.sess
	var size int64
	_, err := os.Stat(m.sess.filePath())
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if exists {
		// A turn interrupted between its transcript append and its commit left
		// a tail the memory rows do not account for. Reconciling removes it, so
		// the two stores agree here instead of the session refusing to undo for
		// the rest of its life. The size is read after that, since reconciling
		// is what decides it.
		if err := m.sess.reconcileTranscript(); err != nil {
			return nil, err
		}
		fi, err := os.Stat(m.sess.filePath())
		if err != nil {
			return nil, err
		}
		size = fi.Size()
		if m.hist != nil {
			replay, readErr := loadMessages(m.sess.id)
			if readErr != nil {
				return nil, readErr
			}
			memory, readErr := m.hist.Messages(context.Background(), m.sess.id)
			if readErr != nil {
				return nil, readErr
			}
			if len(replay) != len(memory) {
				return nil, fmt.Errorf("undo: saved transcript and answer memory differ; start a fresh session with /clear")
			}
			for i, turn := range replay {
				role := histstore.RoleUser
				if turn.Role == roleAssistant {
					role = histstore.RoleAI
				}
				if (turn.Role != roleUser && turn.Role != roleAssistant) || memory[i].Role != role || memory[i].Content != turn.Content {
					return nil, fmt.Errorf("undo: saved transcript and answer memory differ; start a fresh session with /clear")
				}
			}
		}
	}
	wrote := false
	// update appends the tombstone and reports the transcript's new length, which
	// UndoLastExchange commits as the watermark in the same transaction as the
	// row deletions, so the tombstone and the deletions land together.
	update := func() (int64, error) {
		if !exists && m.hist != nil {
			return 0, nil
		}
		wrote = true
		if err := m.sess.appendTombstone(turnRecord{Role: roleTombstone, Mode: m.mode}); err != nil {
			return 0, err
		}
		return m.sess.transcriptSize()
	}
	if m.hist != nil {
		var changed bool
		changed, err = m.hist.UndoLastExchange(context.Background(), m.sess.id, storeMeta(m.sess.meta()), update)
		if err == nil && !changed {
			return nil, fmt.Errorf("no completed exchange to undo")
		}
	} else {
		if m.sess.count < 2 {
			return nil, fmt.Errorf("no completed exchange to undo")
		}
		_, err = update()
	}
	if err != nil {
		if wrote {
			*m.sess = saved
			err = errors.Join(err, os.Truncate(m.sess.filePath(), size), m.sess.syncIndex())
		}
		return nil, err
	}
	return m.reconcileConversationContext(false), nil
}
