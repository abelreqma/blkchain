package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"blkchain/cli/internal/histstore"
)

func (m *model) resetConversation() error {
	if m.working {
		return fmt.Errorf("cancel the current turn before starting fresh")
	}
	s, err := newSession()
	if err != nil {
		return err
	}
	m.sess, m.sessTitle = s, "new session"
	m.agentSession = ""
	m.lastAnswer, m.pendingQ, m.lastQuery = "", "", ""
	m.lastResults, m.openTargets, m.attachments, m.queue = nil, nil, nil, nil
	m.lastCostSet = false
	m.queuePaused = false
	m.ta.Reset()
	m.draftTruncated, m.draftTop, m.draftVertical = false, 0, false
	m.ta.SetHeight(1)
	m.pal = palette{}
	return nil
}

func (m *model) undoConversation() error {
	if m.working {
		return fmt.Errorf("cancel the current turn before undoing")
	}
	if m.sess == nil {
		return fmt.Errorf("no active session")
	}
	saved := *m.sess
	var size int64
	fi, err := os.Stat(m.sess.filePath())
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if exists {
		size = fi.Size()
		if m.hist != nil {
			replay, readErr := loadMessages(m.sess.id)
			if readErr != nil {
				return readErr
			}
			memory, readErr := m.hist.Messages(context.Background(), m.sess.id)
			if readErr != nil {
				return readErr
			}
			if len(replay) != len(memory) {
				return fmt.Errorf("undo: saved transcript and answer memory differ; start a fresh session with /clear")
			}
			for i, turn := range replay {
				role := histstore.RoleUser
				if turn.Role == roleAssistant {
					role = histstore.RoleAI
				}
				if (turn.Role != roleUser && turn.Role != roleAssistant) || memory[i].Role != role || memory[i].Content != turn.Content {
					return fmt.Errorf("undo: saved transcript and answer memory differ; start a fresh session with /clear")
				}
			}
		}
	}
	wrote := false
	update := func() error {
		if !exists && m.hist != nil {
			return nil
		}
		wrote = true
		return m.sess.appendTurn(turnRecord{Role: roleTombstone, Mode: m.mode})
	}
	if m.hist != nil {
		var changed bool
		changed, err = m.hist.UndoLastExchange(context.Background(), m.sess.id, update)
		if err == nil && !changed {
			return fmt.Errorf("no completed exchange to undo")
		}
	} else {
		if m.sess.count < 2 {
			return fmt.Errorf("no completed exchange to undo")
		}
		err = update()
	}
	if err != nil {
		if wrote {
			*m.sess = saved
			err = errors.Join(err, os.Truncate(m.sess.filePath(), size), m.sess.syncIndex())
		}
		return err
	}
	m.lastAnswer, m.lastQuery = "", ""
	m.openTargets, m.lastResults = nil, nil
	m.lastCostSet = false
	return nil
}
