package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"blkchain/cli/internal/histstore"
	"blkchain/cli/internal/retrieval"
)

func plainSlashError(cmd string) error {
	name := strings.ToLower(strings.TrimPrefix(cmd, "/"))
	if _, ok := slashCommand(name); ok {
		return fmt.Errorf("/%s requires the interactive TUI; run blk in a terminal", name)
	}
	return fmt.Errorf("unknown command /%s, try /help", name)
}

func plainAsk(mode, query string, c *replClient, history []priorTurn, preface string, force bool) (string, error) {
	first, rest := splitFirst(query)
	webOnly := first == "--web"
	if webOnly {
		query = rest
	}
	if mode == "agent" && !force && !webOnly {
		return "", runHermes([]string{query})
	}
	var rc *retrieval.Client
	var err error
	if !webOnly {
		rc, err = c.get()
		if err != nil {
			return "", err
		}
	}
	args := []string{query}
	if force {
		args = []string{"--rag", query}
	}
	if webOnly {
		args = []string{"--web", query}
	}
	return askWithPreface(rc, history, args, preface)
}

func plainEditor(before string) (string, error) {
	c, path, err := prepareDraftEditor(before)
	if err != nil {
		return before, fmt.Errorf("editor: %w", err)
	}
	defer os.Remove(path)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return before, fmt.Errorf("editor: %w", err)
	}
	text, err := readEditedDraft(path)
	if err != nil {
		return before, fmt.Errorf("editor: %w", err)
	}
	if strings.TrimSpace(text) == "" || text == strings.TrimRight(before, "\n") {
		fmt.Println(Meta.Render("edit cancelled"))
		return before, nil
	}
	text, cut := boundedDraftText(text, inputCharLimit)
	if cut {
		fmt.Println(Meta.Render("draft truncated at the input limit"))
	}
	fmt.Println(wrapIndent(text, 0, terminalWidth()))
	fmt.Println(Meta.Render("draft ready; Enter submits, /editor edits, /clear discards"))
	return text, nil
}

func plainHistory(m *model, arg string, before []priorTurn) ([]priorTurn, error) {
	if m.hist == nil {
		return before, fmt.Errorf("history: persistent memory is unavailable")
	}
	hs, err := m.hist.Sessions(context.Background())
	if err != nil {
		return before, fmt.Errorf("history: %w", err)
	}
	fields := strings.Fields(arg)
	clear := len(fields) > 0 && strings.EqualFold(fields[0], "clear")
	if clear {
		fields = fields[1:]
		if len(fields) == 0 {
			purgeAllHistory(m.hist)
			fmt.Printf("cleared all history (%d sessions)\n", len(hs))
			return before, nil
		}
	}
	if len(fields) == 0 {
		metas, _ := listSessions()
		titles := make(map[string]string, len(metas))
		for _, s := range metas {
			titles[s.ID] = s.Title
		}
		for i, h := range mergeHistoryMetas(hs, titles) {
			fmt.Printf("%d) %s (%d messages)\n", i+1, sanitizeTerminal(h.Title), h.MsgCount)
		}
		if len(hs) == 0 {
			fmt.Println(Meta.Render("no saved sessions"))
		} else {
			fmt.Println(Meta.Render("/history <number> reopens a session"))
		}
		return before, nil
	}
	n, err := strconv.Atoi(fields[0])
	if len(fields) != 1 || err != nil || n < 1 || n > len(hs) {
		return before, fmt.Errorf("history: give a session number from 1 to %d", len(hs))
	}
	id := hs[n-1].ID
	if clear {
		purgeHistorySession(m.hist, id)
		fmt.Printf("cleared session %d\n", n)
		return before, nil
	}
	var turns []priorTurn
	if sessionExists(id) {
		recs, err := loadMessages(id)
		if err != nil {
			return before, err
		}
		for _, r := range recs {
			switch r.Role {
			case roleUser:
				turns = append(turns, priorTurn{Role: histstore.RoleUser, Content: r.Content})
			case roleAssistant:
				turns = append(turns, priorTurn{Role: histstore.RoleAI, Content: r.Content})
			}
		}
		m.sess, err = openSession(id)
	} else {
		recs, e := m.hist.Messages(context.Background(), id)
		if e != nil {
			return before, e
		}
		for _, r := range recs {
			turns = append(turns, priorTurn{Role: r.Role, Content: r.Content})
		}
		m.sess, err = attachSession(id)
	}
	if err != nil {
		return before, err
	}
	m.lastAnswer = ""
	for _, r := range turns {
		if r.Role == histstore.RoleUser {
			fmt.Println(promptEcho(r.Content))
		} else if r.Role == histstore.RoleAI {
			fmt.Println(formatReplayAnswer(r.Content, terminalWidth()))
			m.lastAnswer = r.Content
		}
	}
	return turns, nil
}
