package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"blkchain/cli/internal/histstore"
	"blkchain/cli/internal/retrieval"
)

// plainAgentTurn runs one plain-REPL agent turn through the transport wiring the
// TUI uses: the hermes gateway when it is reachable, else the hermes subprocess.
// Tool activity and commentary print as they arrive, while the answer deltas are
// accumulated so the finished turn can be printed and returned for persistence.
// The one-shot `hermes -z` path this replaces streamed the child's stdout
// straight to the terminal and returned only an error, so the answer was never
// captured and the turn reached neither the transcript nor the history store.
func plainAgentTurn(ctx context.Context, m *model, message string) (string, error) {
	started := time.Now()
	var full strings.Builder
	var tokens int
	onEvent := func(ev agentEvent) {
		switch ev.kind {
		case agentText:
			full.WriteString(ev.text)
		case agentCommentary:
			fmt.Println(plainAgentNote(oneLine(ev.text)))
		case agentToolActivity:
			fmt.Println(plainAgentNote(sanitizeTerminal(ev.tool) + " " + sanitizeTerminal(ev.text)))
		case agentModelInfo:
			if strings.TrimSpace(ev.text) != "" {
				m.agentModel = ev.text
			}
		case agentTerminal:
			// The terminal final text is the answer only when nothing streamed.
			if ev.text != "" && full.Len() == 0 {
				full.WriteString(ev.text)
			}
			if ev.tokens > 0 {
				tokens = ev.tokens
			}
		}
	}
	err := streamPlainAgent(ctx, m, message, onEvent)
	answer := full.String()
	if strings.TrimSpace(answer) == "" {
		if err != nil && errors.Is(err, errHermesMissing) {
			return "", errors.New("agent mode unavailable: run `hermes gateway`, or install the hermes CLI")
		}
		return "", err
	}
	cost := turnCost{elapsed: time.Since(started), completionTokens: tokens}
	fmt.Println(formatAgentAnswer(answer, cost.elapsed, terminalWidth()))
	fmt.Println(costFooter(cost))
	m.lastCost, m.lastCostSet = cost, true
	return answer, err
}

// plainAgentNote is the muted progress line for tool activity and commentary.
func plainAgentNote(text string) string {
	return "   " + Meta.Render(Glyph(GlyphBullet)+" "+text)
}

// streamPlainAgent picks the transport for one plain-REPL agent turn and caches
// the gateway conversation handle on m, so the next turn continues the same
// conversation. The handle is cached before the stream runs, matching the TUI,
// so a turn that fails part-way does not orphan the conversation it created.
func streamPlainAgent(ctx context.Context, m *model, message string, onEvent func(agentEvent)) error {
	if hermesAvailable(ctx) {
		id := m.agentSession
		if id == "" {
			created, err := ensureSession(ctx)
			if err != nil {
				fmt.Println(plainAgentNote("gateway session failed, using hermes subprocess"))
				return StreamAgentSubprocess(ctx, message, onEvent)
			}
			id = created
		}
		m.agentSession = id
		return StreamAgent(ctx, id, message, m.agentModel, m.reasoning, onEvent)
	}
	return StreamAgentSubprocess(ctx, message, onEvent)
}

func plainSlashError(cmd string) error {
	name := strings.ToLower(strings.TrimPrefix(cmd, "/"))
	if _, ok := slashCommand(name); ok {
		return fmt.Errorf("/%s requires the interactive TUI; run blk in a terminal", name)
	}
	return fmt.Errorf("unknown command /%s, try /help", name)
}

// plainAsk answers one plain-REPL turn, printing it and returning the answer so
// the caller can persist it. m carries the conversation state an agent turn
// reads and updates (the gateway handle and the model the agent reported).
func plainAsk(m *model, mode, query string, c *replClient, history []priorTurn, preface string, force bool) (string, error) {
	c.metrics = &callMetrics{}
	c.started = time.Now()
	first, rest := splitFirst(query)
	webOnly := first == "--web"
	if webOnly {
		query = rest
	}
	if mode == "agent" && !force && !webOnly {
		if preface != "" {
			query = preface + "\n\n" + query
		}
		return plainAgentTurn(context.Background(), m, query)
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
	args = append([]string{"--agent", c.agent}, args...)
	return askWithPreface(rc, history, args, preface, c.metrics)
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
		titles := make(map[string]sessionMeta, len(metas))
		for _, s := range metas {
			titles[s.ID] = s
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
		recs, readErr := loadMessages(id)
		if readErr != nil {
			return before, readErr
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
	dropped := m.reconcileConversationContext(true)
	for _, r := range turns {
		if r.Role == histstore.RoleUser {
			fmt.Println(promptEcho(r.Content))
		} else if r.Role == histstore.RoleAI {
			fmt.Println(formatReplayAnswer(r.Content, terminalWidth()))
			m.lastAnswer = r.Content
		}
	}
	if note := reconciledNote(dropped); note != "" {
		fmt.Println(note)
	}
	return turns, nil
}
