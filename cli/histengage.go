package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"blkchain/cli/internal/engreport"
	"blkchain/cli/internal/histstore"
)

// histengage.go bridges the blk engage report into the REPL history store. After
// an engagement writes report.json, ingestEngageReport folds a compact summary
// of it into the session's memory as one assistant turn, so /history replays the
// engagement outcome alongside the conversation.

// summarizeEngageReport renders a one-message digest of an engagement report:
// the goal, the run status, and each task with its status and objective. It is
// pure so it can be unit tested against a hand-built model.
func summarizeEngageReport(m engreport.Model) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Engagement report [%s]\n", m.Status)
	fmt.Fprintf(&b, "Goal: %s\n", m.Goal)
	tasks := m.Engagement.Tasks
	fmt.Fprintf(&b, "Tasks (%d):", len(tasks))
	for _, t := range tasks {
		fmt.Fprintf(&b, "\n- %s %s [%s]: %s", t.ID, t.Kind, t.Status, t.Objective)
	}
	return b.String()
}

// ingestEngageReport reads report.json at path and stores its summary as one
// assistant turn under session. A missing or malformed report is an error.
func ingestEngageReport(ctx context.Context, store *histstore.Store, session, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m engreport.Model
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parse engage report %s: %w", path, err)
	}
	return store.AppendAI(ctx, session, summarizeEngageReport(m))
}

// engageHistorySessionID is the stable history session id for one engagement
// workspace. The workspace basename is timestamped and unique (engagecmd.go), so
// it identifies the run without leaking any goal text into the id.
func engageHistorySessionID(wsDir string) string {
	return "engage-" + filepath.Base(wsDir)
}

// ingestEngageRun folds a finished engagement's report.json into the default
// history store so /history can reopen the run. It is best-effort: when no store
// can be opened it does nothing, so a memory problem never fails the engagement.
func ingestEngageRun(wsDir string) error {
	store := histstore.OpenDefault()
	if store == nil {
		return nil
	}
	defer store.Close()
	_, jsonPath := reportPaths(wsDir)
	return ingestEngageReport(context.Background(), store, engageHistorySessionID(wsDir), jsonPath)
}
