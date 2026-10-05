package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"blkchain/cli/internal/askuser"
	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/skillcat"
)

// replengagecmd.go wires the REPL /engage command to the gate-governed engage
// entry (replengage.go runReplEngage). It builds the engage
// dependencies from the session, runs the orchestrator in a command goroutine,
// and bridges progress snapshots to the live engagement view so the existing viz
// DAG + bar render the run. The confirm overlay (engageconfirm.go) and the
// Safe-mode asker (engageask.go) are the human-in-the-loop surfaces.

// runReplEngageFn is the engage entry, injected in tests.
var runReplEngageFn = runReplEngage

// engageDoneMsg ends an /engage turn with the orchestrator's final answer or error.
type engageDoneMsg struct {
	final  string
	err    error
	paused bool
}

type engageStatusKey struct{}

type engageRunStatus struct{ paused bool }

// replEngageRun is the fully-built input to one gated REPL engagement. The deps
// (model, rc, cat, roeDB, confirm, cfg, prefs, mode, override, cwd, goal) are
// built on the UI goroutine by buildReplEngageRun; ctx, asker, and stub are set
// by the dispatch once the turn's context exists.
type replEngageRun struct {
	ctx      context.Context
	goal     string
	mode     secgate.Mode
	override bool
	cwd      string
	model    toolLoopModel
	rc       searcher
	cfg      ragconfig.Config
	prefs    modelPrefs
	cat      *skillcat.Catalog
	confirm  secgate.Confirmer
	asker    askuser.Asker
	roeDB    *sql.DB
	stub     *stubEngagement
}

// buildReplEngageRun assembles the engage dependencies from the session, failing
// before a turn starts (like blk engage) when the model, retrieval client, or
// skill catalog cannot be built. ctx, asker, and stub are filled in by the
// dispatch. confirm is the widget EditConfirmer; a nil program fails closed.
func (m model) buildReplEngageRun(goal string) (replEngageRun, error) {
	model, err := newOMLX(m.cfg, m.activeModel())
	if err != nil {
		return replEngageRun{}, fmt.Errorf("engage: %w", err)
	}
	rc, rcErr := m.retrievalClient()
	if rcErr != nil {
		return replEngageRun{}, fmt.Errorf("engage: %w", rcErr)
	}
	cat, err := loadEngageCatalog()
	if err != nil {
		return replEngageRun{}, fmt.Errorf("engage: %w", err)
	}
	var roeDB *sql.DB
	if m.hist != nil {
		roeDB = m.hist.DB()
	}
	cwd, _ := os.Getwd()
	return replEngageRun{
		goal:     goal,
		mode:     m.engageMode,
		override: m.engageOverride,
		cwd:      cwd,
		model:    model,
		rc:       rc,
		cfg:      m.cfg,
		prefs:    m.prefs,
		cat:      cat,
		confirm:  widgetConfirmer{prog: m.prog},
		roeDB:    roeDB,
	}, nil
}

// engageCmd runs the gated orchestrator for the run in a command goroutine. The
// progress callback advances the live engagement view (stub) once per revision,
// so the viz DAG + bar render it. The final result returns as an engageDoneMsg.
func engageCmd(r replEngageRun) tea.Cmd {
	return func() tea.Msg {
		status := &engageRunStatus{}
		ctx := context.WithValue(r.ctx, engageStatusKey{}, status)
		progress := func(rev int64, snap eng.Engagement) {
			if r.stub != nil {
				r.stub.setSnapshot(snap)
			}
		}
		final, err := runReplEngageFn(ctx, "", r.cwd, r.mode, r.override, r.model, r.rc,
			r.cfg, r.prefs, r.cat, r.confirm, r.asker, r.roeDB, r.goal, progress)
		return engageDoneMsg{final: final, err: err, paused: status.paused}
	}
}

// formatEngageDone renders the finished engagement: a done marker with the
// elapsed time, then the orchestrator's summary.
func formatEngageDone(final string, elapsed time.Duration, width int) string {
	return formatEngageResult(final, elapsed, width, false)
}

func formatEngagePaused(final string, elapsed time.Duration, width int) string {
	return formatEngageResult(final, elapsed, width, true)
}

func formatEngageError(final string, err error, width int) string {
	out := styleErr(err)
	if strings.TrimSpace(final) != "" {
		out += "\n" + strings.TrimRight(glowRender(final, width), "\n")
	}
	return out
}

func formatEngageResult(final string, elapsed time.Duration, width int, paused bool) string {
	var b strings.Builder
	marker, label := OK.Render(Glyph(GlyphOK)), "Engagement complete in "
	if paused {
		marker, label = Caut.Render(Glyph(GlyphWarn)), "Engagement paused after "
	}
	fmt.Fprintf(&b, " %s %s\n", marker,
		Meta.Render(label+elapsed.Round(100*time.Millisecond).String()))
	body := strings.TrimSpace(final)
	if body == "" {
		body = Meta.Render("(no summary)")
	} else {
		body = strings.TrimRight(glowRender(body, width), "\n")
	}
	b.WriteString(body)
	return strings.TrimRight(b.String(), "\n")
}
