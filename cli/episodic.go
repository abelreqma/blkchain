package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/histstore"
)

// episode is one recorded "what worked" moment, keyed loosely on the service
// product so recall can match a later service by case-insensitive product text
// (not by the brittle task-id format). Product is stored lowercased.
type episode struct {
	Kind       string // "vantage-advance" | "correlate"
	Engagement string // the engagement name the episode was observed in
	Outcome    string // for vantage-advance, the vantage reached; "" otherwise
	Product    string // lowercased product/service text, for recall matching
	Technique  string // the candidate task objective / technique label
	Target     string // the task target (host:port), for context
	TaskID     string // the engagement task the episode is attributed to
	Citation   engagement.Citation
	Rev        int64 // engagement revision at which it was observed
}

// episodicStore owns the blk_episodic table on the shared history database. The
// handle is shared and WAL is on, so concurrent listener writes are safe.
type episodicStore struct {
	db *sql.DB
}

const episodicSchema = `
CREATE TABLE IF NOT EXISTS blk_episodic (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	kind TEXT NOT NULL,
	engagement TEXT NOT NULL,
	outcome TEXT NOT NULL,
	product TEXT NOT NULL,
	technique TEXT NOT NULL,
	target TEXT NOT NULL,
	task_id TEXT NOT NULL,
	citation TEXT NOT NULL,
	rev INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS blk_episodic_product ON blk_episodic (product);
`

// newEpisodicStore ensures the blk_episodic table exists on db and returns a
// store over it.
func newEpisodicStore(db *sql.DB) (*episodicStore, error) {
	if _, err := db.Exec(episodicSchema); err != nil {
		return nil, err
	}
	return &episodicStore{db: db}, nil
}

// record inserts one episode. Product is normalized (lowercased, trimmed) so
// recall can match case-insensitively; the citation is stored as JSON.
func (es *episodicStore) record(ctx context.Context, ep episode) error {
	cit, err := json.Marshal(ep.Citation)
	if err != nil {
		return err
	}
	_, err = es.db.ExecContext(ctx,
		`INSERT INTO blk_episodic (kind, engagement, outcome, product, technique, target, task_id, citation, rev)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ep.Kind, ep.Engagement, ep.Outcome, strings.ToLower(strings.TrimSpace(ep.Product)),
		ep.Technique, ep.Target, ep.TaskID, string(cit), ep.Rev,
	)
	return err
}

// hintFor returns advisory "what worked" lines for a service, newest first,
// bounded to maxEpisodeHints. Each line is reference-only prose naming the
// technique and either the vantage it reached or that it was a prior candidate;
// it is never a command and the selector never executes it. An error yields no
// lines (the hint degrades silently).
func (es *episodicStore) hintFor(ctx context.Context, svc Service) []string {
	eps, err := es.priorFor(ctx, svc.Product, maxEpisodeHints)
	if err != nil {
		return nil
	}
	var out []string
	for _, ep := range eps {
		tech := strings.TrimSpace(ep.Technique)
		if tech == "" {
			tech = "a prior technique"
		}
		eng := strings.TrimSpace(ep.Engagement)
		switch ep.Kind {
		case "vantage-advance":
			line := tech + " previously reached vantage " + ep.Outcome
			if eng != "" {
				line += " (engagement " + eng + ")"
			}
			out = append(out, line)
		default:
			line := tech + " was a prior candidate for this service"
			if eng != "" {
				line += " (engagement " + eng + ")"
			}
			out = append(out, line)
		}
	}
	return out
}

// activateEpisodicMemory opens the shared history database, creates the episodic
// store, installs the read-hint, and returns the AddOnApply listener to attach
// plus a cleanup that clears the hint and closes the handle. It degrades to a
// no-op (nil listener, no-op cleanup) when the history database cannot be opened,
// so an engagement runs unaffected without episodic memory.
//
// Production calls this through the lazy wrapper registered in init()
// (registerOnApply(prodEpisodic.onApply)), so activation defers to the first
// engagement apply. Tests exercise this function and the listener directly.
func activateEpisodicMemory() (listener func(rev int64, e engagement.Engagement), cleanup func()) {
	hs := histstore.OpenDefault()
	if hs == nil {
		return nil, func() {}
	}
	es, err := newEpisodicStore(hs.DB())
	if err != nil {
		hs.Close()
		return nil, func() {}
	}
	priorEpisodeHint = func(svc Service) []string { return es.hintFor(context.Background(), svc) }
	return newEpisodicApplyListener(es), func() {
		priorEpisodeHint = nil
		hs.Close()
	}
}

// lazyEpisodic defers activation until the first committed apply, so non-engage
// commands pay nothing and the history database opens only when an engagement
// actually runs. activate runs at most once; its listener is then reused, and
// the read-hint it installs persists for the process so recall spans
// engagements. activate is a field so a test can supply its own.
type lazyEpisodic struct {
	once     sync.Once
	activate func() (listener func(rev int64, e engagement.Engagement), cleanup func())
	delegate func(rev int64, e engagement.Engagement)
}

func (le *lazyEpisodic) onApply(rev int64, e engagement.Engagement) {
	le.once.Do(func() { le.delegate, _ = le.activate() })
	if le.delegate != nil {
		le.delegate(rev, e)
	}
}

// prodEpisodic is the process-wide episodic memory, registered below as a
// multi-flow store listener via the foundation registerOnApply seam. It is the
// single production wiring line; everything else lives behind it.
var prodEpisodic = &lazyEpisodic{activate: activateEpisodicMemory}

func init() { registerOnApply(prodEpisodic.onApply) }

// episodicListener observes committed engagement snapshots and writes a "what
// worked" episode on two transitions: a newly correlated exploit candidate task,
// and a vantage advance. It holds the minimal state needed to tell a transition
// from pre-existing state, guarded by a mutex because AddOnApply listeners may
// fire from multiple goroutines and out of order.
type episodicListener struct {
	es *episodicStore

	mu          sync.Mutex
	initialized bool
	maxRev      int64              // highest revision seen, for out-of-order vantage handling
	lastVantage engagement.Vantage // vantage at the highest revision seen
	seen        map[string]bool    // exploit-kind task ids already observed
}

// newEpisodicApplyListener returns an AddOnApply callback that records episodes
// into es. It is best-effort: a write error is swallowed (episodic memory
// degrades rather than disrupting the engagement), and it never mutates the
// engagement store.
func newEpisodicApplyListener(es *episodicStore) func(rev int64, e engagement.Engagement) {
	l := &episodicListener{es: es, seen: map[string]bool{}}
	return l.onApply
}

func (l *episodicListener) onApply(rev int64, e engagement.Engagement) {
	ctx := context.Background()
	l.mu.Lock()
	defer l.mu.Unlock()

	// The first snapshot is a baseline: pre-existing exploit tasks and an
	// already-set vantage are the starting state, not transitions to record.
	if !l.initialized {
		l.initialized = true
		l.maxRev = rev
		l.lastVantage = e.Vantage
		for _, t := range e.Tasks {
			if t.Kind == "exploit" {
				l.seen[t.ID] = true
			}
		}
		return
	}

	// Correlate: any exploit candidate task not seen before. Order-independent;
	// the seen set only grows, so an out-of-order snapshot cannot double-record.
	for _, t := range e.Tasks {
		if t.Kind != "exploit" || l.seen[t.ID] {
			continue
		}
		l.seen[t.ID] = true
		_ = l.es.record(ctx, episode{
			Kind:       "correlate",
			Engagement: e.Name,
			Product:    productFromTask(t),
			Technique:  t.Objective,
			Target:     t.Target,
			TaskID:     t.ID,
			Citation:   t.Citation,
			Rev:        rev,
		})
	}

	// Vantage advance: only act on the newest revision seen, so a late-arriving
	// stale snapshot never records a (monotonic) advance out of order.
	if rev > l.maxRev {
		l.maxRev = rev
		if e.Vantage != "" && e.Vantage != l.lastVantage {
			l.lastVantage = e.Vantage
			l.recordVantageAdvance(ctx, rev, e)
		}
	}
}

// recordVantageAdvance writes one vantage-advance episode per done exploit task,
// attributing the reached vantage to each technique that had succeeded. When no
// exploit task is done it still records the advance once (with empty product),
// so the ledger keeps every transition. Tasks are sorted by id for determinism.
func (l *episodicListener) recordVantageAdvance(ctx context.Context, rev int64, e engagement.Engagement) {
	var done []engagement.Task
	for _, t := range e.Tasks {
		if t.Kind == "exploit" && t.Status == engagement.StatusDone {
			done = append(done, t)
		}
	}
	sort.Slice(done, func(i, j int) bool { return done[i].ID < done[j].ID })
	if len(done) == 0 {
		_ = l.es.record(ctx, episode{Kind: "vantage-advance", Engagement: e.Name, Outcome: string(e.Vantage), Rev: rev})
		return
	}
	for _, t := range done {
		_ = l.es.record(ctx, episode{
			Kind:       "vantage-advance",
			Engagement: e.Name,
			Outcome:    string(e.Vantage),
			Product:    productFromTask(t),
			Technique:  t.Objective,
			Target:     t.Target,
			TaskID:     t.ID,
			Citation:   t.Citation,
			Rev:        rev,
		})
	}
}

// productFromTask extracts the product text an exploit task names, for recall
// keying. The deterministic catalog writes the objective as
// "<technique> against <product> <version>" (correlate.go), so the text after
// " against " is the product; a task without that shape yields "" (logged, but
// not product-recallable).
func productFromTask(t engagement.Task) string {
	const sep = " against "
	if i := strings.Index(t.Objective, sep); i >= 0 {
		return strings.TrimSpace(t.Objective[i+len(sep):])
	}
	return ""
}

// priorFor returns up to limit episodes whose stored product contains the given
// product text (case-insensitive), newest first. An empty or whitespace product,
// or a non-positive limit, yields no rows and no error.
func (es *episodicStore) priorFor(ctx context.Context, product string, limit int) ([]episode, error) {
	key := strings.ToLower(strings.TrimSpace(product))
	if key == "" || limit <= 0 {
		return nil, nil
	}
	rows, err := es.db.QueryContext(ctx,
		`SELECT kind, engagement, outcome, product, technique, target, task_id, citation, rev
		 FROM blk_episodic WHERE instr(product, ?) > 0 ORDER BY id DESC LIMIT ?`,
		key, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []episode
	for rows.Next() {
		var ep episode
		var cit string
		if err := rows.Scan(&ep.Kind, &ep.Engagement, &ep.Outcome, &ep.Product,
			&ep.Technique, &ep.Target, &ep.TaskID, &cit, &ep.Rev); err != nil {
			return nil, err
		}
		if cit != "" {
			_ = json.Unmarshal([]byte(cit), &ep.Citation)
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}
