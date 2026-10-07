package engagement

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"blkchain/cli/internal/webanalysis"
)

const findingSchema = `
CREATE TABLE IF NOT EXISTS finding_record (
	id TEXT PRIMARY KEY,
	surface TEXT NOT NULL,
	task_id TEXT NOT NULL,
	asset TEXT NOT NULL,
	title TEXT NOT NULL,
	status TEXT NOT NULL,
	severity TEXT NOT NULL,
	source TEXT NOT NULL,
	impact TEXT NOT NULL,
	confidence TEXT NOT NULL,
	detail TEXT NOT NULL,
	evidence_ids TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS finding_surface_status ON finding_record(surface, status);
CREATE INDEX IF NOT EXISTS finding_task ON finding_record(task_id);
CREATE TABLE IF NOT EXISTS finding_event (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	finding_id TEXT NOT NULL,
	status TEXT NOT NULL,
	actor TEXT NOT NULL,
	at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS finding_event_finding ON finding_event(finding_id,id);
`

type FindingStatus string

const (
	FindingLead      FindingStatus = "lead"
	FindingObserved  FindingStatus = "observed"
	FindingValidated FindingStatus = "validated"
	FindingDismissed FindingStatus = "dismissed"
)

func (s FindingStatus) valid() bool {
	switch s {
	case FindingLead, FindingObserved, FindingValidated, FindingDismissed:
		return true
	}
	return false
}

// Finding is a reviewable conclusion. EvidenceIDs refer to exact quote rows.
// Web detector records use a web: ID and remain leads until explicitly reviewed.
type Finding struct {
	ID          string        `json:"id"`
	Surface     Surface       `json:"surface"`
	TaskID      string        `json:"task_id,omitempty"`
	Asset       string        `json:"asset"`
	Title       string        `json:"title"`
	Status      FindingStatus `json:"status"`
	Severity    string        `json:"severity,omitempty"`
	Impact      string        `json:"impact,omitempty"`
	Confidence  string        `json:"confidence,omitempty"`
	Detail      string        `json:"detail,omitempty"`
	EvidenceIDs []int64       `json:"evidence_ids,omitempty"`
	Source      string        `json:"source"`
	CreatedAt   string        `json:"created_at,omitempty"`
	UpdatedAt   string        `json:"updated_at,omitempty"`
}

func boundedFindingText(s string, max int) bool {
	return s != "" && len(s) <= max && !strings.ContainsAny(s, "\x00\r")
}

func (s *Store) validateFinding(ctx context.Context, f Finding) error {
	if !f.Surface.valid() || !f.Status.valid() {
		return errors.New("invalid finding surface or status")
	}
	switch f.Severity {
	case "", "info", "low", "medium", "high", "critical":
	default:
		return errors.New("invalid finding severity")
	}
	if !boundedFindingText(f.Asset, 1024) || !boundedFindingText(f.Title, 512) || len(f.Detail) > 8192 || len(f.Impact) > 512 || len(f.Confidence) > 128 || len(f.EvidenceIDs) > 32 {
		return errors.New("invalid finding field length")
	}
	if f.TaskID == "" && len(f.EvidenceIDs) > 0 {
		return errors.New("evidence ids require a task")
	}
	if f.TaskID != "" {
		t, err := s.GetTask(f.TaskID)
		if err != nil {
			return fmt.Errorf("finding task: %w", err)
		}
		if t.Surface != f.Surface {
			return errors.New("finding surface differs from its task")
		}
	}
	for _, id := range f.EvidenceIDs {
		if id <= 0 {
			return errors.New("invalid evidence id")
		}
		var found int
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM evidence WHERE id=? AND task_id=?)`, id, f.TaskID).Scan(&found); err != nil {
			return err
		}
		if found == 0 {
			return fmt.Errorf("evidence %d does not belong to task %s", id, f.TaskID)
		}
	}
	if f.Status == FindingValidated && len(f.EvidenceIDs) == 0 {
		return errors.New("validated findings require exact evidence ids")
	}
	if len(f.EvidenceIDs) == 0 && !strings.HasPrefix(f.ID, "web:") {
		return errors.New("findings require exact evidence ids")
	}
	return nil
}

func (s *Store) SaveFinding(ctx context.Context, f Finding) (saved Finding, err error) {
	if f.ID == "" {
		var nonce [12]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return Finding{}, err
		}
		f.ID = "f:" + hex.EncodeToString(nonce[:])
	}
	if len(f.ID) > 80 || !boundedFindingText(f.ID, 80) {
		return Finding{}, errors.New("invalid finding id")
	}
	if f.Source == "" {
		f.Source = "operator"
	}
	if len(f.Source) > 64 {
		return Finding{}, errors.New("invalid finding source")
	}
	s.wmu.Lock()
	defer func() {
		s.wmu.Unlock()
		if err == nil {
			s.notifyFinding()
		}
	}()
	if err := s.validateFinding(ctx, f); err != nil {
		return Finding{}, err
	}
	if strings.HasPrefix(f.ID, "web:") {
		var found int
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM web_record WHERE kind='finding' AND id=?)`, strings.TrimPrefix(f.ID, "web:")).Scan(&found); err != nil {
			return Finding{}, err
		}
		if found == 0 {
			return Finding{}, errors.New("web finding source does not exist")
		}
	}
	ids, err := json.Marshal(f.EvidenceIDs)
	if err != nil {
		return Finding{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Finding{}, err
	}
	defer tx.Rollback()
	created := now
	var currentUpdated string
	err = tx.QueryRowContext(ctx, `SELECT created_at,updated_at FROM finding_record WHERE id=?`, f.ID).Scan(&created, &currentUpdated)
	existing := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Finding{}, err
	}
	if err == nil && (f.UpdatedAt == "" || f.UpdatedAt != currentUpdated) {
		return Finding{}, errors.New("finding changed since it was read; reload and review again")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO finding_record(id,surface,task_id,asset,title,status,severity,source,impact,confidence,detail,evidence_ids,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
		surface=excluded.surface,task_id=excluded.task_id,asset=excluded.asset,title=excluded.title,status=excluded.status,severity=excluded.severity,source=excluded.source,
		impact=excluded.impact,confidence=excluded.confidence,detail=excluded.detail,evidence_ids=excluded.evidence_ids,updated_at=excluded.updated_at`,
		f.ID, f.Surface, f.TaskID, f.Asset, f.Title, f.Status, f.Severity, f.Source, f.Impact, f.Confidence, f.Detail, string(ids), now, now)
	if err != nil {
		return Finding{}, err
	}
	actor := f.Source
	if existing || strings.HasPrefix(f.ID, "web:") {
		actor = "operator"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_event(finding_id,status,actor,at) VALUES(?,?,?,?)`, f.ID, f.Status, actor, now); err != nil {
		return Finding{}, err
	}
	if err := tx.Commit(); err != nil {
		return Finding{}, err
	}
	f.CreatedAt = created
	f.UpdatedAt = now
	return f, nil
}

func webFinding(id, task, at string, raw []byte) (Finding, error) {
	var w webanalysis.Finding
	if err := json.Unmarshal(raw, &w); err != nil {
		return Finding{}, err
	}
	title := w.Kind
	if w.Name != "" {
		title += ": " + w.Name
	}
	asset := w.SourceURL
	if asset == "" {
		asset = w.Location.Unit
	}
	if asset == "" {
		asset = "unknown web asset"
	}
	detail := webanalysis.RedactText(w.Preview)
	if w.Kind == "secret-candidate" {
		detail = "credential candidate in captured source"
	}
	return Finding{ID: "web:" + id, Surface: SurfaceWeb, TaskID: task, Asset: asset, Title: title,
		Status: FindingLead, Confidence: w.Confidence, Detail: detail, Source: "web-analysis", CreatedAt: at, UpdatedAt: at}, nil
}

// Findings reads the SQLite finding records and web analysis leads together.
// Reviewed web rows override their detector projection without copying secrets.
func (s *Store) Findings(ctx context.Context, surface Surface) ([]Finding, error) {
	if surface != "" && !surface.valid() {
		return nil, errors.New("invalid surface")
	}
	records, err := s.findingRecords(ctx, 100001)
	if err != nil {
		return nil, err
	}
	findings := map[string]Finding{}
	for _, finding := range records {
		findings[finding.ID] = finding
	}
	var rows *sql.Rows
	if len(findings) > 100000 {
		return nil, errors.New("finding limit exceeded")
	}
	if surface == "" || surface == SurfaceWeb {
		rows, err = s.db.QueryContext(ctx, `SELECT id,task_id,document,at FROM web_record WHERE kind='finding' ORDER BY id LIMIT ?`, webanalysis.MaxRecords+1)
		if err != nil {
			return nil, err
		}
		count := 0
		for rows.Next() {
			count++
			if count > webanalysis.MaxRecords {
				rows.Close()
				return nil, errors.New("web finding limit exceeded")
			}
			var id, task, doc, at string
			if err := rows.Scan(&id, &task, &doc, &at); err != nil {
				rows.Close()
				return nil, err
			}
			if _, reviewed := findings["web:"+id]; reviewed {
				continue
			}
			f, err := webFinding(id, task, at, []byte(doc))
			if err != nil {
				rows.Close()
				return nil, err
			}
			findings[f.ID] = f
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if surface == "" || f.Surface == surface {
			out = append(out, f)
		}
	}
	sortFindings(out)
	return out, nil
}

func sortFindings(fs []Finding) {
	times := make(map[string]time.Time, len(fs))
	for _, f := range fs {
		times[f.ID], _ = time.Parse(time.RFC3339Nano, f.CreatedAt)
	}
	sort.Slice(fs, func(i, j int) bool {
		if !times[fs[i].ID].Equal(times[fs[j].ID]) {
			return times[fs[i].ID].Before(times[fs[j].ID])
		}
		return fs[i].ID < fs[j].ID
	})
}

func (s *Store) Finding(ctx context.Context, id string) (Finding, error) {
	fs, err := s.Findings(ctx, "")
	if err != nil {
		return Finding{}, err
	}
	for _, f := range fs {
		if f.ID == id {
			return f, nil
		}
	}
	return Finding{}, sql.ErrNoRows
}

func (s *Store) findingRecords(ctx context.Context, limit int) ([]Finding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,surface,task_id,asset,title,status,severity,source,impact,confidence,detail,evidence_ids,created_at,updated_at FROM finding_record ORDER BY created_at,id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []Finding{}
	for rows.Next() {
		var finding Finding
		var ids string
		if err := rows.Scan(&finding.ID, &finding.Surface, &finding.TaskID, &finding.Asset, &finding.Title, &finding.Status, &finding.Severity, &finding.Source, &finding.Impact, &finding.Confidence, &finding.Detail, &ids, &finding.CreatedAt, &finding.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(ids), &finding.EvidenceIDs); err != nil {
			return nil, err
		}
		records = append(records, finding)
	}
	return records, rows.Err()
}

// ReportFindings returns bounded persisted conclusions and flags omitted records.
func (s *Store) ReportFindings(ctx context.Context, limit int) ([]Finding, bool, error) {
	if limit < 1 || limit > 1000 {
		return nil, false, errors.New("invalid report finding limit")
	}
	findings, err := s.findingRecords(ctx, limit+1)
	if err != nil {
		return nil, false, err
	}
	partial := len(findings) > limit
	if partial {
		findings = findings[:limit]
	}
	return findings, partial, nil
}

// AddOnFinding observes committed finding changes outside the store write lock.
func (s *Store) AddOnFinding(fn func()) func() {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	if s.findingListeners == nil {
		s.findingListeners = map[int]func(){}
	}
	id := s.nextID
	s.nextID++
	s.findingListeners[id] = fn
	return func() {
		s.lmu.Lock()
		delete(s.findingListeners, id)
		s.lmu.Unlock()
	}
}

func (s *Store) notifyFinding() {
	s.lmu.Lock()
	listeners := make([]func(), 0, len(s.findingListeners))
	for _, fn := range s.findingListeners {
		listeners = append(listeners, fn)
	}
	s.lmu.Unlock()
	for _, fn := range listeners {
		fn()
	}
}
