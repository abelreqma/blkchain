package engagement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// Record is one addressable item in an engagement. Its document is the stored
// value, not a model summary. File-backed web blobs remain referenced by hash.
type Record struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Surface  Surface         `json:"surface,omitempty"`
	TaskID   string          `json:"task_id,omitempty"`
	Document json.RawMessage `json:"document"`
}

type RecordPage struct {
	Kind    string   `json:"kind"`
	Surface Surface  `json:"surface,omitempty"`
	Offset  int      `json:"offset"`
	Limit   int      `json:"limit"`
	Total   int      `json:"total"`
	Records []Record `json:"records"`
}

var recordKinds = []string{"task", "finding", "finding-event", "evidence", "receipt", "coverage", "web", "action", "transition", "audit"}

func RecordKinds() []string { return append([]string(nil), recordKinds...) }

func pageSlice[T any](in []T, offset, limit int) []T {
	if offset >= len(in) {
		return []T{}
	}
	end := offset + limit
	if end > len(in) {
		end = len(in)
	}
	return in[offset:end]
}

func recordJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (s *Store) ActionCount(ctx context.Context, surface Surface) (int, error) {
	if surface != "" && surface != "unclassified" && !surface.valid() {
		return 0, errors.New("invalid surface")
	}
	query := `SELECT count(*) FROM action_record a LEFT JOIN task t ON t.id=a.task_id`
	args := []any{}
	if surface != "" {
		query += ` WHERE coalesce(nullif(t.surface,''),'unclassified')=?`
		args = append(args, string(surface))
	}
	var count int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

func (s *Store) Records(ctx context.Context, kind string, surface Surface, offset, limit int) (RecordPage, error) {
	p := RecordPage{Kind: kind, Surface: surface, Offset: offset, Limit: limit, Records: []Record{}}
	if limit < 1 || limit > 100 || offset < 0 || offset > 1000000 {
		return p, errors.New("record page limit must be 1-100 and offset must be non-negative")
	}
	if surface != "" && surface != "unclassified" && !surface.valid() {
		return p, errors.New("invalid surface")
	}
	if (kind == "audit" || kind == "transition") && surface != "" {
		return p, errors.New("audit and transition records are engagement-wide")
	}
	if kind == "web" && surface != "" && surface != SurfaceWeb {
		return p, nil
	}
	where := ""
	args := []any{}
	if surface != "" {
		where = " WHERE coalesce(nullif(t.surface,''),'unclassified') = ?"
		args = append(args, string(surface))
	}
	switch kind {
	case "task", "evidence", "receipt":
		table, alias, idExpr := "task", "t", "t.id"
		join := ""
		if kind == "evidence" {
			table, alias, idExpr, join = "evidence", "e", "e.id", " JOIN task t ON t.id=e.task_id"
		} else if kind == "receipt" {
			table, alias, idExpr, join = "receipt", "r", "r.id", " JOIN task t ON t.id=r.task_id"
		}
		base := " FROM " + table + " " + alias + join + where
		if err := s.db.QueryRowContext(ctx, "SELECT count(*)"+base, args...).Scan(&p.Total); err != nil {
			return p, err
		}
		rows, err := s.db.QueryContext(ctx, "SELECT "+idExpr+base+" ORDER BY "+idExpr+" LIMIT ? OFFSET ?", append(args, limit, offset)...)
		if err != nil {
			return p, err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return p, err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return p, err
		}
		for _, id := range ids {
			if kind == "task" {
				t, err := s.GetTask(id)
				if err != nil {
					return p, err
				}
				recordSurface := t.Surface
				if recordSurface == "" {
					recordSurface = "unclassified"
				}
				p.Records = append(p.Records, Record{ID: "task:" + id, Kind: kind, Surface: recordSurface, TaskID: id, Document: recordJSON(t)})
				continue
			}
			var task, at, taskSurface string
			if kind == "evidence" {
				var quote string
				if err := s.db.QueryRowContext(ctx, `SELECT e.task_id,e.quote,e.at,coalesce(nullif(t.surface,''),'unclassified') FROM evidence e JOIN task t ON t.id=e.task_id WHERE e.id=?`, id).Scan(&task, &quote, &at, &taskSurface); err != nil {
					return p, err
				}
				p.Records = append(p.Records, Record{ID: "evidence:" + id, Kind: kind, Surface: Surface(taskSurface), TaskID: task, Document: recordJSON(struct {
					Quote string `json:"quote"`
					At    string `json:"at"`
				}{quote, at})})
			} else {
				var skill, digest string
				var gen int64
				if err := s.db.QueryRowContext(ctx, `SELECT r.task_id,r.skill,r.bundle_digest,r.context_gen,r.at,coalesce(nullif(t.surface,''),'unclassified') FROM receipt r JOIN task t ON t.id=r.task_id WHERE r.id=?`, id).Scan(&task, &skill, &digest, &gen, &at, &taskSurface); err != nil {
					return p, err
				}
				p.Records = append(p.Records, Record{ID: "receipt:" + id, Kind: kind, Surface: Surface(taskSurface), TaskID: task, Document: recordJSON(Receipt{Skill: skill, BundleDigest: digest, ContextGen: gen, At: at})})
			}
		}
	case "finding":
		if surface == "unclassified" {
			return p, nil
		}
		fs, err := s.Findings(ctx, surface)
		if err != nil {
			return p, err
		}
		p.Total = len(fs)
		for _, f := range pageSlice(fs, offset, limit) {
			p.Records = append(p.Records, Record{ID: f.ID, Kind: kind, Surface: f.Surface, TaskID: f.TaskID, Document: recordJSON(f)})
		}
	case "finding-event":
		filter := ""
		args := []any{}
		if surface != "" {
			filter = " WHERE f.surface=?"
			args = append(args, string(surface))
		}
		base := " FROM finding_event e JOIN finding_record f ON f.id=e.finding_id" + filter
		if err := s.db.QueryRowContext(ctx, "SELECT count(*)"+base, args...).Scan(&p.Total); err != nil {
			return p, err
		}
		rows, err := s.db.QueryContext(ctx, "SELECT e.id,e.finding_id,e.status,e.actor,e.at,f.surface"+base+" ORDER BY e.id LIMIT ? OFFSET ?", append(args, limit, offset)...)
		if err != nil {
			return p, err
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			var findingID, status, actor, at, foundSurface string
			if err := rows.Scan(&id, &findingID, &status, &actor, &at, &foundSurface); err != nil {
				return p, err
			}
			p.Records = append(p.Records, Record{ID: fmt.Sprintf("finding-event:%d", id), Kind: kind, Surface: Surface(foundSurface), Document: recordJSON(map[string]string{"finding_id": findingID, "status": status, "actor": actor, "at": at})})
		}
		if err := rows.Err(); err != nil {
			return p, err
		}
	case "coverage":
		coverage, err := s.AllReconCoverage()
		if err != nil {
			return p, err
		}
		filtered := []ReconCoverage{}
		for _, c := range coverage {
			if surface == "" || c.Surface == surface {
				filtered = append(filtered, c)
			}
		}
		p.Total = len(filtered)
		for _, c := range pageSlice(filtered, offset, limit) {
			p.Records = append(p.Records, Record{ID: "coverage:" + string(c.Surface) + ":" + c.Asset, Kind: kind, Surface: c.Surface, Document: recordJSON(c)})
		}
	case "web":
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM web_record`).Scan(&p.Total); err != nil {
			return p, err
		}
		rows, err := s.db.QueryContext(ctx, `SELECT kind,id,task_id,document FROM web_record ORDER BY kind,id LIMIT ? OFFSET ?`, limit, offset)
		if err != nil {
			return p, err
		}
		defer rows.Close()
		for rows.Next() {
			var subkind, id, task, doc string
			if err := rows.Scan(&subkind, &id, &task, &doc); err != nil {
				return p, err
			}
			if !json.Valid([]byte(doc)) {
				return p, errors.New("stored web record is invalid JSON")
			}
			p.Records = append(p.Records, Record{ID: "web:" + subkind + ":" + id, Kind: "web-" + subkind, Surface: SurfaceWeb, TaskID: task, Document: json.RawMessage(doc)})
		}
		if err := rows.Err(); err != nil {
			return p, err
		}
	case "action":
		filter := ""
		args := []any{}
		if surface != "" {
			filter = " WHERE coalesce(nullif(t.surface,''),'unclassified')=?"
			args = append(args, string(surface))
		}
		base := " FROM action_record a LEFT JOIN task t ON t.id=a.task_id" + filter
		if err := s.db.QueryRowContext(ctx, "SELECT count(*)"+base, args...).Scan(&p.Total); err != nil {
			return p, err
		}
		rows, err := s.db.QueryContext(ctx, "SELECT a.id,a.task_id,a.document,coalesce(nullif(t.surface,''),'unclassified')"+base+" ORDER BY a.rowid LIMIT ? OFFSET ?", append(args, limit, offset)...)
		if err != nil {
			return p, err
		}
		defer rows.Close()
		for rows.Next() {
			var id, task, doc, actionSurface string
			if err := rows.Scan(&id, &task, &doc, &actionSurface); err != nil {
				return p, err
			}
			p.Records = append(p.Records, Record{ID: "action:" + id, Kind: kind, Surface: Surface(actionSurface), TaskID: task, Document: json.RawMessage(doc)})
		}
		if err := rows.Err(); err != nil {
			return p, err
		}
	case "audit", "transition":
		table, idExpr := "audit", "id"
		if kind == "transition" {
			table, idExpr = "transition", "rev"
		}
		if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&p.Total); err != nil {
			return p, err
		}
		rows, err := s.db.QueryContext(ctx, "SELECT "+idExpr+" FROM "+table+" ORDER BY "+idExpr+" LIMIT ? OFFSET ?", limit, offset)
		if err != nil {
			return p, err
		}
		var ids []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return p, err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return p, err
		}
		for _, id := range ids {
			var doc json.RawMessage
			if kind == "audit" {
				var at, actor, action, detail string
				if err := s.db.QueryRowContext(ctx, `SELECT at,actor,action,detail FROM audit WHERE id=?`, id).Scan(&at, &actor, &action, &detail); err != nil {
					return p, err
				}
				doc = recordJSON(map[string]string{"at": at, "actor": actor, "action": action, "detail": detail})
			} else {
				var at, transitionKind, detail string
				if err := s.db.QueryRowContext(ctx, `SELECT at,kind,detail FROM transition WHERE rev=?`, id).Scan(&at, &transitionKind, &detail); err != nil {
					return p, err
				}
				doc = recordJSON(map[string]string{"at": at, "kind": transitionKind, "detail": detail})
			}
			p.Records = append(p.Records, Record{ID: fmt.Sprintf("%s:%d", kind, id), Kind: kind, Document: doc})
		}
	default:
		return p, errors.New("unknown record kind")
	}
	totalBytes := 0
	for _, r := range p.Records {
		totalBytes += len(r.Document)
	}
	if totalBytes > 128<<20 {
		return RecordPage{}, errors.New("record page exceeds 128 MiB; reduce the limit")
	}
	return p, nil
}
