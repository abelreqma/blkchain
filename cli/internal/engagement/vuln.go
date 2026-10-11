package engagement

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const vulnSchema = `
CREATE TABLE IF NOT EXISTS vuln_record (
	id TEXT PRIMARY KEY,
	task_id TEXT NOT NULL,
	surface TEXT NOT NULL,
	asset TEXT NOT NULL,
	scanner TEXT NOT NULL,
	scanner_version TEXT NOT NULL,
	advisory TEXT NOT NULL,
	aliases TEXT NOT NULL,
	severity TEXT NOT NULL,
	cvss TEXT NOT NULL,
	package_name TEXT NOT NULL,
	package_version TEXT NOT NULL,
	ecosystem TEXT NOT NULL,
	fixed_version TEXT NOT NULL,
	summary TEXT NOT NULL,
	location TEXT NOT NULL,
	evidence_id INTEGER NOT NULL,
	scanned_at TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS vuln_advisory ON vuln_record(advisory);
CREATE INDEX IF NOT EXISTS vuln_asset ON vuln_record(asset, severity);
CREATE INDEX IF NOT EXISTS vuln_task ON vuln_record(task_id);
CREATE INDEX IF NOT EXISTS vuln_package ON vuln_record(ecosystem, package_name);
`

// Vuln is one advisory a scanner reported against one package at one asset, citing the scanner output it came from.
type Vuln struct {
	ID             string   `json:"id"`
	TaskID         string   `json:"task_id"`
	Surface        Surface  `json:"surface"`
	Asset          string   `json:"asset"`
	Scanner        string   `json:"scanner"`
	ScannerVersion string   `json:"scanner_version,omitempty"`
	Advisory       string   `json:"advisory"`
	Aliases        []string `json:"aliases,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	CVSS           string   `json:"cvss,omitempty"`
	Package        string   `json:"package"`
	PackageVersion string   `json:"package_version"`
	Ecosystem      string   `json:"ecosystem,omitempty"`
	FixedVersion   string   `json:"fixed_version,omitempty"`
	Summary        string   `json:"summary,omitempty"`
	Location       string   `json:"location,omitempty"`
	EvidenceID     int64    `json:"evidence_id"`
	ScannedAt      string   `json:"scanned_at,omitempty"`
	CreatedAt      string   `json:"created_at,omitempty"`
	UpdatedAt      string   `json:"updated_at,omitempty"`
}

// VulnSeverities lists the severities a filter accepts, most severe first.
func VulnSeverities() []string {
	return []string{"critical", "high", "medium", "low", "unknown"}
}

// normalizeSeverity maps a scanner rating onto the filter vocabulary.
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low", "negligible":
		return "low"
	case "":
		return ""
	}
	return "unknown"
}

const maxVulnField = 512

func boundedVulnText(s string, max int) bool {
	return len(s) <= max && !strings.ContainsAny(s, "\x00\r\n")
}

// VulnFilter narrows a query. An empty field does not constrain.
type VulnFilter struct {
	Asset     string
	Advisory  string
	Severity  string
	Scanner   string
	Ecosystem string
	Package   string
	Limit     int
	Offset    int
}

func (s *Store) validateVuln(ctx context.Context, v Vuln) error {
	if !v.Surface.valid() {
		return errors.New("invalid vuln surface")
	}
	if v.Advisory == "" || !boundedVulnText(v.Advisory, 128) {
		return errors.New("invalid advisory id")
	}
	if v.Package == "" || !boundedVulnText(v.Package, 256) {
		return errors.New("invalid package name")
	}
	if v.Asset == "" || !boundedVulnText(v.Asset, maxVulnField) {
		return errors.New("invalid asset")
	}
	if v.Scanner == "" || !boundedVulnText(v.Scanner, 64) {
		return errors.New("invalid scanner")
	}
	for _, f := range []string{v.ScannerVersion, v.CVSS, v.PackageVersion, v.Ecosystem, v.FixedVersion, v.Location} {
		if !boundedVulnText(f, maxVulnField) {
			return errors.New("vuln field exceeds bounds")
		}
	}
	if len(v.Summary) > 4096 || strings.ContainsRune(v.Summary, '\x00') {
		return errors.New("invalid summary")
	}
	if len(v.Aliases) > 64 {
		return errors.New("too many aliases")
	}
	for _, a := range v.Aliases {
		if a == "" || !boundedVulnText(a, 128) {
			return errors.New("invalid alias")
		}
	}
	if v.EvidenceID <= 0 {
		return errors.New("vuln requires an evidence row")
	}
	var found int
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM evidence WHERE id=? AND task_id=?)`, v.EvidenceID, v.TaskID).Scan(&found); err != nil {
		return err
	}
	if found == 0 {
		return errors.New("vuln evidence does not belong to the task")
	}
	return nil
}

// SaveVuln upserts one advisory record, so a rescan updates the row instead of adding a duplicate.
func (s *Store) SaveVuln(ctx context.Context, v Vuln) (saved Vuln, err error) {
	if s == nil {
		return Vuln{}, errors.New("engagement store unavailable")
	}
	if v.ID == "" || !boundedVulnText(v.ID, 96) {
		return Vuln{}, errors.New("invalid vuln id")
	}
	v.Severity = normalizeSeverity(v.Severity)
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := s.validateVuln(ctx, v); err != nil {
		return Vuln{}, err
	}
	aliases, err := json.Marshal(v.Aliases)
	if err != nil {
		return Vuln{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if v.ScannedAt == "" {
		v.ScannedAt = now
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO vuln_record
		(id, task_id, surface, asset, scanner, scanner_version, advisory, aliases, severity, cvss,
		 package_name, package_version, ecosystem, fixed_version, summary, location, evidence_id,
		 scanned_at, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			severity = excluded.severity,
			cvss = excluded.cvss,
			fixed_version = excluded.fixed_version,
			summary = excluded.summary,
			location = excluded.location,
			aliases = excluded.aliases,
			scanner_version = excluded.scanner_version,
			evidence_id = excluded.evidence_id,
			scanned_at = MAX(vuln_record.scanned_at, excluded.scanned_at),
			updated_at = excluded.updated_at
			WHERE vuln_record.task_id = excluded.task_id`,
		v.ID, v.TaskID, string(v.Surface), v.Asset, v.Scanner, v.ScannerVersion, v.Advisory, string(aliases),
		v.Severity, v.CVSS, v.Package, v.PackageVersion, v.Ecosystem, v.FixedVersion, v.Summary, v.Location,
		v.EvidenceID, v.ScannedAt, now, now)
	if err != nil {
		return Vuln{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return Vuln{}, err
	}
	if changed == 0 {
		return Vuln{}, errors.New("vuln id belongs to another task")
	}
	return s.Vuln(ctx, v.ID)
}

const vulnColumns = `id, task_id, surface, asset, scanner, scanner_version, advisory, aliases, severity,
	cvss, package_name, package_version, ecosystem, fixed_version, summary, location, evidence_id,
	scanned_at, created_at, updated_at`

func scanVuln(rows interface {
	Scan(...any) error
}) (Vuln, error) {
	var v Vuln
	var surface, aliases string
	if err := rows.Scan(&v.ID, &v.TaskID, &surface, &v.Asset, &v.Scanner, &v.ScannerVersion, &v.Advisory,
		&aliases, &v.Severity, &v.CVSS, &v.Package, &v.PackageVersion, &v.Ecosystem, &v.FixedVersion,
		&v.Summary, &v.Location, &v.EvidenceID, &v.ScannedAt, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return Vuln{}, err
	}
	v.Surface = Surface(surface)
	if aliases != "" {
		if err := json.Unmarshal([]byte(aliases), &v.Aliases); err != nil {
			return Vuln{}, err
		}
	}
	return v, nil
}

// Vuln returns one record by id.
func (s *Store) Vuln(ctx context.Context, id string) (Vuln, error) {
	if s == nil {
		return Vuln{}, errors.New("engagement store unavailable")
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+vulnColumns+` FROM vuln_record WHERE id = ?`, id)
	v, err := scanVuln(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Vuln{}, errors.New("vuln not found")
	}
	return v, err
}

// Vulns returns matching records ordered by severity, then advisory, then package, so the ordering does not depend on insertion order.
func (s *Store) Vulns(ctx context.Context, f VulnFilter) ([]Vuln, error) {
	if s == nil {
		return nil, errors.New("engagement store unavailable")
	}
	q := `SELECT ` + vulnColumns + ` FROM vuln_record`
	var where []string
	var args []any
	for _, c := range []struct {
		col string
		val string
	}{
		{"asset", f.Asset},
		{"advisory", f.Advisory},
		{"scanner", f.Scanner},
		{"ecosystem", f.Ecosystem},
		{"package_name", f.Package},
	} {
		if c.val != "" {
			where = append(where, c.col+" = ?")
			args = append(args, c.val)
		}
	}
	if f.Severity != "" {
		if severity := normalizeSeverity(f.Severity); severity == "unknown" {
			where = append(where, "severity IN ('', 'unknown')")
		} else {
			where = append(where, "severity = ?")
			args = append(args, severity)
		}
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += ` ORDER BY CASE lower(severity)
		WHEN 'critical' THEN 0 WHEN 'high' THEN 1
		WHEN 'moderate' THEN 2 WHEN 'medium' THEN 2
		WHEN 'low' THEN 3
		WHEN 'negligible' THEN 4 WHEN 'none' THEN 4
		WHEN 'info' THEN 4 WHEN 'informational' THEN 4
		ELSE 5 END, advisory, package_name, id`
	if f.Limit == 0 {
		f.Limit = 100
	}
	if f.Limit < 1 || f.Limit > 100 || f.Offset < 0 || f.Offset > 1000000 {
		return nil, errors.New("vuln page limit or offset is out of range")
	}
	q += " LIMIT ? OFFSET ?"
	args = append(args, f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Vuln
	for rows.Next() {
		v, err := scanVuln(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// VulnSummary counts records per severity and the distinct advisories, packages and assets behind them.
type VulnSummary struct {
	Rows       int            `json:"rows"`
	Advisories int            `json:"advisories"`
	Assets     int            `json:"assets"`
	BySeverity map[string]int `json:"by_severity"`
	ByScanner  map[string]int `json:"by_scanner"`
}

// VulnStats returns counts over every stored record.
func (s *Store) VulnStats(ctx context.Context) (VulnSummary, error) {
	if s == nil {
		return VulnSummary{}, errors.New("engagement store unavailable")
	}
	out := VulnSummary{BySeverity: map[string]int{}, ByScanner: map[string]int{}}
	rows, err := s.db.QueryContext(ctx, `SELECT severity, scanner FROM vuln_record`)
	if err != nil {
		return VulnSummary{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev, scanner string
		if err := rows.Scan(&sev, &scanner); err != nil {
			return VulnSummary{}, err
		}
		if sev == "" {
			sev = "unknown"
		}
		out.Rows++
		out.BySeverity[sev]++
		out.ByScanner[scanner]++
	}
	if err := rows.Err(); err != nil {
		return VulnSummary{}, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT advisory), COUNT(DISTINCT asset) FROM vuln_record`).Scan(&out.Advisories, &out.Assets); err != nil {
		return VulnSummary{}, err
	}
	return out, nil
}
