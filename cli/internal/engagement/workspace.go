package engagement

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const auditDetailCap = 2000

// Workspace is a named per-engagement directory: the store, an evidence tree,
// and an append-only JSONL audit log.
type Workspace struct {
	Dir         string
	Store       *Store
	evidenceDir string
	auditPath   string
}

// OpenWorkspace creates (if needed) the workspace directory tree and opens the
// store inside it. The directory is created with mode 0700.
func OpenWorkspace(dir string) (*Workspace, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	evid := filepath.Join(abs, "evidence")
	if err := os.MkdirAll(evid, 0o700); err != nil {
		return nil, err
	}
	st, err := Open(filepath.Join(abs, "engagement.db"))
	if err != nil {
		return nil, err
	}
	return &Workspace{Dir: abs, Store: st, evidenceDir: evid, auditPath: filepath.Join(abs, "audit.jsonl")}, nil
}

// EvidenceDir returns the evidence subdirectory path.
func (w *Workspace) EvidenceDir() string { return w.evidenceDir }

// Close releases the store.
func (w *Workspace) Close() error {
	if w.Store != nil {
		return w.Store.Close()
	}
	return nil
}

// auditRecord is one JSONL audit line.
type auditRecord struct {
	At     string `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

// AuditLine appends one sanitized JSON object to audit.jsonl.
func (w *Workspace) AuditLine(actor, action, detail string) error {
	rec := auditRecord{
		At:     time.Now().UTC().Format(time.RFC3339),
		Actor:  sanitizeAuditDetail(actor),
		Action: sanitizeAuditDetail(action),
		Detail: sanitizeAuditDetail(detail),
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(w.auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

// sanitizeAuditDetail maps control bytes (< 0x20 or 0x7f, including NUL and
// newline) to spaces and truncates to auditDetailCap runes.
func sanitizeAuditDetail(s string) string {
	r := []rune(s)
	if len(r) > auditDetailCap {
		r = r[:auditDetailCap]
	}
	for i, c := range r {
		if c < 0x20 || c == 0x7f {
			r[i] = ' '
		}
	}
	return string(r)
}
