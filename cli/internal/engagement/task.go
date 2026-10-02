package engagement

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// Status is the lifecycle state of a task.
type Status string

const (
	StatusTodo    Status = "todo"
	StatusActive  Status = "active"
	StatusDone    Status = "done"
	StatusNA      Status = "na"
	StatusBlocked Status = "blocked"
)

func (s Status) valid() bool {
	switch s {
	case StatusTodo, StatusActive, StatusDone, StatusNA, StatusBlocked:
		return true
	}
	return false
}

// Phase is the engagement stage a task belongs to.
type Phase string

const (
	PhaseRecon   Phase = "recon"
	PhaseExploit Phase = "exploit"
	PhasePostEx  Phase = "post-ex"
	PhaseReport  Phase = "report"
)

func (p Phase) valid() bool {
	switch p {
	case PhaseRecon, PhaseExploit, PhasePostEx, PhaseReport:
		return true
	}
	return false
}

// Surface is the attack surface a task targets.
type Surface string

const (
	SurfaceLocal      Surface = "local"
	SurfaceNetwork    Surface = "network"
	SurfaceWeb        Surface = "web"
	SurfaceAD         Surface = "ad"
	SurfaceCloud      Surface = "cloud"
	SurfaceCloudAWS   Surface = "cloud-aws"
	SurfaceCloudGCP   Surface = "cloud-gcp"
	SurfaceCloudAzure Surface = "cloud-azure"
	SurfaceContainer  Surface = "container"
	SurfaceAISecurity Surface = "ai-security"
)

// allSurfaces is the canonical ordered set of every valid Surface. valid() and
// Vantage.Reaches stay exhaustive over it; AllSurfaces returns a copy of it.
var allSurfaces = []Surface{
	SurfaceLocal, SurfaceNetwork, SurfaceWeb, SurfaceAD,
	SurfaceCloud, SurfaceCloudAWS, SurfaceCloudGCP, SurfaceCloudAzure,
	SurfaceContainer, SurfaceAISecurity,
}

func (s Surface) valid() bool {
	switch s {
	case SurfaceLocal, SurfaceNetwork, SurfaceWeb, SurfaceAD,
		SurfaceCloud, SurfaceCloudAWS, SurfaceCloudGCP, SurfaceCloudAzure,
		SurfaceContainer, SurfaceAISecurity:
		return true
	}
	return false
}

// AllSurfaces returns a copy of the canonical surface set in a stable order.
// Callers that must iterate every surface (for example the vantage seed, which
// decides which surfaces a new vantage newly reaches) use this so they track any
// surface added here without their own literal list. The returned slice is a
// copy; callers must not rely on mutating the backing array.
func AllSurfaces() []Surface {
	out := make([]Surface, len(allSurfaces))
	copy(out, allSurfaces)
	return out
}

// Capability is the class of action a task performs.
type Capability string

const (
	CapPassive   Capability = "passive"
	CapEnumerate Capability = "enumerate"
	CapActive    Capability = "active"
)

func (c Capability) valid() bool {
	switch c {
	case CapPassive, CapEnumerate, CapActive:
		return true
	}
	return false
}

// surfaceForKindMap gives the default Surface for a task Kind. A kind not listed
// here defaults
// to SurfaceNetwork via surfaceForKind. The per-CSP cloud surfaces
// (cloud-aws/cloud-gcp/cloud-azure) are not derived from a Kind here: there are
// no per-CSP personas, so a cloud Kind maps to the generic SurfaceCloud and the
// provider-specific surface is set explicitly on Task.Surface from the
// target/scope.
var surfaceForKindMap = map[string]Surface{
	"web":             SurfaceWeb,
	"ad":              SurfaceAD,
	"cloud":           SurfaceCloud,
	"k8s":             SurfaceContainer,
	"container":       SurfaceContainer,
	"ai-security":     SurfaceAISecurity,
	"ai":              SurfaceAISecurity,
	"local":           SurfaceLocal,
	"target-analysis": SurfaceLocal,
	"exploit-dev":     SurfaceLocal,
	"wifi":            SurfaceNetwork,
	"recon":           SurfaceNetwork,
	"generic":         SurfaceNetwork,
	"":                SurfaceNetwork,
}

// surfaceForKind returns the default Surface for kind, falling back to
// SurfaceNetwork for an unknown kind.
func surfaceForKind(kind string) Surface {
	if s, ok := surfaceForKindMap[kind]; ok {
		return s
	}
	return SurfaceNetwork
}

// phaseForKindMap gives the default Phase for a task Kind whose nature is not
// recon. Only the exploit-oriented persona is listed; every other Kind (including
// the enumeration/analysis personas and the empty or unknown Kind) defaults to
// recon via phaseForKind. Deriving an exploit phase makes the task requiresArm at
// the gate (denied unless armed), which is the intended fail-safe for a Kind that
// is not recon-phase work.
var phaseForKindMap = map[string]Phase{
	"exploit-dev": PhaseExploit,
	"exploit":     PhaseExploit,
}

// phaseForKind returns the default Phase for kind, falling back to PhaseRecon for
// any Kind not in phaseForKindMap. The lookup is case-insensitive and trimmed so a
// mis-cased exploit Kind still derives the stricter phase (fail-safe); an empty
// Phase on a task is derived from its Kind in applyLocked, so a non-recon-nature
// Kind cannot silently route to the recon tier.
func phaseForKind(kind string) Phase {
	if p, ok := phaseForKindMap[strings.ToLower(strings.TrimSpace(kind))]; ok {
		return p
	}
	return PhaseRecon
}

// Citation records where a candidate task came from: a corpus (kb) source
// pointer and its origin trust, captured at seed time. It is empty for a
// code-owned candidate whose source is its finding evidence (BasisIDs). Origin is
// "trusted" for the local corpus and "untrusted" for a web source; "" means no
// corpus citation (the source is the finding evidence). All fields are
// comparable, so a zero Citation compares equal to Citation{}.
type Citation struct {
	Source   string `json:"source,omitempty"`
	Path     string `json:"path,omitempty"`
	Section  string `json:"section,omitempty"`
	CWEClass string `json:"cwe_class,omitempty"`
	Origin   string `json:"origin,omitempty"`
}

// Task is one unit of engagement work.
type Task struct {
	ID         string
	Kind       string
	Target     string
	Objective  string
	DoneWhen   string
	Status     Status
	Phase      Phase
	Surface    Surface
	Capability Capability
	Armed      bool
	DependsOn  []string
	BasisIDs   []string
	// CoverageGap marks a candidate that a deterministic detector matched but the
	// corpus could not ground with an accepted citation. It is the
	// structured discriminator for a non-actionable "corpus-coverage-gap"
	// candidate: such a candidate is persisted Status=blocked and is surfaced to
	// the operator but not dispatched (dispatch_batch skips blocked) and not armed
	// (armTask refuses it) until it is grounded.
	CoverageGap bool
	// Citation is the candidate's source provenance: the kb
	// source + origin trust when it was seeded from the corpus, empty otherwise.
	Citation Citation
	// Advisory is an operator-facing advisory string: prior-episode recall from
	// episodic memory, display-only. It is read by no gate, label, classifier,
	// selector, or correlation edge, so untrusted recall text in it can never
	// steer detection, arming, or targeting. Empty when there is no prior-episode
	// hint. A writer (the D' correlation path) sets it; the plumbing here only
	// persists and surfaces it.
	Advisory   string
	CreatedRev int64
	UpdatedRev int64
}

// ErrNotFound is returned when a task id does not exist.
var ErrNotFound = errors.New("engagement: task not found")

// marshalStrings encodes a string slice as JSON text; nil and empty give "[]".
func marshalStrings(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// unmarshalStrings decodes JSON text into a string slice; "" and "[]" give an
// empty slice.
func unmarshalStrings(s string) ([]string, error) {
	if s == "" {
		return []string{}, nil
	}
	out := []string{}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// marshalCitation encodes a Citation as JSON text; an empty Citation gives "".
func marshalCitation(c Citation) string {
	if c == (Citation{}) {
		return ""
	}
	b, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return string(b)
}

// unmarshalCitation decodes JSON text into a Citation; "" gives an empty Citation.
func unmarshalCitation(s string) (Citation, error) {
	if s == "" {
		return Citation{}, nil
	}
	var c Citation
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return Citation{}, err
	}
	return c, nil
}

// GetTask returns the task with the given id, or ErrNotFound.
func (s *Store) GetTask(id string) (Task, error) {
	var (
		t                      Task
		status                 string
		deps, bas              sql.NullString
		phase, surface, capVal sql.NullString
		cit                    sql.NullString
		advisory               sql.NullString
		armed                  sql.NullInt64
		coverageGap            sql.NullInt64
	)
	err := s.db.QueryRow(
		`SELECT id, kind, target, objective, done_when, status, depends_on, basis_ids, created_rev, updated_rev, phase, surface, capability, armed, coverage_gap, citation, advisory
		 FROM task WHERE id = ?`, id).
		Scan(&t.ID, &t.Kind, &t.Target, &t.Objective, &t.DoneWhen, &status, &deps, &bas, &t.CreatedRev, &t.UpdatedRev, &phase, &surface, &capVal, &armed, &coverageGap, &cit, &advisory)
	if errors.Is(err, sql.ErrNoRows) {
		return Task{}, ErrNotFound
	}
	if err != nil {
		return Task{}, err
	}
	t.Status = Status(status)
	t.Phase = Phase(phase.String)
	t.Surface = Surface(surface.String)
	t.Capability = Capability(capVal.String)
	t.Armed = armed.Int64 != 0
	t.CoverageGap = coverageGap.Int64 != 0
	t.Advisory = advisory.String
	if t.DependsOn, err = unmarshalStrings(deps.String); err != nil {
		return Task{}, err
	}
	if t.BasisIDs, err = unmarshalStrings(bas.String); err != nil {
		return Task{}, err
	}
	if t.Citation, err = unmarshalCitation(cit.String); err != nil {
		return Task{}, err
	}
	return t, nil
}

// Revision returns the current engagement revision counter.
func (s *Store) Revision(ctx context.Context) (int64, error) {
	return readRevision(ctx, s.db)
}
