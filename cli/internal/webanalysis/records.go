package webanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const Version = "webanalysis-1"
const MaxSource = 4 << 20
const MaxRecords = 20000

type Location struct {
	Unit   string `json:"unit"`
	Offset int    `json:"offset"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}
type Artifact struct {
	ID          string      `json:"id"`
	Hash        string      `json:"sha256"`
	TaskID      string      `json:"task_id,omitempty"`
	Kind        string      `json:"kind"`
	URL         string      `json:"url"`
	FinalURL    string      `json:"final_url"`
	DocumentURL string      `json:"document_url,omitempty"`
	CapturedAt  string      `json:"captured_at,omitempty"`
	RetrievedAt string      `json:"retrieved_at"`
	Role        string      `json:"role"`
	Status      int         `json:"status,omitempty"`
	MIME        string      `json:"mime,omitempty"`
	Headers     http.Header `json:"headers,omitempty"`
	Size        int         `json:"size"`
	Complete    bool        `json:"complete"`
	Parents     []string    `json:"parents,omitempty"`
	Gap         string      `json:"gap,omitempty"`
	SourceMap   string      `json:"source_map,omitempty"`
	MapLine     int         `json:"map_line_offset,omitempty"`
	MapColumn   int         `json:"map_column_offset,omitempty"`
}
type SourceUnit struct {
	ID              string    `json:"id"`
	Artifact        string    `json:"artifact"`
	Hash            string    `json:"sha256"`
	URL             string    `json:"url"`
	Name            string    `json:"name,omitempty"`
	DocumentURL     string    `json:"document_url,omitempty"`
	Language        string    `json:"language"`
	Kind            string    `json:"kind"`
	Offset          int       `json:"offset"`
	Parse           string    `json:"parse"`
	Mappings        []Mapping `json:"mappings,omitempty"`
	Original        *Location `json:"original,omitempty"`
	Transformations []string  `json:"transformations,omitempty"`
}
type Parameter struct {
	Name       string `json:"name"`
	Field      string `json:"field"`
	Expression string `json:"expression"`
	Type       string `json:"type,omitempty"`
	Default    string `json:"default,omitempty"`
	Unresolved bool   `json:"unresolved,omitempty"`
}
type Function struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Enclosing  string      `json:"enclosing,omitempty"`
	Location   Location    `json:"location"`
	Parameters []Parameter `json:"parameters"`
}
type Call struct {
	ID         string   `json:"id"`
	Function   string   `json:"function,omitempty"`
	Callee     string   `json:"callee"`
	Location   Location `json:"location"`
	Arguments  []string `json:"arguments"`
	Conditions []string `json:"conditions,omitempty"`
}
type Operation struct {
	ID          string           `json:"id"`
	Origin      string           `json:"origin"`
	Method      string           `json:"method"`
	Path        string           `json:"path"`
	Query       string           `json:"query,omitempty"`
	Protocol    string           `json:"protocol"`
	Parameters  []Parameter      `json:"parameters"`
	ContentType string           `json:"content_type,omitempty"`
	GraphQL     string           `json:"graphql,omitempty"`
	Variables   []string         `json:"variables,omitempty"`
	Discoveries []string         `json:"discoveries"`
	Validation  string           `json:"validation"`
	Statuses    []int            `json:"statuses,omitempty"`
	Calls       []string         `json:"calls,omitempty"`
	Roles       []string         `json:"roles,omitempty"`
	Features    []string         `json:"features"`
	Examples    []RequestExample `json:"examples,omitempty"`
	Unresolved  []string         `json:"unresolved,omitempty"`
}
type RequestExample struct {
	Cached    bool   `json:"cached,omitempty"`
	SocketID  string `json:"socket_id,omitempty"`
	Sequence  int    `json:"sequence,omitempty"`
	Direction string `json:"direction,omitempty"`
	Opcode    int    `json:"opcode,omitempty"`
	Encoding  string `json:"encoding,omitempty"`
	Denied    bool   `json:"denied,omitempty"`
	Worker    string `json:"worker,omitempty"`

	ResourceType string      `json:"resource_type,omitempty"`
	URL          string      `json:"url"`
	Method       string      `json:"method"`
	Headers      http.Header `json:"headers,omitempty"`
	Body         string      `json:"body,omitempty"`
	Role         string      `json:"role"`
	Status       int         `json:"status,omitempty"`
	Frame        string      `json:"frame,omitempty"`
	Initiator    string      `json:"initiator,omitempty"`
	Artifact     string      `json:"artifact,omitempty"`
}
type Relationship struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	To         string `json:"to"`
	Kind       string `json:"kind"`
	Field      string `json:"field,omitempty"`
	Expression string `json:"expression,omitempty"`
}
type Finding struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	Detector       string   `json:"detector"`
	Confidence     string   `json:"confidence"`
	Location       Location `json:"location"`
	Preview        string   `json:"preview"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
	Version        string   `json:"analyzer_version"`
	Library        string   `json:"library,omitempty"`
	LibraryVersion string   `json:"library_version,omitempty"`
	Advisory       string   `json:"advisory,omitempty"`
	Snapshot       string   `json:"snapshot,omitempty"`
}
type Gap struct {
	Stage  string `json:"stage"`
	URL    string `json:"url,omitempty"`
	Reason string `json:"reason"`
}
type Coverage struct {
	Targets      []string `json:"targets,omitempty"`
	ID           string   `json:"id"`
	Role         string   `json:"role"`
	Routes       []string `json:"routes"`
	Interactions []string `json:"interactions"`
	Downloaded   []string `json:"downloaded"`
	Stages       []string `json:"stages"`
	Gaps         []Gap    `json:"gaps"`
	Requests     int      `json:"requests"`
	Bytes        int      `json:"bytes"`
	Started      string   `json:"started"`
	Ended        string   `json:"ended,omitempty"`
	State        string   `json:"state"`
}
type Feature struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Operations []string `json:"operations"`
	Calls      []string `json:"calls"`
	Roles      []string `json:"roles"`
	Routes     []string `json:"routes,omitempty"`
	Conditions []string `json:"conditions,omitempty"`
}
type Result struct {
	Units         []SourceUnit   `json:"units"`
	Functions     []Function     `json:"functions"`
	Calls         []Call         `json:"calls"`
	Operations    []Operation    `json:"operations"`
	Relationships []Relationship `json:"relationships"`
	Findings      []Finding      `json:"findings"`
	Dependencies  []Dependency   `json:"dependencies"`
	Gaps          []Gap          `json:"gaps"`
	Formatted     []byte         `json:"formatted,omitempty"`
}
type Dependency struct {
	URL        string   `json:"url,omitempty"`
	Kind       string   `json:"kind"`
	Expression string   `json:"expression,omitempty"`
	Location   Location `json:"location"`
}
type Snapshot struct {
	Requests      []RequestExample `json:"requests"`
	Exports       []Template       `json:"exports"`
	Artifacts     []Artifact       `json:"artifacts"`
	Units         []SourceUnit     `json:"units"`
	Functions     []Function       `json:"functions"`
	Calls         []Call           `json:"calls"`
	Operations    []Operation      `json:"operations"`
	Relationships []Relationship   `json:"relationships"`
	Findings      []Finding        `json:"findings"`
	Features      []Feature        `json:"features"`
	Coverage      []Coverage       `json:"coverage"`
}

func Hash(b []byte) string       { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func ID(values ...string) string { return Hash([]byte(strings.Join(values, "\x00"))) }
func Now() string                { return time.Now().UTC().Format(time.RFC3339Nano) }
func AddUnique(v []string, s string) []string {
	if s == "" {
		return v
	}
	for _, x := range v {
		if x == s {
			return v
		}
	}
	return append(v, s)
}

var sensitive = regexp.MustCompile(`(?i)(authorization|cookie|token|secret|password|api.?key|csrf|signature|credential|session)`)

func Sensitive(s string) bool { return sensitive.MatchString(s) }
func SafeText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || (r >= 0x80 && r <= 0x9f) {
			return ' '
		}
		return r
	}, s)
}
func RedactHeaders(h http.Header) http.Header {
	out := h.Clone()
	for k := range out {
		if Sensitive(k) {
			out[k] = []string{"[REDACTED]"}
		}
	}
	return out
}
func Fingerprint(s string) string { return Hash([]byte(s)) }
func RecordID(v any) string       { b, _ := json.Marshal(v); return Hash(b) }

type Mapping struct {
	GeneratedLine   int `json:"generated_line"`
	GeneratedColumn int `json:"generated_column"`
	OriginalLine    int `json:"original_line"`
	OriginalColumn  int `json:"original_column"`
	Source          int `json:"source"`
}
