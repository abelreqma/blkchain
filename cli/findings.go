package main

// findings.go holds the shared, code-parsed engagement models. Findings,
// assets, services, and TLS details are parsed in code from verbatim evidence
// (never asserted by the model), and every record carries Provenance tracing it
// to the exact evidence quote it came from. The per-type parsers live in their
// own files (findings_asset.go, findings_service.go, findings_tls.go,
// findings_finding.go); correlation (correlate.go) consumes the Service model.

// Provenance ties a parsed record to the exact evidence it came from: the task
// that produced the evidence and the evidence-quote row id. A record whose
// provenance is not valid has no verifiable source and is rejected by the
// parsers (no model-asserted field without a quote id).
type Provenance struct {
	TaskID     string
	EvidenceID int64
}

// valid reports whether the provenance names a real task and a real evidence
// row. EvidenceID is a positive sqlite rowid, so a non-positive id means the
// record was not tied to a stored quote.
func (p Provenance) valid() bool { return p.TaskID != "" && p.EvidenceID > 0 }

// Severity ranks a Finding. The parsers assign it from a fixed code mapping,
// never from the model.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Asset is a host or address discovered during recon.
type Asset struct {
	Host string
	Prov Provenance
}

// Service is a network service observed on a host: its port and transport, and
// the product and version when the output disclosed them (empty when it did
// not; the parser never invents a product or version). Service+version is the
// deterministic key correlation maps to a candidate exploit task.
type Service struct {
	Host      string
	Port      int
	Transport string
	Product   string
	Version   string
	Prov      Provenance
}

// TLSInfo is a parsed TLS detail for a host:port. Issue names a concrete problem
// the output actually showed (e.g. "deprecated-protocol", "self-signed",
// "expired"); it is empty for a clean observation.
type TLSInfo struct {
	Host     string
	Port     int
	Protocol string
	Cipher   string
	Issue    string
	Prov     Provenance
}

// Finding is a general, severity-ranked security observation parsed from
// evidence. Host and Port are set when the evidence located the finding; Port
// is 0 when it did not apply.
type Finding struct {
	Title    string
	Severity Severity
	Detail   string
	Host     string
	Port     int
	Prov     Provenance
}
