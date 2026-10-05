package webanalysis

import "strings"

type EvidenceGrade struct {
	Grade       string `json:"grade"`
	Explanation string `json:"explanation"`
}

type ExchangeValidation struct {
	Adapter   string   `json:"adapter"`
	Role      string   `json:"role"`
	At        string   `json:"at"`
	Artifacts []string `json:"artifacts"`
}

func OperationEvidence(o Operation) EvidenceGrade {
	if o.Protocol == "websocket" {
		if o.Exchange != nil && len(o.Exchange.Artifacts) >= 2 {
			return EvidenceGrade{"exchange-validated", "The supplied message transcript matched for the recorded role and time. This validates that exchange only."}
		}
		grade := EvidenceGrade{"discovered", "A WebSocket endpoint was found. Its handshake and application protocol remain unvalidated."}
		for _, e := range o.Examples {
			if e.Denied {
				continue
			}
			if e.Status == 101 && (e.Direction == "received" || e.Direction == "sent") {
				return EvidenceGrade{"message-observed", "A WebSocket application message was captured. No supplied response expectation was validated."}
			}
			if e.Status == 101 {
				grade = EvidenceGrade{"handshake-observed", "The WebSocket upgrade succeeded. A subscription or application exchange remains unvalidated."}
			}
		}
		return grade
	}
	switch o.Validation {
	case "response-observed":
		return EvidenceGrade{"response-observed", "An HTTP response was captured for the recorded role. Status alone does not prove business behavior or other roles."}
	case "access-response":
		return EvidenceGrade{"access-observed", "An access denial was captured. Authorized behavior remains unvalidated."}
	case "cache-response-observed":
		return EvidenceGrade{"cache-observed", "A cached response was captured. Current server behavior remains unvalidated."}
	case "attempted":
		return EvidenceGrade{"attempted", "A request was captured without a response. Reachability and application behavior remain unvalidated."}
	}
	if strings.Contains(strings.Join(o.Discoveries, ","), "historical") {
		return EvidenceGrade{"historical", "The operation was found in archived source. Current availability and application behavior remain unvalidated."}
	}
	return EvidenceGrade{"discovered", "The operation was found in source. Runtime values, roles and application behavior remain unvalidated."}
}

func FindingEvidence(f Finding) EvidenceGrade {
	switch f.Kind {
	case "secret-candidate":
		if f.EnvironmentVariable {
			return EvidenceGrade{"configuration-observed", "A captured target environment assignment contains this value. Sensitivity and runtime use remain unverified."}
		}
		return EvidenceGrade{"detected", "A secret pattern matched. The credential has not been tested for validity."}
	case "library-vulnerability":
		return EvidenceGrade{"advisory-match", "A detected library version matched an advisory range in the recorded snapshot. Exploitability remains unvalidated."}
	case "library":
		return EvidenceGrade{"detected", "A library signature or version banner matched. Runtime use remains unvalidated."}
	case "technology":
		return EvidenceGrade{"inferred", "A source or header signal suggests this technology. The server stack and version remain unverified."}
	default:
		return EvidenceGrade{"lead", "A static source pattern matched. Its execution path and security impact remain unvalidated."}
	}
}

func GradeSnapshot(s Snapshot) Snapshot {
	for i := range s.Operations {
		s.Operations[i].Evidence = OperationEvidence(s.Operations[i])
		if s.Operations[i].Protocol == "websocket" {
			switch s.Operations[i].Evidence.Grade {
			case "exchange-validated":
				s.Operations[i].Validation = "application-exchange-validated"
			case "handshake-observed", "message-observed":
				s.Operations[i].Validation = s.Operations[i].Evidence.Grade
			default:
				if len(s.Operations[i].Examples) > 0 {
					s.Operations[i].Validation = "attempted"
				} else {
					s.Operations[i].Validation = "unvalidated"
				}
			}
		}
	}
	for i := range s.Findings {
		s.Findings[i].Evidence = FindingEvidence(s.Findings[i])
	}
	return s
}
