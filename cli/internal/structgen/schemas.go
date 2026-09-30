package structgen

import (
	"fmt"
	"strings"
)

// maxSliceLen caps every array field on a schema so a runaway model cannot emit
// unbounded output.
const maxSliceLen = 200

var (
	assetTypes      = []string{"host", "web-app", "api", "network", "mobile", "cloud", "binary", "unknown"}
	severities      = []string{"info", "low", "medium", "high", "critical"}
	iocTypes        = []string{"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "filepath", "registry", "mutex", "other"}
	assessmentTypes = []string{"binary", "privesc", "suid", "capability", "service", "other"}
	platforms       = []string{"linux", "windows", "macos", "unknown"}
	exploitability  = []string{"none", "theoretical", "likely", "confirmed"}
)

func nonEmpty(field, val string) error {
	if strings.TrimSpace(val) == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}

func oneOf(field, val string, allowed []string) error {
	for _, a := range allowed {
		if val == a {
			return nil
		}
	}
	return fmt.Errorf("%s %q must be one of: %s", field, val, strings.Join(allowed, ", "))
}

func capLen(field string, n int) error {
	if n > maxSliceLen {
		return fmt.Errorf("%s has %d entries, exceeds limit %d", field, n, maxSliceLen)
	}
	return nil
}

// ExposedService is one listening service on a target.
type ExposedService struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Notes   string `json:"notes"`
}

// TargetProfile is a recon-derived profile of a target.
type TargetProfile struct {
	Target          string           `json:"target"`
	AssetType       string           `json:"asset_type"`
	Technologies    []string         `json:"technologies"`
	ExposedServices []ExposedService `json:"exposed_services"`
	AttackSurface   []string         `json:"attack_surface"`
	Notes           string           `json:"notes"`
}

func (t *TargetProfile) Validate() error {
	if err := nonEmpty("target", t.Target); err != nil {
		return err
	}
	if err := oneOf("asset_type", t.AssetType, assetTypes); err != nil {
		return err
	}
	if err := capLen("technologies", len(t.Technologies)); err != nil {
		return err
	}
	if err := capLen("exposed_services", len(t.ExposedServices)); err != nil {
		return err
	}
	if err := capLen("attack_surface", len(t.AttackSurface)); err != nil {
		return err
	}
	for i, s := range t.ExposedServices {
		if s.Port < 0 || s.Port > 65535 {
			return fmt.Errorf("exposed_services[%d].port %d out of range", i, s.Port)
		}
	}
	return nil
}

// AttackPhase is one stage of an attack plan.
type AttackPhase struct {
	Name       string   `json:"name"`
	Techniques []string `json:"techniques"`
	Tools      []string `json:"tools"`
	Rationale  string   `json:"rationale"`
}

// AttackPlan is a bounded plan of attack for an authorized engagement.
type AttackPlan struct {
	Objective         string        `json:"objective"`
	Target            string        `json:"target"`
	Phases            []AttackPhase `json:"phases"`
	Assumptions       []string      `json:"assumptions"`
	Risks             []string      `json:"risks"`
	AuthorizationNote string        `json:"authorization_note"`
}

func (a *AttackPlan) Validate() error {
	if err := nonEmpty("objective", a.Objective); err != nil {
		return err
	}
	if err := nonEmpty("target", a.Target); err != nil {
		return err
	}
	if len(a.Phases) == 0 {
		return fmt.Errorf("phases requires at least one entry")
	}
	if err := capLen("phases", len(a.Phases)); err != nil {
		return err
	}
	for i, p := range a.Phases {
		if err := nonEmpty(fmt.Sprintf("phases[%d].name", i), p.Name); err != nil {
			return err
		}
		if err := capLen(fmt.Sprintf("phases[%d].techniques", i), len(p.Techniques)); err != nil {
			return err
		}
		if err := capLen(fmt.Sprintf("phases[%d].tools", i), len(p.Tools)); err != nil {
			return err
		}
	}
	if err := capLen("assumptions", len(a.Assumptions)); err != nil {
		return err
	}
	return capLen("risks", len(a.Risks))
}

// Finding is a single security finding record.
type Finding struct {
	Title        string   `json:"title"`
	Severity     string   `json:"severity"`
	CWE          string   `json:"cwe"`
	Affected     string   `json:"affected"`
	Description  string   `json:"description"`
	Evidence     []string `json:"evidence"`
	Reproduction []string `json:"reproduction"`
	Remediation  string   `json:"remediation"`
	References   []string `json:"references"`
}

func (f *Finding) Validate() error {
	if err := nonEmpty("title", f.Title); err != nil {
		return err
	}
	if err := oneOf("severity", f.Severity, severities); err != nil {
		return err
	}
	if err := nonEmpty("affected", f.Affected); err != nil {
		return err
	}
	if err := nonEmpty("description", f.Description); err != nil {
		return err
	}
	if err := capLen("evidence", len(f.Evidence)); err != nil {
		return err
	}
	if err := capLen("reproduction", len(f.Reproduction)); err != nil {
		return err
	}
	return capLen("references", len(f.References))
}

// Indicator is one indicator of compromise.
type Indicator struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context"`
}

// IOCExtraction is a set of indicators extracted from a log or artifact.
type IOCExtraction struct {
	Indicators []Indicator `json:"indicators"`
	Summary    string      `json:"summary"`
}

func (x *IOCExtraction) Validate() error {
	if len(x.Indicators) == 0 {
		return fmt.Errorf("indicators requires at least one entry")
	}
	if err := capLen("indicators", len(x.Indicators)); err != nil {
		return err
	}
	for i, ind := range x.Indicators {
		if err := oneOf(fmt.Sprintf("indicators[%d].type", i), ind.Type, iocTypes); err != nil {
			return err
		}
		if err := nonEmpty(fmt.Sprintf("indicators[%d].value", i), ind.Value); err != nil {
			return err
		}
	}
	return nil
}

// Weakness is one weakness found in a binary/privesc assessment.
type Weakness struct {
	Name     string `json:"name"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

// BinaryAssessment is an assessment of a binary or a privilege-escalation vector.
type BinaryAssessment struct {
	Subject         string     `json:"subject"`
	AssessmentType  string     `json:"assessment_type"`
	Platform        string     `json:"platform"`
	Weaknesses      []Weakness `json:"weaknesses"`
	Exploitability  string     `json:"exploitability"`
	PrivescVectors  []string   `json:"privesc_vectors"`
	Recommendations []string   `json:"recommendations"`
}

func (b *BinaryAssessment) Validate() error {
	if err := nonEmpty("subject", b.Subject); err != nil {
		return err
	}
	if err := oneOf("assessment_type", b.AssessmentType, assessmentTypes); err != nil {
		return err
	}
	if b.Platform != "" {
		if err := oneOf("platform", b.Platform, platforms); err != nil {
			return err
		}
	}
	if b.Exploitability != "" {
		if err := oneOf("exploitability", b.Exploitability, exploitability); err != nil {
			return err
		}
	}
	if err := capLen("weaknesses", len(b.Weaknesses)); err != nil {
		return err
	}
	for i, w := range b.Weaknesses {
		if w.Severity != "" {
			if err := oneOf(fmt.Sprintf("weaknesses[%d].severity", i), w.Severity, severities); err != nil {
				return err
			}
		}
	}
	if err := capLen("privesc_vectors", len(b.PrivescVectors)); err != nil {
		return err
	}
	return capLen("recommendations", len(b.Recommendations))
}

// schemas is the registry, in help-listing order.
var schemas = []Schema{
	{
		Name:         "target-profile",
		Description:  "profile a target from recon notes",
		PromptSchema: "Schema target-profile. Fields: target (string, required); asset_type (one of host, web-app, api, network, mobile, cloud, binary, unknown; required); technologies (array of strings); exposed_services (array of objects {port: integer, service: string, notes: string}); attack_surface (array of strings); notes (string).",
		newTarget:    func() validator { return &TargetProfile{} },
	},
	{
		Name:         "attack-plan",
		Description:  "draft a bounded attack plan for a target",
		PromptSchema: "Schema attack-plan. Fields: objective (string, required); target (string, required); phases (array of objects {name: string, techniques: array of strings, tools: array of strings, rationale: string}, at least one, each name required); assumptions (array of strings); risks (array of strings); authorization_note (string).",
		newTarget:    func() validator { return &AttackPlan{} },
	},
	{
		Name:         "finding",
		Description:  "record a single security finding",
		PromptSchema: "Schema finding. Fields: title (string, required); severity (one of info, low, medium, high, critical; required); cwe (string, e.g. CWE-79); affected (string, required); description (string, required); evidence (array of strings); reproduction (array of strings); remediation (string); references (array of strings).",
		newTarget:    func() validator { return &Finding{} },
	},
	{
		Name:         "ioc",
		Description:  "extract indicators of compromise from text",
		PromptSchema: "Schema ioc. Fields: indicators (array of objects {type: one of ipv4, ipv6, domain, url, md5, sha1, sha256, email, filepath, registry, mutex, other; value: string, required; context: string}, at least one); summary (string).",
		newTarget:    func() validator { return &IOCExtraction{} },
	},
	{
		Name:         "binary-assessment",
		Description:  "assess a binary or privilege-escalation vector",
		PromptSchema: "Schema binary-assessment. Fields: subject (string, required); assessment_type (one of binary, privesc, suid, capability, service, other; required); platform (one of linux, windows, macos, unknown); weaknesses (array of objects {name: string, detail: string, severity: one of info, low, medium, high, critical}); exploitability (one of none, theoretical, likely, confirmed); privesc_vectors (array of strings); recommendations (array of strings).",
		newTarget:    func() validator { return &BinaryAssessment{} },
	},
}

// Schemas returns a copy of the schema registry, in help-listing order.
func Schemas() []Schema {
	out := make([]Schema, len(schemas))
	copy(out, schemas)
	return out
}

// Lookup returns the schema with the given name.
func Lookup(name string) (Schema, bool) {
	for _, s := range schemas {
		if s.Name == name {
			return s, true
		}
	}
	return Schema{}, false
}

// SchemaNames returns the schema names in help-listing order.
func SchemaNames() []string {
	names := make([]string, len(schemas))
	for i, s := range schemas {
		names[i] = s.Name
	}
	return names
}
