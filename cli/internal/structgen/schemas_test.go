package structgen

import (
	"context"
	"strings"
	"testing"
)

func TestRegistryHasFiveSchemas(t *testing.T) {
	names := SchemaNames()
	want := []string{"target-profile", "attack-plan", "finding", "ioc", "binary-assessment"}
	if len(names) != len(want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	for i, n := range want {
		if names[i] != n {
			t.Fatalf("names[%d] = %q, want %q", i, names[i], n)
		}
		if _, ok := Lookup(n); !ok {
			t.Fatalf("Lookup(%q) not found", n)
		}
	}
	if _, ok := Lookup("nope"); ok {
		t.Fatalf("Lookup(nope) should be false")
	}
	if len(Schemas()) != len(want) {
		t.Fatalf("Schemas() len = %d", len(Schemas()))
	}
}

func TestTargetProfileValidate(t *testing.T) {
	ok := TargetProfile{Target: "acme.test", AssetType: "web-app"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid instance rejected: %v", err)
	}
	if err := (&TargetProfile{AssetType: "web-app"}).Validate(); err == nil {
		t.Fatalf("missing target accepted")
	}
	if err := (&TargetProfile{Target: "x", AssetType: "banana"}).Validate(); err == nil {
		t.Fatalf("bad asset_type accepted")
	}
	if err := (&TargetProfile{Target: "x", AssetType: "host", ExposedServices: []ExposedService{{Port: 70000}}}).Validate(); err == nil {
		t.Fatalf("out-of-range port accepted")
	}
}

func TestAttackPlanValidate(t *testing.T) {
	ok := AttackPlan{Objective: "assess", Target: "acme.test", Phases: []AttackPhase{{Name: "recon"}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid instance rejected: %v", err)
	}
	if err := (&AttackPlan{Objective: "x", Target: "y"}).Validate(); err == nil {
		t.Fatalf("empty phases accepted")
	}
	if err := (&AttackPlan{Objective: "x", Target: "y", Phases: []AttackPhase{{Name: ""}}}).Validate(); err == nil {
		t.Fatalf("phase with empty name accepted")
	}
}

func TestFindingRejectsBadSeverity(t *testing.T) {
	ok := Finding{Title: "XSS", Severity: "high", Affected: "/q", Description: "reflected"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid finding rejected: %v", err)
	}
	if err := (&Finding{Title: "XSS", Severity: "urgent", Affected: "/q", Description: "d"}).Validate(); err == nil {
		t.Fatalf("bad severity accepted")
	}
	for _, missing := range []Finding{
		{Severity: "low", Affected: "a", Description: "d"},
		{Title: "t", Affected: "a", Description: "d"},
		{Title: "t", Severity: "low", Description: "d"},
		{Title: "t", Severity: "low", Affected: "a"},
	} {
		if err := missing.Validate(); err == nil {
			t.Fatalf("missing required field accepted: %+v", missing)
		}
	}
}

func TestIOCValidate(t *testing.T) {
	ok := IOCExtraction{Indicators: []Indicator{{Type: "ipv4", Value: "10.0.0.1"}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid ioc rejected: %v", err)
	}
	if err := (&IOCExtraction{}).Validate(); err == nil {
		t.Fatalf("empty indicators accepted")
	}
	if err := (&IOCExtraction{Indicators: []Indicator{{Type: "wat", Value: "x"}}}).Validate(); err == nil {
		t.Fatalf("bad indicator type accepted")
	}
	if err := (&IOCExtraction{Indicators: []Indicator{{Type: "domain", Value: ""}}}).Validate(); err == nil {
		t.Fatalf("empty indicator value accepted")
	}
}

func TestBinaryAssessmentValidate(t *testing.T) {
	ok := BinaryAssessment{Subject: "/usr/bin/foo", AssessmentType: "suid"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid assessment rejected: %v", err)
	}
	if err := (&BinaryAssessment{AssessmentType: "suid"}).Validate(); err == nil {
		t.Fatalf("missing subject accepted")
	}
	if err := (&BinaryAssessment{Subject: "s", AssessmentType: "wat"}).Validate(); err == nil {
		t.Fatalf("bad assessment_type accepted")
	}
	if err := (&BinaryAssessment{Subject: "s", AssessmentType: "binary", Platform: "solaris"}).Validate(); err == nil {
		t.Fatalf("bad platform accepted")
	}
	if err := (&BinaryAssessment{Subject: "s", AssessmentType: "binary", Exploitability: "maybe"}).Validate(); err == nil {
		t.Fatalf("bad exploitability accepted")
	}
}

func TestSliceLengthCapEnforced(t *testing.T) {
	big := make([]string, maxSliceLen+1)
	for i := range big {
		big[i] = "x"
	}
	tp := TargetProfile{Target: "x", AssetType: "host", Technologies: big}
	if err := tp.Validate(); err == nil {
		t.Fatalf("oversized technologies slice accepted")
	}
}

func TestValidateThroughGenerate(t *testing.T) {
	// A bad enum from the model must be rejected by Generate, proving the schema
	// wires into the primitive.
	s, _ := Lookup("finding")
	g := &fakeGen{replies: []string{
		`{"title":"t","severity":"urgent","affected":"a","description":"d"}`,
		`{"title":"t","severity":"high","affected":"a","description":"d"}`,
	}}
	out, err := Generate(context.Background(), g, "subject", s, Options{MaxRetries: 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), `"high"`) {
		t.Fatalf("expected corrected output, got %s", out)
	}
	_ = g
}
