package webanalysis

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestDiscoveredPasswordValuePreserved(t *testing.T) {
	for _, password := range []string{"weak", "fixture value with spaces!", "quote\"backtick`\nline", "'boundary'", "`boundary`"} {
		source := "const password=" + strconv.Quote(password) + ";"
		result, err := Analyze(context.Background(), input(source))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range Display(Snapshot{Findings: result.Findings}).Findings {
			data, err := json.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err = json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			if fields["value"] == password && fields["credential_type"] == "password" && f.Preview == strconv.Quote(password) {
				found = true
			}
		}
		if !found {
			t.Fatalf("exact discovered password missing for %q: %+v", password, result.Findings)
		}
	}
}

func TestDiscoveredTokenValuePreserved(t *testing.T) {
	value := "ghp_" + strings.Repeat("FixtureA1", 8)
	result, err := Analyze(context.Background(), input("const token="+strconv.Quote(value)+";"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range Display(Snapshot{Findings: result.Findings}).Findings {
		data, _ := json.Marshal(f)
		var fields map[string]any
		_ = json.Unmarshal(data, &fields)
		found = found || fields["value"] == value
	}
	if !found {
		t.Fatal("detected token lost its exact value")
	}
}

func TestCredentialEventEscapesControlsWithoutChangingValue(t *testing.T) {
	password := "fixture\x1b[31m\u009b\u202e\U0001f600\npassword"
	data, err := FindingEvent("task", Finding{Kind: "secret-candidate", Value: password})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range data {
		if value < 0x20 || value >= 0x7f {
			t.Fatal("terminal control or non-ASCII event byte")
		}
	}
	var event struct {
		Finding Finding `json:"finding"`
	}
	if err = json.Unmarshal(data, &event); err != nil || event.Finding.Value != password {
		t.Fatal("JSON escaping changed credential", err)
	}
}

func TestCredentialDetectionLimitsAndUnresolvedValues(t *testing.T) {
	result, err := Analyze(context.Background(), input("const password=unknownRuntimeValue;"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.Value != "" {
			t.Fatal("invented password")
		}
	}
	unit := SourceUnit{ID: ID("credential-json"), URL: "https://fixture.test/password"}
	encoded, _ := json.Marshal(map[string]string{"password": strings.Repeat("x", MaxCredentialValue+1)})
	findings, gaps := JSONCredentials(unit, "reader", encoded)
	if len(findings) != 0 || len(gaps) == 0 {
		t.Fatal("oversized credential silently truncated")
	}
	nested := `{"password":"fixture"}`
	for i := 0; i < 34; i++ {
		nested = `{"nested":` + nested + `}`
	}
	findings, gaps = JSONCredentials(unit, "reader", []byte(nested))
	if len(findings) != 0 || len(gaps) == 0 {
		t.Fatal("credential depth gap missing")
	}
}

func TestStaticallyResolvedPasswordExpressions(t *testing.T) {
	for _, source := range []string{`const password="weak"+"word";`, "const password=`weakword`;", `config.auth.password="weakword";`} {
		result, err := Analyze(context.Background(), input(source))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range result.Findings {
			found = found || f.Value == "weakword" && f.CredentialType == "password"
		}
		if !found {
			t.Fatal("known password expression lost", source, result.Findings)
		}
	}
}

func TestPasswordDOMValuesAndAbsentValues(t *testing.T) {
	unit := SourceUnit{ID: ID("password-dom"), URL: "https://fixture.test/login", Artifact: ID("artifact")}
	findings, gaps := HTMLCredentials(unit, "reader", []byte(`<input type="password" name="login" value="fixture &amp; password"><input name="password" placeholder="not a discovered value"><input type="password" value="">`))
	if len(findings) != 1 || len(gaps) != 0 || findings[0].Value != "fixture & password" || findings[0].CredentialType != "password" {
		t.Fatal("DOM password evidence lost or invented", findings, gaps)
	}
}

func TestCredentialSummaryBoundsWithoutMasking(t *testing.T) {
	findings := []Finding{}
	for i := 0; i < 4; i++ {
		findings = append(findings, Finding{Kind: "secret-candidate", Value: strings.Repeat("x", MaxCredentialValue)})
	}
	output := CredentialSummary(findings)
	if len(output) > 200000 || !strings.Contains(output, `"value":"`+strings.Repeat("x", MaxCredentialValue)+`"`) || !strings.Contains(output, "additional findings remain in the store") {
		t.Fatal("credential preview hid values or its coverage limit")
	}
}

func TestCredentialFieldAndFindingBounds(t *testing.T) {
	unit := SourceUnit{ID: ID("field-limits")}
	largePath := strings.Repeat("x", 4097)
	data, _ := json.Marshal(map[string]any{largePath: map[string]string{"password": "fixture"}})
	findings, gaps := JSONCredentials(unit, "reader", data)
	if len(findings) != 0 || len(gaps) == 0 {
		t.Fatal("unbounded credential path accepted")
	}
	fields := map[string]string{}
	for i := 0; i < 1001; i++ {
		fields["password_"+strconv.Itoa(i)] = "fixture"
	}
	data, _ = json.Marshal(fields)
	findings, gaps = JSONCredentials(unit, "reader", data)
	if len(findings) != 1000 || len(gaps) == 0 {
		t.Fatal("credential finding bound or gap missing", len(findings), gaps)
	}
}

func TestNamedSecretsDoNotRequirePasswordOrEntropy(t *testing.T) {
	for _, name := range []string{"apiKey", "CLIENT_SECRET", "signingKey", "privateKey", "DATABASE_URL", "accessToken"} {
		result, err := Analyze(context.Background(), input("const "+name+"=\"fixture\";"))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, finding := range result.Findings {
			found = found || finding.Name == name && finding.Value == "fixture"
		}
		if !found {
			t.Fatal("named secret missing", name, result.Findings)
		}
	}
}
