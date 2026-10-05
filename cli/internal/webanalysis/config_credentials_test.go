package webanalysis

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestSecretNameClassificationBoundaries(t *testing.T) {
	for _, test := range []struct{ name, words, kind string }{
		{"API_KEY", "api key", "api-key"}, {"serviceApiKey", "service api key", "api-key"},
		{"JWTSigningKey", "jwt signing key", "signing-key"}, {"AWS_SECRET_ACCESS_KEY", "aws secret access key", "access-key"},
		{"DATABASE_URL", "database url", "connection-string"}, {"monkey", "monkey", ""}, {"tokenizer", "tokenizer", ""},
	} {
		if got := secretWords(test.name); got != test.words {
			t.Fatal("wrong normalized name", test.name, got)
		}
		if got := secretType(test.name); got != test.kind {
			t.Fatal("wrong secret type", test.name, got)
		}
	}
}

func TestExposedEnvironmentValuesAndPrivateKeyBytes(t *testing.T) {
	unit := SourceUnit{ID: ID("env-unit"), URL: "https://fixture.test/debug/env", Artifact: ID("env-artifact")}
	body := []byte("export API_KEY='short-key'\nCLIENT_SECRET=fixture+secret@value\nDATABASE_URL=postgres://fixture:fixture@db.test/db\nPORT=8000\nUNKNOWN_SECRET=${UNAVAILABLE}\n")
	findings, gaps := TextCredentials(unit, "reader", body)
	values := map[string]string{}
	for _, f := range findings {
		values[f.Name] = f.Value
		if !f.EnvironmentVariable || f.Role != "reader" || f.SourceURL != unit.URL || f.Expression == "" {
			t.Fatal("environment provenance missing", f)
		}
	}
	if len(values) != 4 || values["API_KEY"] != "short-key" || values["PORT"] != "8000" || values["CLIENT_SECRET"] != "fixture+secret@value" || values["DATABASE_URL"] != "postgres://fixture:fixture@db.test/db" || len(gaps) != 1 {
		t.Fatal("environment values lost or unresolved value invented", values, gaps)
	}
	key := "-----BEGIN PRIVATE KEY-----\nZml4dHVyZQ==\n-----END PRIVATE KEY-----"
	findings, gaps = TextCredentials(SourceUnit{ID: ID("key-unit"), URL: "https://fixture.test/key.pem"}, "reader", []byte(key+"\n"))
	if len(findings) != 1 || findings[0].Value != key || findings[0].CredentialType != "private-key" || len(gaps) != 0 {
		t.Fatal("private key bytes lost", findings, gaps)
	}
	if f, g := TextCredentials(unit, "reader", []byte(strings.Repeat("x", MaxCredentialValue+4097))); len(f) != 0 || len(g) == 0 {
		t.Fatal("configuration line limit missing")
	}
}

func TestJSONEnvironmentAndSecretFields(t *testing.T) {
	body := []byte(`{"api_key":"short-key","private_key":"fixture-private-key","database_url":"postgres://fixture:fixture@db.test/db","environment":{"PUBLIC_API_URL":"https://fixture.test/","PORT":"8000","ENABLED":false,"COUNTER":1000000000000000001}}`)
	findings, gaps := JSONCredentials(SourceUnit{ID: ID("json-env")}, "reader", body)
	values := map[string]string{}
	for _, f := range findings {
		values[f.Name] = f.Value
		if strings.HasPrefix(f.Name, "/environment/") && !f.EnvironmentVariable {
			t.Fatal("environment context lost")
		}
	}
	if len(values) != 7 || values["/api_key"] != "short-key" || values["/environment/COUNTER"] != "1000000000000000001" || values["/environment/ENABLED"] != "false" || len(gaps) != 0 {
		t.Fatal("JSON secret values lost", values, gaps)
	}
	encoded, _ := json.Marshal(map[string]string{"private_key": "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----"})
	if duplicate, _ := TextCredentials(SourceUnit{}, "reader", encoded); len(duplicate) != 0 {
		t.Fatal("JSON escape text was reported as another key")
	}
}

func TestEnvironmentReferenceIsNotReadFromRunner(t *testing.T) {
	t.Setenv("UNAVAILABLE_SECRET", "fixture-host-value")
	result, err := Analyze(context.Background(), input(`const apiKey=process.env.UNAVAILABLE_SECRET;`))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Gaps) == 0 {
		t.Fatal("unavailable environment value was not a gap")
	}
	for _, finding := range result.Findings {
		if finding.Value == "fixture-host-value" {
			t.Fatal("runner environment used as target evidence")
		}
	}
	result, err = Analyze(context.Background(), input(`process.env.API_KEY="target-key";const config={env:{PORT:"8000"}};`))
	if err != nil {
		t.Fatal(err)
	}
	exposed := map[string]bool{}
	for _, finding := range result.Findings {
		if finding.EnvironmentVariable {
			exposed[finding.Value] = true
		}
	}
	if !exposed["target-key"] || !exposed["8000"] {
		t.Fatal("given environment literals missing", result.Findings)
	}
}

func TestSensitiveHeadersAndHiddenInputs(t *testing.T) {
	unit := SourceUnit{ID: ID("header-unit")}
	findings, gaps := HeaderCredentials(unit, "reader", http.Header{"X-Api-Key": []string{"fixture-key"}, "Set-Cookie": []string{"session=fixture; HttpOnly"}, "Authorization": []string{"Bearer fixture"}})
	if len(findings) != 3 || len(gaps) != 0 {
		t.Fatal("sensitive headers missing", findings, gaps)
	}
	findings, gaps = HTMLCredentials(unit, "reader", []byte(`<input type="hidden" name="csrf_token" value="fixture-csrf"><input name="apiKey" value="fixture-api-key">`))
	if len(findings) != 2 || len(gaps) != 0 {
		t.Fatal("sensitive input values missing", findings, gaps)
	}
}
