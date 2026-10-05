package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNVDLookupReturnsBoundedEvidence(t *testing.T) {
	t.Setenv("NVD_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/json/cves/2.0" || r.URL.Query().Get("cveId") != "CVE-2021-44228" {
			t.Errorf("NVD request = %s", r.URL.String())
		}
		if r.Header.Get("apiKey") != "test-key" {
			t.Error("NVD API key header missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228","vulnStatus":"Analyzed","published":"2021-12-10T10:15:09.143","lastModified":"2024-11-03T20:15:00.000","descriptions":[{"lang":"en","value":"Apache Log4j2 JNDI lookup vulnerability."}],"metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"baseScore":10,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:L"}}]},"weaknesses":[{"description":[{"lang":"en","value":"CWE-502"}]}],"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*","versionEndExcluding":"2.16.0"}]}]}],"references":[{"url":"https://example.org/advisory","tags":["Vendor Advisory"]},{"url":"https://example.org/poc","tags":["Exploit"]}]}}]}`))
	}))
	defer srv.Close()

	results, err := lookupNVDAt(context.Background(), srv.URL, "CVE-2021-44228")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Payload.Source != "nvd" || results[0].Payload.Path != "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" {
		t.Fatalf("NVD results = %+v", results)
	}
	combined := results[0].Payload.Text + results[1].Payload.Text
	for _, want := range []string{"Apache Log4j2", "CVSS:3.1/AV:N/AC:L", "CWE-502", "2.16.0", "https://example.org/poc"} {
		if !strings.Contains(combined, want) {
			t.Errorf("NVD evidence missing %q: %s", want, combined)
		}
	}
	for _, result := range results {
		if len(result.Payload.Text) > nvdEvidenceMaxChars {
			t.Fatalf("NVD evidence length = %d", len(result.Payload.Text))
		}
	}
}

func TestNVDEvidenceDoesNotPresentPartialCPEListAsApplicability(t *testing.T) {
	var record nvdRecord
	if err := json.Unmarshal([]byte(`{"id":"CVE-2024-1234","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"product-one"},{"vulnerable":true,"criteria":"product-two"},{"vulnerable":true,"criteria":"product-three"},{"vulnerable":true,"criteria":"product-four"}]}]}]}`), &record); err != nil {
		t.Fatal(err)
	}
	_, details := nvdEvidence(record)
	if !strings.Contains(details, "multiple product matches") || strings.Contains(details, "product-one") {
		t.Errorf("partial CPE list presented as applicability: %s", details)
	}
}

func TestNVDEvidenceMarksTruncation(t *testing.T) {
	record := nvdRecord{ID: "CVE-2024-1234", Status: strings.Repeat("s", 500), Descriptions: []nvdText{{Lang: "en", Value: strings.Repeat("x", 4000)}}}
	summary, _ := nvdEvidence(record)
	if len(summary) > nvdEvidenceMaxChars || !strings.Contains(summary, "[truncated") {
		t.Errorf("NVD summary lacks a truncation marker: len=%d tail=%q", len(summary), summary[max(0, len(summary)-80):])
	}
}

func TestNVDLookupRejectsInvalidIDAndRedirect(t *testing.T) {
	if _, err := lookupNVDAt(context.Background(), "https://services.nvd.nist.gov", "CVE-2021-44228&x=y"); err == nil {
		t.Fatal("accepted invalid CVE id")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/secret", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := lookupNVDAt(context.Background(), srv.URL, "CVE-2021-44228"); err == nil {
		t.Fatal("followed NVD redirect")
	}
}

func TestNVDLookupRejectsOversizedAndMismatchedResponses(t *testing.T) {
	for _, body := range []string{
		`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}]}`,
		strings.Repeat("x", nvdMaxResponseBytes+1),
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		_, err := lookupNVDAt(context.Background(), srv.URL, "CVE-2021-44228")
		srv.Close()
		if err == nil {
			t.Fatal("accepted invalid NVD response")
		}
	}
}

func TestNVDLookupWithoutKeyAndHTTPError(t *testing.T) {
	t.Setenv("NVD_API_KEY", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") != "" {
			t.Error("sent an API key when none was configured")
		}
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("private response token"))
	}))
	defer srv.Close()
	_, err := lookupNVDAt(context.Background(), srv.URL, "CVE-2021-44228")
	if err == nil || !strings.Contains(err.Error(), "HTTP 429") || strings.Contains(err.Error(), "private response token") {
		t.Fatalf("NVD HTTP error = %v", err)
	}
}
