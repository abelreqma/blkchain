package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"blkchain/cli/internal/retrieval"
)

const (
	nvdBaseURL          = "https://services.nvd.nist.gov"
	nvdSource           = "nvd"
	nvdMaxResponseBytes = 4 << 20
	nvdEvidenceMaxChars = 1200
)

var nvdHTTPClient = &http.Client{
	Timeout:       15 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

var nvdLookup = lookupNVD

type nvdText struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetric struct {
	Source string `json:"source"`
	Type   string `json:"type"`
	Data   struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

type nvdNode struct {
	CPEMatch []struct {
		Vulnerable            bool   `json:"vulnerable"`
		Criteria              string `json:"criteria"`
		VersionStartIncluding string `json:"versionStartIncluding"`
		VersionStartExcluding string `json:"versionStartExcluding"`
		VersionEndIncluding   string `json:"versionEndIncluding"`
		VersionEndExcluding   string `json:"versionEndExcluding"`
	} `json:"cpeMatch"`
	Children []nvdNode `json:"children"`
}

type nvdRecord struct {
	ID           string    `json:"id"`
	Status       string    `json:"vulnStatus"`
	Published    string    `json:"published"`
	LastModified string    `json:"lastModified"`
	Descriptions []nvdText `json:"descriptions"`
	Metrics      struct {
		V40 []nvdMetric `json:"cvssMetricV40"`
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []nvdText `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Nodes []nvdNode `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
}

func lookupNVD(ctx context.Context, id string) ([]retrieval.Result, error) {
	return lookupNVDAt(ctx, nvdBaseURL, id)
}

func lookupNVDAt(ctx context.Context, baseURL, id string) ([]retrieval.Result, error) {
	if len(id) > 64 || !cveQueryPattern.MatchString(id) || cveQueryPattern.FindString(id) != id {
		return nil, errors.New("nvd: invalid CVE id")
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/rest/json/cves/2.0?" + url.Values{"cveId": {id}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("nvd: invalid request")
	}
	req.Header.Set("User-Agent", "blkChain/1.0")
	if key := strings.TrimSpace(os.Getenv("NVD_API_KEY")); key != "" {
		req.Header.Set("apiKey", key)
	}
	resp, err := nvdHTTPClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("nvd: request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, nvdMaxResponseBytes+1))
	if err != nil {
		return nil, errors.New("nvd: cannot read response")
	}
	if len(data) > nvdMaxResponseBytes {
		return nil, errors.New("nvd: response exceeds size limit")
	}
	var payload struct {
		TotalResults    int `json:"totalResults"`
		Vulnerabilities []struct {
			CVE nvdRecord `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, errors.New("nvd: invalid response")
	}
	if payload.TotalResults != 1 || len(payload.Vulnerabilities) != 1 || payload.Vulnerabilities[0].CVE.ID != id {
		return nil, errors.New("nvd: CVE not found in response")
	}
	record := payload.Vulnerabilities[0].CVE
	link := "https://nvd.nist.gov/vuln/detail/" + id
	summary, details := nvdEvidence(record)
	return []retrieval.Result{
		{ID: id + ":summary", Score: 1, Payload: retrieval.Payload{Source: nvdSource, Path: link, Section: id + " summary", Type: "cve", Text: summary}},
		{ID: id + ":details", Score: 1, Payload: retrieval.Payload{Source: nvdSource, Path: link, Section: id + " applicability and references", Type: "cve", Text: details}},
	}, nil
}

func nvdEvidence(record nvdRecord) (string, string) {
	var summary, details strings.Builder
	fmt.Fprintf(&summary, "NVD record %s. Status: %s. Published: %s. Last modified: %s.\n", record.ID, record.Status, record.Published, record.LastModified)
	for _, group := range [][]nvdMetric{record.Metrics.V40, record.Metrics.V31, record.Metrics.V30, record.Metrics.V2} {
		if len(group) == 0 {
			continue
		}
		metric := group[0]
		for _, m := range group {
			if m.Type == "Primary" && m.Source == "nvd@nist.gov" {
				metric = m
				break
			}
		}
		fmt.Fprintf(&summary, "CVSS: %.1f %s %s (source: %s).\n", metric.Data.BaseScore, metric.Data.BaseSeverity, metric.Data.VectorString, metric.Source)
		break
	}
	weaknessCount := 0
	for _, weakness := range record.Weaknesses {
		for _, d := range weakness.Description {
			if d.Lang == "en" && weaknessCount < 4 {
				fmt.Fprintf(&summary, "Weakness: %s.\n", capRunes(d.Value, 100))
				weaknessCount++
				break
			}
		}
	}
	for _, d := range record.Descriptions {
		if d.Lang == "en" {
			fmt.Fprintf(&summary, "Description: %s\n", capRunes(d.Value, 850))
			break
		}
	}
	count := 0
	for _, ref := range record.References {
		if count == 4 {
			break
		}
		if allowedSearchURL(ref.URL, nil) {
			fmt.Fprintf(&details, "Reference (%s): %s\n", capRunes(strings.Join(ref.Tags, ", "), 80), capRunes(ref.URL, 250))
			count++
		}
	}
	count = 0
	matches := make([]string, 0, 4)
	var writeNode func(nvdNode, int)
	writeNode = func(node nvdNode, depth int) {
		if depth > 5 {
			return
		}
		for _, match := range node.CPEMatch {
			if !match.Vulnerable || count >= 4 {
				continue
			}
			matches = append(matches, fmt.Sprintf("Vulnerable CPE match (check configuration logic): %s; versions: start including %s, start excluding %s, end including %s, end excluding %s.\n",
				capRunes(match.Criteria, 160), match.VersionStartIncluding, match.VersionStartExcluding, match.VersionEndIncluding, match.VersionEndExcluding))
			count++
		}
		for _, child := range node.Children {
			if count < 4 {
				writeNode(child, depth+1)
			}
		}
	}
	for _, config := range record.Configurations {
		for _, node := range config.Nodes {
			if count < 4 {
				writeNode(node, 0)
			}
		}
	}
	if len(matches) > 3 {
		details.WriteString("NVD lists multiple product matches; inspect the complete configuration logic and vendor advisory before applying a version range.\n")
	} else {
		for _, match := range matches {
			details.WriteString(match)
		}
	}
	return nvdCapText(summary.String()), nvdCapText(details.String())
}

func nvdCapText(value string) string {
	runes := []rune(value)
	if len(runes) <= nvdEvidenceMaxChars {
		return value
	}
	const marker = "\n[truncated; open NVD source for the full record]"
	return string(runes[:nvdEvidenceMaxChars-len([]rune(marker))]) + marker
}
