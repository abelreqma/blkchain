package main

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/webanalysis"
)

// vulnscan.go parses scanner JSON into eng.Vuln records, dropping any record that lacks an advisory id or a package name.

// maxScanBytes caps the scanner output a parser will decode.
const maxScanBytes = 32 << 20

// vulnScanners are the scanner names parseVulnScan accepts.
func vulnScanners() []string { return []string{"grype", "osv-scanner", "trivy"} }

// osvReport is the subset of osv-scanner's JSON output the parser reads.
type osvReport struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []osvAdvisory `json:"vulnerabilities"`
			Groups          []struct {
				IDs         []string `json:"ids"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

type osvAdvisory struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// fixedVersion returns the first fixed version the advisory records.
func (a osvAdvisory) fixedVersion() string {
	for _, af := range a.Affected {
		for _, r := range af.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

// cvss returns the first CVSS vector the advisory carries.
func (a osvAdvisory) cvss() string {
	for _, s := range a.Severity {
		if s.Score != "" {
			return s.Score
		}
	}
	return ""
}

// cvssBand maps a CVSS base score to its rating on the CVSS v3.1 severity scale, and "" for anything outside 0..10.
func cvssBand(score string) string {
	v, err := strconv.ParseFloat(strings.TrimSpace(score), 64)
	if err != nil || v < 0 || v > 10 {
		return ""
	}
	switch {
	case v >= 9.0:
		return "critical"
	case v >= 7.0:
		return "high"
	case v >= 4.0:
		return "medium"
	case v > 0:
		return "low"
	}
	return "none"
}

// trivyReport is the subset of trivy's JSON output the parser reads.
type trivyReport struct {
	ArtifactName string `json:"ArtifactName"`
	Trivy        struct {
		Version string `json:"Version"`
	} `json:"Trivy"`
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string               `json:"VulnerabilityID"`
			VendorIDs        []string             `json:"VendorIDs"`
			PkgName          string               `json:"PkgName"`
			InstalledVersion string               `json:"InstalledVersion"`
			FixedVersion     string               `json:"FixedVersion"`
			Severity         string               `json:"Severity"`
			Title            string               `json:"Title"`
			Description      string               `json:"Description"`
			PkgPath          string               `json:"PkgPath"`
			CVSS             map[string]trivyCVSS `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

type trivyCVSS struct {
	V3Vector string  `json:"V3Vector"`
	V3Score  float64 `json:"V3Score"`
}

// firstVector returns the vector of the lowest source key that carries one.
func firstVector(m map[string]trivyCVSS) string {
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if v.V3Vector != "" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	return m[keys[0]].V3Vector
}

// grypeReport is the subset of grype's JSON the parser reads; Target is decoded on its own because its shape varies by source.
type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID          string `json:"id"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
			Fix         struct {
				Versions []string `json:"versions"`
				State    string   `json:"state"`
			} `json:"fix"`
			CVSS []struct {
				Type    string `json:"type"`
				Version string `json:"version"`
				Vector  string `json:"vector"`
			} `json:"cvss"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			ID string `json:"id"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Type      string `json:"type"`
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
		} `json:"artifact"`
	} `json:"matches"`
	Source struct {
		Type   string          `json:"type"`
		Target json.RawMessage `json:"target"`
	} `json:"source"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor"`
}

// target returns the asset grype names: the string of a path source or the userInput of an image source.
func (r grypeReport) target() string {
	if len(r.Source.Target) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(r.Source.Target, &s) == nil {
		return s
	}
	var obj struct {
		UserInput string `json:"userInput"`
	}
	if json.Unmarshal(r.Source.Target, &obj) == nil {
		return obj.UserInput
	}
	return ""
}

// grypeVector returns the vector of the highest CVSS version the match carries.
func grypeVector(in []struct {
	Type    string `json:"type"`
	Version string `json:"version"`
	Vector  string `json:"vector"`
}) string {
	best, bestVer := "", ""
	for _, c := range in {
		if c.Vector == "" {
			continue
		}
		if best == "" || c.Version > bestVer {
			best, bestVer = c.Vector, c.Version
		}
	}
	return best
}

// truncateSummary bounds a scanner-supplied description and strips the control characters the store rejects.
func truncateSummary(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\x00' {
			return -1
		}
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}
	return s
}

// sanitizeField strips control characters the store rejects and bounds length.
func sanitizeField(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\x00' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		return s[:max]
	}
	return s
}

// vulnID derives the stable row id so a rescan updates in place.
func vulnID(scanner, asset, ecosystem, pkg, version, advisory string) string {
	return "cve:" + webanalysis.ID(scanner, asset, ecosystem, pkg, version, advisory)[:40]
}

// parseOSVScanner converts osv-scanner JSON into records, banding the group's base score when an advisory has no word rating.
func parseOSVScanner(out []byte, asset, scannerVersion string) ([]eng.Vuln, error) {
	if len(out) > maxScanBytes {
		return nil, errors.New("scanner output exceeds the size limit")
	}
	var r osvReport
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, err
	}
	var vulns []eng.Vuln
	for _, res := range r.Results {
		for _, p := range res.Packages {
			groupSeverity := map[string]string{}
			for _, g := range p.Groups {
				band := cvssBand(g.MaxSeverity)
				if band == "" {
					continue
				}
				for _, id := range g.IDs {
					groupSeverity[id] = band
				}
			}
			for _, a := range p.Vulnerabilities {
				if a.ID == "" || p.Package.Name == "" {
					continue
				}
				severity := a.DatabaseSpecific.Severity
				if severity == "" {
					severity = groupSeverity[a.ID]
				}
				vulns = append(vulns, eng.Vuln{
					ID:             vulnID("osv-scanner", asset, p.Package.Ecosystem, p.Package.Name, p.Package.Version, a.ID),
					Asset:          sanitizeField(asset, 512),
					Scanner:        "osv-scanner",
					ScannerVersion: sanitizeField(scannerVersion, 512),
					Advisory:       sanitizeField(a.ID, 128),
					Aliases:        boundedAliases(a.Aliases),
					Severity:       severity,
					CVSS:           sanitizeField(a.cvss(), 512),
					Package:        sanitizeField(p.Package.Name, 256),
					PackageVersion: sanitizeField(p.Package.Version, 512),
					Ecosystem:      sanitizeField(p.Package.Ecosystem, 512),
					FixedVersion:   sanitizeField(a.fixedVersion(), 512),
					Summary:        truncateSummary(a.Summary, 4096),
					Location:       sanitizeField(res.Source.Path, 512),
				})
			}
		}
	}
	return vulns, nil
}

// parseTrivy converts trivy JSON into records, preferring the report's own ArtifactName and Trivy.Version.
func parseTrivy(out []byte, asset, scannerVersion string) ([]eng.Vuln, error) {
	if len(out) > maxScanBytes {
		return nil, errors.New("scanner output exceeds the size limit")
	}
	var r trivyReport
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, err
	}
	if r.ArtifactName != "" {
		asset = r.ArtifactName
	}
	if r.Trivy.Version != "" {
		scannerVersion = r.Trivy.Version
	}
	var vulns []eng.Vuln
	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			if v.VulnerabilityID == "" || v.PkgName == "" {
				continue
			}
			summary := v.Title
			if summary == "" {
				summary = v.Description
			}
			location := v.PkgPath
			if location == "" {
				location = res.Target
			}
			vulns = append(vulns, eng.Vuln{
				ID:             vulnID("trivy", asset, res.Type, v.PkgName, v.InstalledVersion, v.VulnerabilityID),
				Asset:          sanitizeField(asset, 512),
				Scanner:        "trivy",
				ScannerVersion: sanitizeField(scannerVersion, 512),
				Advisory:       sanitizeField(v.VulnerabilityID, 128),
				Aliases:        boundedAliases(v.VendorIDs),
				Severity:       v.Severity,
				CVSS:           sanitizeField(firstVector(v.CVSS), 512),
				Package:        sanitizeField(v.PkgName, 256),
				PackageVersion: sanitizeField(v.InstalledVersion, 512),
				Ecosystem:      sanitizeField(res.Type, 512),
				FixedVersion:   sanitizeField(v.FixedVersion, 512),
				Summary:        truncateSummary(summary, 4096),
				Location:       sanitizeField(location, 512),
			})
		}
	}
	return vulns, nil
}

// localScanSource reports whether a report names scanner input rather than the assessed asset.
func localScanSource(target string) bool {
	target = strings.TrimRight(strings.TrimSpace(target), "/")
	switch target {
	case "", ".", "..", "dir:.", "/work":
		return true
	}
	for _, prefix := range []string{"dir:", "file:", "sbom:", "docker-archive:", "oci-archive:"} {
		if strings.HasPrefix(target, prefix) {
			return true
		}
	}
	return false
}

// parseGrype converts grype JSON into records, preferring the report's own source target and descriptor version.
func parseGrype(out []byte, asset, scannerVersion string) ([]eng.Vuln, error) {
	if len(out) > maxScanBytes {
		return nil, errors.New("scanner output exceeds the size limit")
	}
	var r grypeReport
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, err
	}
	// A scan directory names no asset, so the task's own target is kept instead.
	if t := r.target(); t != "" && !localScanSource(t) {
		asset = t
	}
	if v := r.Descriptor.Version; v != "" && v != "[not provided]" {
		scannerVersion = v
	}
	var vulns []eng.Vuln
	for _, m := range r.Matches {
		if m.Vulnerability.ID == "" || m.Artifact.Name == "" {
			continue
		}
		fixed := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixed = m.Vulnerability.Fix.Versions[0]
		}
		location := ""
		if len(m.Artifact.Locations) > 0 {
			location = m.Artifact.Locations[0].Path
		}
		aliases := make([]string, 0, len(m.RelatedVulnerabilities))
		for _, rel := range m.RelatedVulnerabilities {
			aliases = append(aliases, rel.ID)
		}
		vulns = append(vulns, eng.Vuln{
			ID:             vulnID("grype", asset, m.Artifact.Type, m.Artifact.Name, m.Artifact.Version, m.Vulnerability.ID),
			Asset:          sanitizeField(asset, 512),
			Scanner:        "grype",
			ScannerVersion: sanitizeField(scannerVersion, 512),
			Advisory:       sanitizeField(m.Vulnerability.ID, 128),
			Aliases:        boundedAliases(aliases),
			Severity:       m.Vulnerability.Severity,
			CVSS:           sanitizeField(grypeVector(m.Vulnerability.CVSS), 512),
			Package:        sanitizeField(m.Artifact.Name, 256),
			PackageVersion: sanitizeField(m.Artifact.Version, 512),
			Ecosystem:      sanitizeField(m.Artifact.Type, 512),
			FixedVersion:   sanitizeField(fixed, 512),
			Summary:        truncateSummary(m.Vulnerability.Description, 4096),
			Location:       sanitizeField(location, 512),
		})
	}
	return vulns, nil
}

// boundedAliases drops empty aliases and caps the list at what the store accepts.
func boundedAliases(in []string) []string {
	var out []string
	for _, a := range in {
		a = sanitizeField(a, 128)
		if a == "" {
			continue
		}
		out = append(out, a)
		if len(out) == 64 {
			break
		}
	}
	return out
}

// parseVulnScan dispatches on the scanner name.
func parseVulnScan(scanner string, out []byte, asset, scannerVersion string) ([]eng.Vuln, error) {
	switch scanner {
	case "osv-scanner":
		return parseOSVScanner(out, asset, scannerVersion)
	case "trivy":
		return parseTrivy(out, asset, scannerVersion)
	case "grype":
		return parseGrype(out, asset, scannerVersion)
	}
	return nil, errors.New("unknown scanner " + scanner + "; use " + strings.Join(vulnScanners(), ", "))
}
