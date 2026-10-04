package webanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type RetireLibrary struct {
	Extractors struct {
		Filecontent, Filename, URI []string
		Hashes                     map[string]string
	}
	Vulnerabilities []struct {
		Below, AtOrAbove string
		Severity         string
		Identifiers      map[string]any
	}
}

func ScanRetire(ctx context.Context, unit SourceUnit, source, repository []byte, snapshot string) ([]Finding, []Gap, error) {
	if len(repository) > 4<<20 || len(source) > MaxSource {
		return nil, nil, errors.New("library analysis input limit")
	}
	var libs map[string]RetireLibrary
	if json.Unmarshal(repository, &libs) != nil || len(libs) > 1500 {
		return nil, nil, errors.New("invalid advisory repository")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	findings := []Finding{}
	gaps := []Gap{}
	keys := []string{}
	for k := range libs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	patterns := 0
	for _, name := range keys {
		if ctx.Err() != nil {
			gaps = append(gaps, Gap{Stage: "libraries", Reason: "scanner time budget exhausted"})
			break
		}
		lib := libs[name]
		version := ""
		offset := 0
		signal := ""
		inputs := []struct {
			patterns []string
			text     string
			kind     string
		}{{lib.Extractors.Filecontent, string(source), "filecontent"}, {lib.Extractors.Filename, unit.URL, "filename"}, {lib.Extractors.URI, unit.URL, "uri"}}
		for _, input := range inputs {
			for _, pattern := range input.patterns {
				patterns++
				if patterns > 5000 || len(pattern) > 4096 {
					gaps = append(gaps, Gap{Stage: "libraries", Reason: "advisory pattern limit"})
					break
				}
				pattern = strings.ReplaceAll(pattern, "\u00a7\u00a7version\u00a7\u00a7", `[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?`)
				r, e := regexp.Compile(pattern)
				if e != nil {
					if len(gaps) < 20 {
						gaps = append(gaps, Gap{Stage: "libraries", Reason: "unsupported Retire extractor: " + name})
					}
					continue
				}
				indexes := r.FindStringSubmatchIndex(input.text)
				if len(indexes) >= 4 && indexes[2] >= 0 {
					version = input.text[indexes[2]:indexes[3]]
					offset = indexes[0]
					signal = input.kind
					break
				}
			}
			if version != "" {
				break
			}
		}
		if version == "" {
			continue
		}
		loc := Location{Unit: unit.ID, Offset: offset, Line: 1}
		if signal == "filecontent" {
			loc.Line = strings.Count(string(source[:offset]), "\n") + 1
		}
		findings = append(findings, Finding{ID: ID(unit.ID, name, version, "retire"), Kind: "library", Detector: "retire-local-" + signal, Confidence: "high", Location: loc, Preview: name + " " + version, Version: Version, Library: name, LibraryVersion: version, Snapshot: snapshot})
		for _, v := range lib.Vulnerabilities {
			before, ok := compareVersion(version, v.Below)
			if !ok {
				if len(gaps) < 20 {
					gaps = append(gaps, Gap{Stage: "libraries", Reason: "unsupported advisory version range: " + name})
				}
				continue
			}
			if before >= 0 {
				continue
			}
			if v.AtOrAbove != "" {
				above, ok := compareVersion(version, v.AtOrAbove)
				if !ok || above < 0 {
					continue
				}
			}
			id, _ := json.Marshal(v.Identifiers)
			kind := "library-vulnerability"
			summary, _ := v.Identifiers["summary"].(string)
			if strings.Contains(strings.ToLower(summary), "end-of-life") || strings.Contains(strings.ToLower(summary), "outdated") {
				kind = "library-outdated"
			}
			findings = append(findings, Finding{ID: ID(unit.ID, name, version, string(id)), Kind: kind, Detector: "retire-local-range", Confidence: "high", Location: loc, Preview: RedactText(summary), Version: Version, Library: name, LibraryVersion: version, Advisory: string(id), Snapshot: snapshot})
		}
	}
	return findings, gaps, nil
}
func compareVersion(a, b string) (int, bool) {
	parse := func(s string) ([3]int, string, bool) {
		var v [3]int
		s = strings.TrimPrefix(s, "v")
		s = strings.Split(s, "+")[0]
		base, pre, _ := strings.Cut(s, "-")
		parts := strings.Split(base, ".")
		if len(parts) < 2 || len(parts) > 3 {
			return v, "", false
		}
		for i, p := range parts {
			n, e := strconv.Atoi(p)
			if e != nil || n < 0 {
				return v, "", false
			}
			v[i] = n
		}
		return v, pre, true
	}
	av, ap, aok := parse(a)
	bv, bp, bok := parse(b)
	if !aok || !bok {
		return 0, false
	}
	for i := range av {
		if av[i] < bv[i] {
			return -1, true
		}
		if av[i] > bv[i] {
			return 1, true
		}
	}
	if ap == bp {
		return 0, true
	}
	if ap == "" {
		return 1, true
	}
	if bp == "" {
		return -1, true
	}
	as, bs := strings.Split(ap, "."), strings.Split(bp, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] == bs[i] {
			continue
		}
		ai, ae := strconv.Atoi(as[i])
		bi, be := strconv.Atoi(bs[i])
		if ae == nil && be == nil {
			if ai < bi {
				return -1, true
			}
			return 1, true
		}
		if ae == nil {
			return -1, true
		}
		if be == nil {
			return 1, true
		}
		if as[i] < bs[i] {
			return -1, true
		}
		return 1, true
	}
	if len(as) < len(bs) {
		return -1, true
	}
	return 1, true
}
func AdvisorySnapshot(date, revision, hash string) string {
	return fmt.Sprintf("%s revision=%s sha256=%s", date, revision, hash)
}
