package webcollect

import (
	"blkchain/cli/internal/webanalysis"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type mapSection struct {
	Offset struct{ Line, Column int }
	Map    json.RawMessage
	URL    string
}
type sourceMap struct {
	Version        int
	SourceRoot     string `json:"sourceRoot"`
	Sources        []string
	SourcesContent []*string `json:"sourcesContent"`
	Names          []string
	Mappings       string
	Sections       []mapSection
}

var mapComment = regexp.MustCompile(`(?m)[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)`)

func mapReferences(a webanalysis.Artifact, b []byte) []string {
	out := []string{}
	if a.SourceMap != "" && !strings.HasPrefix(a.SourceMap, "data:") {
		out = webanalysis.AddUnique(out, resolve(a.FinalURL, a.SourceMap))
	}
	for _, m := range mapComment.FindAllSubmatch(b, 4) {
		ref := string(m[1])
		if !strings.HasPrefix(ref, "data:") {
			out = webanalysis.AddUnique(out, resolve(a.FinalURL, ref))
		}
	}
	for _, h := range []string{"SourceMap", "X-SourceMap"} {
		if v := a.Headers.Get(h); v != "" {
			out = webanalysis.AddUnique(out, resolve(a.FinalURL, v))
		}
	}
	if len(out) == 0 {
		u, e := url.Parse(a.FinalURL)
		if e == nil && strings.HasSuffix(u.Path, ".js") {
			u.Path += ".map"
			out = append(out, u.String())
		}
	}
	return out
}
func embeddedMaps(b []byte) ([][]byte, error) {
	out := [][]byte{}
	for _, m := range mapComment.FindAllSubmatch(b, 4) {
		ref := string(m[1])
		if !strings.HasPrefix(ref, "data:") {
			continue
		}
		head, data, ok := strings.Cut(ref, ",")
		if !ok || len(data) > webanalysis.MaxSource*2 {
			return out, errors.New("embedded map limit")
		}
		var decoded []byte
		var e error
		if strings.HasSuffix(head, ";base64") {
			decoded, e = base64.StdEncoding.DecodeString(data)
		} else {
			var s string
			s, e = url.PathUnescape(data)
			decoded = []byte(s)
		}
		if e != nil || len(decoded) > webanalysis.MaxSource {
			return out, errors.New("invalid or oversized embedded map")
		}
		out = append(out, decoded)
	}
	return out, nil
}
func (s *Service) sourceMap(ctx context.Context, a webanalysis.Artifact, b []byte, depth int) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	sources, total := 0, 0
	var walk func([]byte, int, int, int) error
	walk = func(b []byte, n, line, col int) error {
		if n > 8 || ctx.Err() != nil {
			return errors.New("source map traversal limit")
		}
		var m sourceMap
		if json.Unmarshal(b, &m) != nil || m.Version != 3 {
			return errors.New("invalid source map version or structure")
		}
		if len(m.Sources) > 1000 || len(m.Sections) > 100 || len(m.SourcesContent) > len(m.Sources) || len(m.Mappings) > webanalysis.MaxSource {
			return errors.New("source map expansion limit")
		}
		for _, section := range m.Sections {
			if section.Offset.Line < 0 || section.Offset.Column < 0 {
				return errors.New("invalid source map offset")
			}
			sectionColumn := section.Offset.Column
			if section.Offset.Line == 0 {
				sectionColumn += col
			}
			if section.URL != "" {
				s.enqueue(ctx, frontier{MapLine: line + section.Offset.Line, MapColumn: sectionColumn, URL: resolve(a.FinalURL, section.URL), Kind: "sourcemap", DocumentURL: a.DocumentURL, Parent: a.ID, Depth: depth + 1, Timestamp: a.CapturedAt})
			}
			if len(section.Map) > 0 {
				if e := walk(section.Map, n+1, line+section.Offset.Line, sectionColumn); e != nil {
					return e
				}
			}
		}
		mappings, e := parseMappings(m.Mappings, len(m.Sources))
		if e != nil {
			return e
		}
		for i, name := range m.Sources {
			sources++
			if sources > 1000 {
				return errors.New("source map source limit")
			}
			logical := name
			ref := strings.TrimRight(m.SourceRoot, "/") + "/" + name
			if m.SourceRoot == "" {
				ref = name
			}
			u := resolve(a.FinalURL, ref)
			loc := webanalysis.Location{Unit: a.ID, Line: line + 1, Column: col}
			if first, ok := mappings[i]; ok {
				loc.Line = first[0].GeneratedLine + line
				loc.Column = first[0].GeneratedColumn
				if first[0].GeneratedLine == 1 {
					loc.Column += col
				}
			}
			if i >= len(m.SourcesContent) || m.SourcesContent[i] == nil {
				if u != "" {
					s.enqueue(ctx, frontier{URL: u, Kind: "original-source", DocumentURL: a.DocumentURL, Parent: a.ID, Depth: depth + 1, Timestamp: a.CapturedAt})
				} else {
					s.gap("sourcemap", logical, "missing original content; logical or local-file source is not fetched")
				}
				continue
			}
			data := []byte(*m.SourcesContent[i])
			total += len(data)
			if total > 16<<20 || len(data) > webanalysis.MaxSource {
				return errors.New("source map decoded byte limit")
			}
			originalURL := a.FinalURL
			if u != "" {
				originalURL = u
			}
			child, e := s.Store.SaveWebArtifact(ctx, webanalysis.Artifact{DocumentURL: a.DocumentURL, Kind: "original-source", URL: originalURL, FinalURL: originalURL, Role: a.Role, Complete: true, Parents: []string{a.ID}, CapturedAt: a.CapturedAt}, data)
			if e != nil {
				return e
			}
			lang := "javascript"
			if strings.HasSuffix(name, ".tsx") {
				lang = "tsx"
			} else if strings.HasSuffix(name, ".ts") {
				lang = "typescript"
			} else if strings.HasSuffix(name, ".jsx") {
				lang = "jsx"
			}
			unit := webanalysis.SourceUnit{ID: webanalysis.ID(child.ID, "map", logical), Artifact: child.ID, Hash: child.Hash, DocumentURL: a.DocumentURL, URL: originalURL, Name: logical, Language: lang, Kind: "original-source", Original: &loc, Transformations: []string{"source-map-v3"}}
			unit.Mappings = mappings[i]
			for j := range unit.Mappings {
				if unit.Mappings[j].GeneratedLine == 1 {
					unit.Mappings[j].GeneratedColumn += col
				}
				unit.Mappings[j].GeneratedLine += line
			}
			result, e := s.Parse(ctx, webanalysis.Input{Unit: unit, Source: data, Role: a.Role, Historical: a.CapturedAt != ""})
			if e != nil {
				s.gap("parser", logical, "recovered source parse failed")
				continue
			}
			if e = s.persist(ctx, result); e != nil {
				return e
			}
			for _, d := range result.Dependencies {
				if u := resolve(originalURL, d.URL); u != "" {
					s.enqueue(ctx, frontier{URL: u, Kind: "script", DocumentURL: a.DocumentURL, Parent: child.ID, Depth: depth + 1, Timestamp: a.CapturedAt})
				}
			}
		}
		return nil
	}
	return walk(b, 0, a.MapLine, a.MapColumn)
}

const vlqAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func parseMappings(s string, sourceCount int) (map[int][]webanalysis.Mapping, error) {
	out := map[int][]webanalysis.Mapping{}
	source, originalLine, originalColumn := 0, 0, 0
	segments := 0
	for line, raw := range strings.Split(s, ";") {
		column := 0
		for _, segment := range strings.Split(raw, ",") {
			if segment == "" {
				continue
			}
			segments++
			if segments > 200000 {
				return nil, errors.New("source map segment limit")
			}
			v, e := vlq(segment)
			if e != nil || len(v) != 1 && len(v) != 4 && len(v) != 5 {
				return nil, errors.New("invalid source map VLQ")
			}
			column += v[0]
			if column < 0 {
				return nil, errors.New("negative generated column")
			}
			if len(v) >= 4 {
				source += v[1]
				originalLine += v[2]
				originalColumn += v[3]
				if source < 0 || source >= sourceCount || originalLine < 0 || originalColumn < 0 {
					return nil, errors.New("invalid source map source index")
				}
				if len(out[source]) >= 4096 {
					return nil, errors.New("source mapping record limit")
				}
				out[source] = append(out[source], webanalysis.Mapping{GeneratedLine: line + 1, GeneratedColumn: column, OriginalLine: originalLine + 1, OriginalColumn: originalColumn, Source: source})
			}
		}
	}
	return out, nil
}
func vlq(s string) ([]int, error) {
	out := []int{}
	value, shift := 0, 0
	for _, r := range s {
		v := strings.IndexRune(vlqAlphabet, r)
		if v < 0 || shift > 25 {
			return nil, errors.New("invalid VLQ")
		}
		value |= (v & 31) << shift
		if v&32 != 0 {
			shift += 5
			continue
		}
		n := value >> 1
		if value&1 != 0 {
			n = -n
		}
		out = append(out, n)
		value, shift = 0, 0
		if len(out) > 5 {
			return nil, errors.New("VLQ field limit")
		}
	}
	if shift != 0 {
		return nil, errors.New("incomplete VLQ")
	}
	return out, nil
}
