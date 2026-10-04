package webanalysis

import (
	"net/http"
	"regexp"
	"strings"
)

func Technology(unit SourceUnit, source []byte, headers http.Header) []Finding {
	signals := []struct{ name, pattern string }{
		{"react", `(?:React\.(?:createElement|useState)|react-dom|node_modules/react/)`},
		{"vue", `(?:Vue\.(?:createApp|component)|node_modules/vue/|__VUE__)`},
		{"angular", `(?:angular\.(?:module|bootstrap)|@angular/core)`},
		{"next", `(?:__NEXT_DATA__|/_next/static/)`},
		{"webpack", `(?:__webpack_require__|webpackChunk|webpack://)`},
		{"vite", `(?:__vite__mapDeps|/@vite/client|import\.meta\.env)`},
	}
	out := []Finding{}
	for _, signal := range signals {
		match := regexp.MustCompile(signal.pattern).FindIndex(source)
		if match == nil {
			continue
		}
		before := source[:match[0]]
		line := strings.Count(string(before), "\n") + 1
		column := match[0]
		if i := strings.LastIndexByte(string(before), '\n'); i >= 0 {
			column = match[0] - i - 1
		}
		out = append(out, Finding{ID: ID(unit.ID, signal.name, "source-signal"), Kind: "technology", Detector: "source-signal", Confidence: "medium", Location: Location{Unit: unit.ID, Offset: unit.Offset + match[0], Line: line, Column: column}, Preview: signal.name + "; version unknown", Library: signal.name, Version: Version})
	}
	if powered := headers.Get("X-Powered-By"); powered != "" {
		out = append(out, Finding{ID: ID(unit.ID, "powered-by", powered), Kind: "technology", Detector: "response-header", Confidence: "low", Location: Location{Unit: unit.ID, Line: 1}, Preview: RedactText("X-Powered-By: " + powered + "; version unverified"), Version: Version})
	}
	return out
}
