package webcollect

import (
	"blkchain/cli/internal/webanalysis"
	"bytes"
	"encoding/json"
	"golang.org/x/net/html"
	"net/url"
	"strings"
)

type inlineSource struct {
	Kind, Name, Language string
	Offset               int
	Body                 []byte
}
type reference struct{ URL, Kind string }
type htmlResult struct {
	Base   string
	Inline []inlineSource
	Refs   []reference
	Gaps   []webanalysis.Gap
}

func parseHTML(body []byte, base string) htmlResult {
	out := htmlResult{}
	z := html.NewTokenizer(bytes.NewReader(body))
	offset := 0
	var scriptKind, scriptType, scriptName string
	var script bytes.Buffer
	scriptOffset := 0
	for {
		typ := z.Next()
		raw := append([]byte(nil), z.Raw()...)
		start := offset
		offset += len(raw)
		if typ == html.ErrorToken {
			if scriptKind != "" {
				out.Gaps = append(out.Gaps, webanalysis.Gap{Stage: "html", URL: base, Reason: "unterminated script element"})
			}
			break
		}
		if typ == html.TextToken && scriptKind != "" {
			if script.Len()+len(raw) <= webanalysis.MaxSource {
				script.Write(raw)
			}
			continue
		}
		t := z.Token()
		if typ == html.EndTagToken && t.Data == "script" && scriptKind != "" {
			if scriptKind == "importmap" {
				var v struct {
					Imports map[string]string            `json:"imports"`
					Scopes  map[string]map[string]string `json:"scopes"`
				}
				if json.Unmarshal(script.Bytes(), &v) == nil {
					for _, u := range v.Imports {
						out.Refs = append(out.Refs, reference{resolve(base, u), "module"})
					}
					for _, s := range v.Scopes {
						for _, u := range s {
							out.Refs = append(out.Refs, reference{resolve(base, u), "module"})
						}
					}
				}
			}
			out.Inline = append(out.Inline, inlineSource{Kind: scriptKind, Language: scriptType, Name: scriptName, Offset: scriptOffset, Body: append([]byte(nil), script.Bytes()...)})
			scriptKind = ""
			script.Reset()
			continue
		}
		if typ != html.StartTagToken && typ != html.SelfClosingTagToken {
			continue
		}
		attrs := map[string]string{}
		for _, at := range t.Attr {
			attrs[at.Key] = at.Val
			if strings.HasPrefix(at.Key, "on") && len(at.Key) > 2 {
				out.Inline = append(out.Inline, inlineSource{Kind: "event-handler", Language: "javascript", Name: t.Data + "." + at.Key, Offset: start, Body: []byte(at.Val)})
			}
		}
		switch t.Data {
		case "base":
			if u := resolve(base, attrs["href"]); u != "" {
				base = u
			}
		case "script":
			kind := "inline-script"
			lang := "javascript"
			mt := strings.ToLower(attrs["type"])
			if mt == "importmap" {
				kind = "importmap"
				lang = "json"
			} else if strings.Contains(mt, "json") {
				kind = "data-script"
				lang = "json"
			} else if mt != "" && mt != "module" && !strings.Contains(mt, "javascript") && !strings.Contains(mt, "ecmascript") {
				kind = "data-script"
				lang = "text"
			}
			if src := attrs["src"]; src != "" {
				out.Refs = append(out.Refs, reference{resolve(base, src), "script"})
			} else {
				scriptKind = kind
				scriptType = lang
				scriptName = attrs["id"]
				scriptOffset = offset
				script.Reset()
			}
		case "a":
			out.Refs = append(out.Refs, reference{resolve(base, attrs["href"]), "page"})
		case "iframe":
			out.Refs = append(out.Refs, reference{resolve(base, attrs["src"]), "frame"})
		case "link":
			rel := attrs["rel"]
			if rel == "modulepreload" || rel == "preload" && attrs["as"] == "script" {
				out.Refs = append(out.Refs, reference{resolve(base, attrs["href"]), "module"})
			}
			if rel == "manifest" {
				out.Refs = append(out.Refs, reference{resolve(base, attrs["href"]), "manifest"})
			}
		}
		if len(out.Inline)+len(out.Refs) > 2000 {
			out.Gaps = append(out.Gaps, webanalysis.Gap{Stage: "html", URL: base, Reason: "HTML discovery limit"})
			break
		}
	}
	out.Base = base
	return out
}
func resolve(base, ref string) string {
	if ref == "" || strings.ContainsAny(ref, "\x00\r\n") {
		return ""
	}
	b, e := url.Parse(base)
	u, e2 := url.Parse(ref)
	if e != nil || e2 != nil {
		return ""
	}
	u = b.ResolveReference(u)
	if u.Scheme != "http" && u.Scheme != "https" || u.User != nil {
		return ""
	}
	return u.String()
}
