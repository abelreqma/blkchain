package webanalysis

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

func FromObserved(e RequestExample) (Operation, error) {
	u, err := url.Parse(e.URL)
	if err != nil || u.Host == "" || u.User != nil {
		return Operation{}, errors.New("invalid observed URL")
	}
	o := Operation{Origin: u.Scheme + "://" + u.Host, Method: e.Method, Path: u.Path, Query: u.RawQuery, Protocol: "http", Validation: "attempted", Discoveries: []string{"observed"}, Roles: []string{e.Role}, Examples: []RequestExample{e}, Features: FeatureTags(u.Path), ContentType: e.Headers.Get("Content-Type")}
	if u.Scheme == "ws" || u.Scheme == "wss" {
		o.Protocol = "websocket"
	}
	if e.Status != 0 {
		o.Statuses = []int{e.Status}
		o.Validation = "response-observed"
		if e.Status == 401 || e.Status == 403 {
			o.Validation = "access-response"
		}
	}
	if e.Cached {
		o.Discoveries = append(o.Discoveries, "worker-cache")
		o.Validation = "cache-response-observed"
	}
	for k, vs := range u.Query() {
		for _, v := range vs {
			o.Parameters = append(o.Parameters, Parameter{Name: k, Field: "query." + k, Expression: v, Type: "string"})
		}
	}
	for k := range e.Headers {
		o.Parameters = append(o.Parameters, Parameter{Name: k, Field: "header." + k, Type: "string", Unresolved: Sensitive(k)})
	}
	for _, cookie := range strings.Split(e.Headers.Get("Cookie"), ";") {
		if name, _, ok := strings.Cut(strings.TrimSpace(cookie), "="); ok {
			o.Parameters = append(o.Parameters, Parameter{Name: name, Field: "cookie." + name, Type: "string", Unresolved: true})
		}
	}
	var body map[string]any
	if json.Unmarshal([]byte(e.Body), &body) == nil {
		for k, v := range body {
			typ := "unknown"
			switch v.(type) {
			case nil:
				typ = "null"
			case string:
				typ = "string"
			case float64:
				typ = "number"
			case bool:
				typ = "boolean"
			case map[string]any:
				typ = "object"
			case []any:
				typ = "array"
			}
			o.Parameters = append(o.Parameters, Parameter{Name: k, Field: "body." + k, Type: typ})
			if k == "query" {
				o.GraphQL, _ = v.(string)
				o.Variables = graphqlVariables(o.GraphQL)
			}
		}
	} else if strings.Contains(strings.ToLower(o.ContentType), "form-urlencoded") {
		if q, err := url.ParseQuery(e.Body); err == nil {
			for k := range q {
				o.Parameters = append(o.Parameters, Parameter{Name: k, Field: "body." + k, Type: "string"})
			}
		}
	}
	if UnsupportedObservedBody(o) {
		o.Unresolved = AddUnique(o.Unresolved, "body: unsupported observed representation")
	}
	o.ID = OperationID(o)
	return o, nil
}
func MatchesObserved(a, b Operation) bool {
	if a.Origin != b.Origin || a.Method != b.Method || a.Protocol != b.Protocol || a.GraphQL != b.GraphQL {
		return false
	}
	pattern := regexp.QuoteMeta(a.Path)
	pattern = regexp.MustCompile(`\\\{[^{}]+\\\}`).ReplaceAllString(pattern, `[^/]+`)
	r, e := regexp.Compile("^" + pattern + "$")
	if e != nil || !r.MatchString(b.Path) {
		return false
	}
	aq, _ := url.ParseQuery(a.Query)
	bq, _ := url.ParseQuery(b.Query)
	if len(aq) != len(bq) {
		return false
	}
	for k, v := range aq {
		bv, ok := bq[k]
		if !ok || len(v) != len(bv) {
			return false
		}
		for i, x := range v {
			if !strings.Contains(x, "{") && x != bv[i] {
				return false
			}
		}
	}
	return true
}
