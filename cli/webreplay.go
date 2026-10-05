package main

import (
	"blkchain/cli/internal/webacquire"
	"blkchain/cli/internal/webanalysis"
	"encoding/json"
	"errors"
	"golang.org/x/net/http/httpguts"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var webReplayMethod = regexp.MustCompile(`^(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)$`)

func webReplayRequest(op webanalysis.Operation, values map[string]string) (webAPIRequest, error) {
	out := webAPIRequest{Method: op.Method}
	if webanalysis.UnsupportedObservedBody(op) {
		return out, errors.New("structured replay cannot represent this body; select a stored example with --example")
	}
	if op.Protocol != "http" || !webReplayMethod.MatchString(op.Method) {
		return out, errors.New("unsupported replay method or protocol")
	}
	for _, unresolved := range op.Unresolved {
		if !strings.HasPrefix(unresolved, "URL expression:") {
			return out, errors.New("replay signature requires runtime resolution")
		}
	}
	substitute := func(s string, escape func(string) string) (string, error) {
		missing := false
		s = webPlaceholder.ReplaceAllStringFunc(s, func(m string) string {
			v, ok := values[m[1:len(m)-1]]
			if !ok {
				missing = true
			}
			return escape(v)
		})
		if missing || strings.ContainsAny(s, "\r\n\x00") {
			return "", errors.New("unresolved or invalid replay parameter")
		}
		return s, nil
	}
	path, e := substitute(op.Path, url.PathEscape)
	if e != nil {
		return out, e
	}
	query, e := url.ParseQuery(op.Query)
	if e != nil {
		return out, e
	}
	plain := func(s string) string { return s }
	for k, vs := range query {
		for i, v := range vs {
			query[k][i], e = substitute(v, plain)
			if e != nil {
				return out, e
			}
		}
	}
	headers := map[string]string{}
	body := map[string]any{}
	for _, p := range op.Parameters {
		v, provided := values[p.Name]
		if !provided {
			v = p.Expression
			if v == "" {
				v = p.Default
			}
		}
		if strings.HasPrefix(p.Field, "cookie.") {
			continue
		}
		if strings.HasPrefix(p.Field, "header.") {
			if webanalysis.Sensitive(p.Field) {
				continue
			}
			if v != "" {
				v, e = substitute(v, plain)
				if e != nil {
					return out, e
				}
				headers[strings.TrimPrefix(p.Field, "header.")] = v
			}
		}
		if strings.HasPrefix(p.Field, "query.") {
			key := strings.TrimPrefix(p.Field, "query.")
			if _, exists := query[key]; !exists || provided {
				v, e = substitute(v, plain)
				if e != nil {
					return out, e
				}
				query.Set(key, v)
			}
		}
		if strings.HasPrefix(p.Field, "body.") {
			key := strings.TrimPrefix(p.Field, "body.")
			if op.GraphQL != "" && (key == "query" || key == "variables") {
				continue
			}
			if !provided && (p.Unresolved || v == "") {
				return out, errors.New("replay body parameter missing")
			}
			v, e = substitute(v, plain)
			if e != nil {
				return out, e
			}
			var typed any = v
			switch p.Type {
			case "number", "boolean", "true", "false", "null", "object", "array":
				if json.Unmarshal([]byte(v), &typed) != nil {
					return out, errors.New("invalid typed replay body value")
				}
			}
			body[key] = typed
		}
	}
	if op.GraphQL != "" {
		body["query"] = op.GraphQL
		vars := map[string]any{}
		for _, name := range op.Variables {
			v, ok := values[name]
			if !ok {
				return out, errors.New("GraphQL variable missing")
			}
			var typed any = v
			if json.Unmarshal([]byte(v), &typed) != nil {
				typed = v
			}
			vars[name] = typed
		}
		body["variables"] = vars
	}
	out.URL = op.Origin + path
	if len(query) > 0 {
		out.URL += "?" + query.Encode()
	}
	if _, e = webacquire.URL(out.URL); e != nil {
		return out, e
	}
	if op.ContentType != "" {
		headers["Content-Type"] = op.ContentType
	}
	if len(body) > 0 {
		if strings.Contains(strings.ToLower(op.ContentType), "form-urlencoded") {
			form := url.Values{}
			for k, v := range body {
				s, ok := v.(string)
				if !ok {
					return out, errors.New("form field must be a string")
				}
				form.Set(k, s)
			}
			out.Body = form.Encode()
		} else {
			if op.ContentType != "" && !strings.Contains(strings.ToLower(op.ContentType), "json") {
				return out, errors.New("body protocol requires specialized replay")
			}
			data, e := json.Marshal(body)
			if e != nil {
				return out, e
			}
			out.Body = string(data)
			headers["Content-Type"] = "application/json"
		}
	}
	for k, v := range headers {
		if strings.ContainsAny(k+v, "\r\n\x00") {
			return out, errors.New("invalid replay header")
		}
		out.Headers = append(out.Headers, k+": "+v)
	}
	return out, nil
}

func webReplayExample(op webanalysis.Operation, index int) (webAPIRequest, string, error) {
	out := webAPIRequest{}
	if op.Protocol != "http" || index < 1 || index > len(op.Examples) {
		return out, "", errors.New("stored HTTP example not found")
	}
	example := op.Examples[index-1]
	if example.Denied || !webReplayMethod.MatchString(example.Method) || example.BodyOmitted {
		return out, "", errors.New("stored request unavailable or denied")
	}
	u, err := webacquire.URL(example.URL)
	if err != nil || u.Scheme+"://"+u.Host != op.Origin || example.Method != op.Method {
		return out, "", errors.New("stored request origin or method mismatch")
	}
	for k := range u.Query() {
		if webanalysis.Sensitive(k) {
			return out, "", errors.New("stored URL needs credential refresh; use structured replay")
		}
	}
	_, body, err := webanalysis.ReplayBody(example)
	if err != nil {
		return out, "", err
	}
	out.URL = example.URL
	out.Method = example.Method
	out.Body = string(body)
	keys := make([]string, 0, len(example.Headers))
	for k := range example.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if webanalysis.Sensitive(k) || strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") || strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Accept-Encoding") {
			continue
		}
		for _, v := range example.Headers[k] {
			if strings.ContainsAny(k+v, "\r\n\x00") || !httpguts.ValidHeaderFieldName(k) {
				return out, "", errors.New("invalid stored request header")
			}
			out.Headers = append(out.Headers, k+": "+v)
		}
	}
	return out, example.Role, nil
}
