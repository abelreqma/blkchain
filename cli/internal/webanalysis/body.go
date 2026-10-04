package webanalysis

import (
	"encoding/json"
	"mime"
	"net/url"
	"strings"
)

func UnsupportedObservedBody(op Operation) bool {
	if op.Protocol != "http" {
		return false
	}
	for _, example := range op.Examples {
		if example.Body == "" {
			continue
		}
		contentType := example.Headers.Get("Content-Type")
		if contentType == "" {
			contentType = op.ContentType
		}
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil && contentType != "" {
			return true
		}
		if mediaType == "application/x-www-form-urlencoded" {
			fields, err := url.ParseQuery(example.Body)
			if err != nil || len(fields) == 0 {
				return true
			}
			continue
		}
		if mediaType != "" && mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") {
			return true
		}
		var body map[string]any
		if json.Unmarshal([]byte(example.Body), &body) != nil || len(body) == 0 {
			return true
		}
	}
	return false
}
