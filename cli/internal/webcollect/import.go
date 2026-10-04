package webcollect

import (
	"blkchain/cli/internal/webanalysis"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

type harPair struct{ Name, Value string }
type harEntry struct {
	StartedDateTime string
	Request         struct {
		URL, Method string
		Headers     []harPair
		PostData    struct {
			MimeType, Text string
			Params         []harPair
		}
	}
	Response struct {
		Status  int
		Headers []harPair
		Content struct {
			Size                     *int
			MimeType, Text, Encoding string
		}
	}
	ResourceType string `json:"_resourceType"`
}

func (s *Service) ImportHAR(ctx context.Context, r io.Reader, role string) error {
	b, e := io.ReadAll(io.LimitReader(r, 16<<20+1))
	if e != nil || len(b) > 16<<20 {
		return errors.New("HAR input limit")
	}
	var h struct{ Log struct{ Entries []harEntry } }
	if json.Unmarshal(b, &h) != nil || len(h.Log.Entries) > 500 {
		return errors.New("invalid or oversized HAR")
	}
	total := 0
	for _, entry := range h.Log.Entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.DiscoveryAllowed == nil || !s.DiscoveryAllowed(entry.Request.URL) {
			s.gap("import", entry.Request.URL, "request outside discovery scope")
			continue
		}
		headers := http.Header{}
		for _, p := range entry.Request.Headers {
			headers.Add(p.Name, p.Value)
		}
		if entry.Request.PostData.MimeType != "" {
			headers.Set("Content-Type", entry.Request.PostData.MimeType)
		}
		req := webanalysis.RequestExample{ResourceType: entry.ResourceType, URL: entry.Request.URL, Method: entry.Request.Method, Role: role, Status: entry.Response.Status, Headers: headers, Body: entry.Request.PostData.Text}
		if len(req.Body) > 1<<20 {
			return errors.New("HAR request body limit")
		}
		body := []byte(entry.Response.Content.Text)
		if entry.Response.Content.Encoding == "base64" {
			body, e = base64.StdEncoding.DecodeString(entry.Response.Content.Text)
			if e != nil {
				s.gap("import", req.URL, "invalid base64 response")
				continue
			}
		} else if entry.Response.Content.Encoding != "" {
			s.gap("import", req.URL, "unsupported response encoding")
			continue
		}
		total += len(body)
		if len(body) > webanalysis.MaxSource || total > 64<<20 {
			return errors.New("HAR body limit")
		}
		complete := len(body) > 0 || entry.Response.Content.Size != nil && *entry.Response.Content.Size == 0
		gap := ""
		if !complete {
			gap = "response body omitted from HAR"
			s.gap("import", req.URL, gap)
		}
		kind := "import-response"
		mime := entry.Response.Content.MimeType
		if entry.ResourceType == "script" || strings.Contains(mime, "javascript") {
			kind = "script"
		}
		if strings.Contains(mime, "html") {
			kind = "html"
		}
		rh := http.Header{}
		for _, p := range entry.Response.Headers {
			rh.Add(p.Name, p.Value)
		}
		a, e := s.Accept(ctx, webanalysis.Artifact{Kind: kind, URL: req.URL, Role: role, Status: req.Status, Headers: rh, MIME: mime, RetrievedAt: entry.StartedDateTime, Complete: complete, Gap: gap}, body, 0)
		if e != nil {
			return e
		}
		req.Artifact = a.ID
		if e = s.Observe(ctx, req); e != nil {
			return e
		}
	}
	s.mu.Lock()
	c := s.coverage
	c.ID = webanalysis.ID("har", webanalysis.Now(), role)
	c.Role = role
	c.State = "imported"
	c.Started = webanalysis.Now()
	c.Ended = c.Started
	c.Stages = []string{"import", "analysis"}
	s.mu.Unlock()
	if e = s.Store.PutWeb(ctx, "coverage", c.ID, s.task, c); e != nil {
		return e
	}
	return s.Features(ctx)
}
