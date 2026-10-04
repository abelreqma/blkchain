package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"blkchain/cli/internal/webanalysis"
)

type webCachedResponse struct {
	Session webSourceSession
	Data    map[string]any
	Request webanalysis.RequestExample
}

func (d *webPlaywrightDriver) cdpCachedResponse(session webSourceSession, v map[string]any, worker string) {
	response, _ := v["response"].(map[string]any)
	if response == nil {
		return
	}
	if response["fromServiceWorker"] != true && response["fromDiskCache"] != true && response["fromPrefetchCache"] != true {
		return
	}
	id, _ := v["requestId"].(string)
	d.cdp.mu.Lock()
	defer d.cdp.mu.Unlock()
	if len(d.cdp.Cached) >= 100 {
		d.cdp.Gap = true
		return
	}
	request := d.cdp.Requests[worker+":"+id]
	d.cdp.Cached = append(d.cdp.Cached, webCachedResponse{Session: session, Data: v, Request: request})
}
func (d *webPlaywrightDriver) drainCached(ctx context.Context) error {
	d.cdp.mu.Lock()
	events := d.cdp.Cached
	d.cdp.Cached = nil
	d.cdp.mu.Unlock()
	for _, event := range events {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		response, _ := event.Data["response"].(map[string]any)
		raw, _ := response["url"].(string)
		if d.redirectOK == nil || !d.redirectOK(raw) {
			continue
		}
		mime, _ := response["mimeType"].(string)
		status, _ := response["status"].(float64)
		headers := http.Header{}
		if values, ok := response["headers"].(map[string]any); ok {
			for k, v := range values {
				headers.Set(k, fmt.Sprint(v))
			}
		}
		artifact := webanalysis.Artifact{Kind: "cached-response", URL: raw, FinalURL: raw, Role: d.role, Status: int(status), MIME: mime, Headers: headers}
		request := event.Request
		request.URL = raw
		request.Status = int(status)
		request.Role = d.role
		request.Cached = true
		if request.Method == "" {
			request.Method = "GET"
		}
		if request.ResourceType == "" {
			request.ResourceType = "fetch"
		}
		var body []byte
		length, _ := response["encodedDataLength"].(float64)
		id, _ := event.Data["requestId"].(string)
		if length <= webanalysis.MaxSource {
			value, err := event.Session.Send("Network.getResponseBody", map[string]any{"requestId": id})
			if err == nil {
				if data, ok := value.(map[string]any); ok {
					source, _ := data["body"].(string)
					if len(source) <= webanalysis.MaxSource*2 {
						body = []byte(source)
						if data["base64Encoded"] == true {
							body, err = base64.StdEncoding.DecodeString(source)
						}
						artifact.Complete = err == nil && len(body) <= webanalysis.MaxSource
					}
				}
			}
		}
		if !artifact.Complete {
			artifact.Gap = "cached response body unavailable or exceeds capture limit"
			body = nil
		}
		if strings.Contains(mime, "javascript") {
			artifact.Kind = "script"
		}
		if d.observe != nil {
			if err := d.observe(webObservation{Artifact: artifact, Body: body, Request: request}); err != nil {
				return err
			}
		}
	}
	return nil
}
