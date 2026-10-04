package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"blkchain/cli/internal/webanalysis"
	"github.com/mxschmitt/playwright-go"
)

type webSourceSession interface {
	Send(string, map[string]any) (any, error)
}
type webWorkerSession struct {
	Parent  playwright.CDPSession
	ID, URL string
	Page    playwright.Page
	Driver  *webPlaywrightDriver
	mu      sync.Mutex
	next    int
	pending map[int]chan map[string]any
}

func (w *webWorkerSession) Send(method string, params map[string]any) (any, error) {
	w.mu.Lock()
	w.next++
	id := w.next
	if len(w.pending) >= 16 {
		w.mu.Unlock()
		return nil, errors.New("worker CDP request limit")
	}
	response := make(chan map[string]any, 1)
	w.pending[id] = response
	w.mu.Unlock()
	defer func() { w.mu.Lock(); delete(w.pending, id); w.mu.Unlock() }()
	data, _ := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if _, err := w.Parent.Send("Target.sendMessageToTarget", map[string]any{"sessionId": w.ID, "message": string(data)}); err != nil {
		return nil, err
	}
	select {
	case result := <-response:
		if result["error"] != nil {
			return nil, errors.New("worker CDP request failed")
		}
		return result["result"], nil
	case <-time.After(3 * time.Second):
		return nil, errors.New("worker CDP request timed out")
	}
}
func (d *webPlaywrightDriver) workerAttach(parent playwright.CDPSession, page playwright.Page, contextID string, filter []map[string]any) error {
	workers := map[string]*webWorkerSession{}
	var mu sync.Mutex
	parent.On("Target.attachedToTarget", func(event map[string]any) {
		info, _ := event["targetInfo"].(map[string]any)
		id, _ := event["sessionId"].(string)
		if info == nil || id == "" {
			return
		}
		if contextID != "" && info["browserContextId"] != contextID {
			return
		}
		mu.Lock()
		if len(workers) >= 20 {
			mu.Unlock()
			d.cdp.mu.Lock()
			d.cdp.Gap = true
			d.cdp.mu.Unlock()
			return
		}
		raw, _ := info["url"].(string)
		w := &webWorkerSession{Parent: parent, ID: id, URL: raw, Page: page, Driver: d, pending: map[int]chan map[string]any{}}
		workers[id] = w
		mu.Unlock()
		go func() {
			defer func() { _, _ = w.Send("Runtime.runIfWaitingForDebugger", nil) }()
			if _, err := w.Send("Network.enable", map[string]any{"maxTotalBufferSize": 4 << 20, "maxResourceBufferSize": 4 << 20, "maxPostDataSize": 1 << 20}); err != nil {
				d.workerGap(raw)
			}
			if _, err := w.Send("Debugger.enable", map[string]any{"maxScriptsCacheSize": 16 << 20}); err != nil {
				d.workerGap(raw)
			}
		}()
	})
	parent.On("Target.receivedMessageFromTarget", func(event map[string]any) {
		id, _ := event["sessionId"].(string)
		message, _ := event["message"].(string)
		mu.Lock()
		w := workers[id]
		mu.Unlock()
		if w == nil {
			return
		}
		if len(message) > 6<<20 {
			d.workerGap(w.URL)
			return
		}
		var v map[string]any
		if json.Unmarshal([]byte(message), &v) != nil {
			return
		}
		if n, ok := v["id"].(float64); ok {
			w.mu.Lock()
			ch := w.pending[int(n)]
			w.mu.Unlock()
			if ch != nil {
				select {
				case ch <- v:
				default:
				}
			}
			return
		}
		params, _ := v["params"].(map[string]any)
		if params == nil {
			return
		}
		switch v["method"] {
		case "Debugger.scriptParsed":
			d.cdp.mu.Lock()
			if source, ok := params["url"].(string); ok && source != "" {
				if d.cdp.WorkerSources == nil {
					d.cdp.WorkerSources = map[string]string{}
				}
				if len(d.cdp.WorkerSources) < 200 {
					d.cdp.WorkerSources[source] = w.ID
				}
			}
			if d.cdp.Count >= 200 || len(d.cdp.Scripts) >= 200 {
				d.cdp.Gap = true
			} else {
				d.cdp.Count++
				d.cdp.Scripts = append(d.cdp.Scripts, webScriptEvent{Session: w, Data: params, Page: page, BaseURL: w.URL, Worker: w.ID})
			}
			d.cdp.mu.Unlock()
		case "Network.responseReceived":
			d.cdpCachedResponse(w, params, w.ID)
		case "Network.requestWillBeSent":
			d.cdpRecordRequest(params, w.ID)
		}
	})
	if contextID != "" {
		parent.On("Target.targetCreated", func(event map[string]any) {
			info, _ := event["targetInfo"].(map[string]any)
			if info == nil || info["browserContextId"] != contextID {
				return
			}
			id, _ := info["targetId"].(string)
			go func() {
				if _, err := parent.Send("Target.attachToTarget", map[string]any{"targetId": id, "flatten": false}); err != nil {
					d.workerGap(id)
				}
			}()
		})
		_, err := parent.Send("Target.setDiscoverTargets", map[string]any{"discover": true, "filter": filter})
		return err
	}
	_, err := parent.Send("Target.setAutoAttach", map[string]any{"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": false, "filter": filter})
	return err
}
func (d *webPlaywrightDriver) workerGap(raw string) {
	d.cdp.mu.Lock()
	d.cdp.Gap = true
	d.cdp.mu.Unlock()
}
func (d *webPlaywrightDriver) cdpRecordRequest(v map[string]any, worker string) {
	id, _ := v["requestId"].(string)
	r, _ := v["request"].(map[string]any)
	if r == nil {
		return
	}
	raw, _ := r["url"].(string)
	method, _ := r["method"].(string)
	frame, _ := v["frameId"].(string)
	typ, _ := v["type"].(string)
	init, _ := v["initiator"].(map[string]any)
	loc, _ := init["url"].(string)
	if stack, ok := init["stack"].(map[string]any); ok {
		if frames, ok := stack["callFrames"].([]any); ok && len(frames) > 0 {
			if f, ok := frames[0].(map[string]any); ok {
				loc = fmt.Sprint(f["url"], ":", f["lineNumber"], ":", f["columnNumber"])
			}
		}
	}
	d.cdp.mu.Lock()
	defer d.cdp.mu.Unlock()
	if len(d.cdp.Requests) >= 500 {
		d.cdp.Gap = true
		return
	}
	headers := http.Header{}
	if values, ok := r["headers"].(map[string]any); ok {
		for k, v := range values {
			headers.Set(k, fmt.Sprint(v))
		}
	}
	body, _ := r["postData"].(string)
	if len(body) > 1<<20 {
		body = ""
		d.cdp.Gap = true
	}
	d.cdp.Requests[worker+":"+id] = webanalysis.RequestExample{Headers: headers, Body: body, URL: raw, Method: method, Frame: frame, Initiator: loc, Worker: worker, ResourceType: strings.ToLower(typ)}
}
func (d *webPlaywrightDriver) workerBrowserAttach(page playwright.Page, session playwright.CDPSession) error {
	result, err := session.Send("Target.getTargetInfo", nil)
	if err != nil {
		return err
	}
	value, _ := result.(map[string]any)
	info, _ := value["targetInfo"].(map[string]any)
	contextID, _ := info["browserContextId"].(string)
	if contextID == "" {
		return errors.New("worker context identity missing")
	}
	browser, err := d.browser.NewBrowserCDPSession()
	if err != nil {
		return err
	}
	// Browser TLS terminates at the isolated proxy; the Go broker verifies target TLS.
	if _, err = browser.Send("Security.setIgnoreCertificateErrors", map[string]any{"ignore": true}); err != nil {
		return err
	}
	return d.workerAttach(browser, page, contextID, []map[string]any{{"type": "worker"}, {"type": "shared_worker"}, {"type": "service_worker"}, {"exclude": true}})
}
