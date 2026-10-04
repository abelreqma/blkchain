package main

import (
	"blkchain/cli/internal/webanalysis"
	"context"
	"errors"
	"github.com/mxschmitt/playwright-go"
	"strings"
	"sync"
)

type webScriptEvent struct {
	Session         webSourceSession
	Data            map[string]any
	Page            playwright.Page
	BaseURL, Worker string
}
type webCDPState struct {
	mu            sync.Mutex
	Scripts       []webScriptEvent
	Requests      map[string]webanalysis.RequestExample
	Pages         []playwright.Page
	Seen          map[playwright.Page]bool
	Count         int
	Gap           bool
	Cached        []webCachedResponse
	WorkerSources map[string]string
}

func (d *webPlaywrightDriver) cdpAttach(page playwright.Page) error {
	d.cdp.mu.Lock()
	if d.cdp.Seen == nil {
		d.cdp.Seen = map[playwright.Page]bool{}
		d.cdp.Requests = map[string]webanalysis.RequestExample{}
	}
	if d.cdp.Seen[page] {
		d.cdp.mu.Unlock()
		return nil
	}
	d.cdp.Seen[page] = true
	d.cdp.mu.Unlock()
	session, err := d.context.NewCDPSession(page)
	if err != nil {
		return errors.New("CDP collection unavailable")
	}
	session.On("Debugger.scriptParsed", func(v map[string]any) {
		d.cdp.mu.Lock()
		defer d.cdp.mu.Unlock()
		if aux, ok := v["executionContextAuxData"].(map[string]any); ok && aux["isDefault"] == false {
			return
		}
		if source, ok := v["url"].(string); ok && strings.HasPrefix(source, "__playwright") {
			return
		}
		d.cdp.Count++
		if d.cdp.Count > 200 || len(d.cdp.Scripts) >= 200 {
			d.cdp.Gap = true
			return
		}
		d.cdp.Scripts = append(d.cdp.Scripts, webScriptEvent{Session: session, Data: v, Page: page})
	})
	session.On("Network.requestWillBeSent", func(v map[string]any) { d.cdpRecordRequest(v, "") })
	session.On("Network.responseReceived", func(v map[string]any) { d.cdpCachedResponse(session, v, "") })
	if err = d.workerAttach(session, page, "", []map[string]any{{"type": "worker"}, {"exclude": true}}); err != nil {
		return err
	}
	if d.workerRoot == nil {
		d.workerRoot = session
		if err = d.workerBrowserAttach(page, session); err != nil {
			return err
		}
	}
	if _, err = session.Send("Network.enable", map[string]any{"maxTotalBufferSize": 4 << 20, "maxResourceBufferSize": 4 << 20, "maxPostDataSize": 1 << 20}); err != nil {
		return err
	}
	if _, err = session.Send("Debugger.enable", map[string]any{"maxScriptsCacheSize": 16 << 20}); err != nil {
		return err
	}
	return nil
}
func (d *webPlaywrightDriver) cdpRequest(e webanalysis.RequestExample) webanalysis.RequestExample {
	d.cdp.mu.Lock()
	defer d.cdp.mu.Unlock()
	for _, r := range d.cdp.Requests {
		if r.URL == e.URL && r.Method == e.Method {
			e.Frame = r.Frame
			e.Initiator = r.Initiator
			if r.Worker != "" {
				e.Worker = r.Worker
			}
			if e.ResourceType == "" || e.ResourceType == "empty" {
				e.ResourceType = r.ResourceType
			}
		}
	}
	if e.Worker == "" {
		for raw, id := range d.cdp.WorkerSources {
			if strings.HasPrefix(e.Initiator, raw+":") {
				e.Worker = id
				break
			}
		}
	}
	return e
}
func (d *webPlaywrightDriver) cdpDrain(ctx context.Context) error {
	if err := d.drainCached(ctx); err != nil {
		return err
	}
	d.cdp.mu.Lock()
	pages := d.cdp.Pages
	d.cdp.Pages = nil
	d.cdp.mu.Unlock()
	for _, p := range pages {
		if e := d.cdpAttach(p); e != nil {
			return e
		}
	}
	d.cdp.mu.Lock()
	events := d.cdp.Scripts
	d.cdp.Scripts = nil
	gap := d.cdp.Gap
	d.cdp.Gap = false
	d.cdp.mu.Unlock()
	for _, v := range events {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		length, _ := v.Data["length"].(float64)
		sourceURL, _ := v.Data["url"].(string)
		id, _ := v.Data["scriptId"].(string)
		if length > webanalysis.MaxSource || length < 0 {
			gap = true
			continue
		}
		// Full source is retrieved only for parsed scripts within the browser's memory limit.
		result, err := v.Session.Send("Debugger.getScriptSource", map[string]any{"scriptId": id})
		if err != nil {
			gap = true
			continue
		}
		m, ok := result.(map[string]any)
		if !ok {
			gap = true
			continue
		}
		source, _ := m["scriptSource"].(string)
		if len(source) > webanalysis.MaxSource {
			gap = true
			continue
		}
		if sourceURL == "" && webInstrumentationSource([]byte(source)) {
			continue
		}
		base := v.Page.URL()
		if strings.HasPrefix(v.BaseURL, "http:") || strings.HasPrefix(v.BaseURL, "https:") {
			base = v.BaseURL
		}
		if strings.HasPrefix(sourceURL, "http:") || strings.HasPrefix(sourceURL, "https:") {
			if d.redirectOK == nil || !d.redirectOK(sourceURL) {
				gap = true
				continue
			}
			base = sourceURL
		}
		if sourceURL == "" {
			sourceURL = base + "#generated-script-" + id
		}
		sm, _ := v.Data["sourceMapURL"].(string)
		if d.observe != nil {
			if err = d.observe(webObservation{Artifact: webanalysis.Artifact{DocumentURL: func() string {
				if v.Worker != "" {
					return base
				}
				return v.Page.URL()
			}(), Kind: "cdp-script", URL: sourceURL, FinalURL: base, Role: d.role, Complete: true, SourceMap: sm}, Body: []byte(source)}); err != nil {
				return err
			}
		}
	}
	if gap && d.observe != nil {
		return d.observe(webObservation{Artifact: webanalysis.Artifact{Kind: "collection-gap", URL: d.page.URL(), Role: d.role, Gap: "CDP script/worker/target source unavailable or capture limit exhausted"}})
	}
	return nil
}

func webInstrumentationSource(source []byte) bool {
	if string(source) == webDOMCaptureScript {
		return true
	}
	switch webanalysis.Hash(source) {
	case "8995b66c740cc1e3f79f0317ef1c6526d98322093224c49807a665807e4f9490", "1b5c31c526a4baf61cffdaf0751b74e08509263ebd7e13e7056f305170014331", "fd3b882cab3a898b34e827ab330d9fb152340d61f7d0c3cec30247018af131e4", "9e22374178d30310bf36b9ad25aeb7e094195c70fae675a5d8e48cad46b77308", "ceb74286d43fc194ff50d1f86945a29e8926db77c473259a98c48a10ff62d7d7", "a3c74b2aecbdd0b615e6a2eed4788a374366e25d5fdcd45dca45d55fbb119046":
		return true
	}
	return false
}
