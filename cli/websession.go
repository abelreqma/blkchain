package main

import (
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/webanalysis"
	"blkchain/cli/internal/webcollect"
	"context"
	"encoding/json"
	"errors"
	"github.com/mxschmitt/playwright-go"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type webSessionRole struct {
	Name       string            `json:"name"`
	Origin     string            `json:"origin"`
	HeadersEnv map[string]string `json:"headers_env"`
	CookiesEnv map[string]string `json:"cookies_env"`
	Login      *webBrowserArgs   `json:"login,omitempty"`
	Storage    map[string]string `json:"storage_env,omitempty"`
}

func webLoadSessions(path string) ([]webSessionRole, error) {
	if path == "" {
		return []webSessionRole{{Name: "anonymous"}}, nil
	}
	b, e := webReadFile(path, 1<<20)
	if e != nil {
		return nil, e
	}
	var v struct {
		Roles []webSessionRole `json:"roles"`
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if dec.Decode(&v) != nil || len(v.Roles) == 0 || len(v.Roles) > 10 {
		return nil, errors.New("session file requires 1 to 10 roles")
	}
	seen := map[string]bool{}
	for _, r := range v.Roles {
		if r.Name == "" || len(r.Name) > 64 || webanalysis.SafeText(r.Name) != r.Name || seen[r.Name] {
			return nil, errors.New("invalid or duplicate session role")
		}
		seen[r.Name] = true
		u, e := url.Parse(r.Origin)
		if e != nil || u.User != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" || u.Path != "" && u.Path != "/" || u.RawQuery != "" {
			return nil, errors.New("session origin must be an HTTP origin")
		}
		if len(r.HeadersEnv)+len(r.CookiesEnv)+len(r.Storage) > 100 {
			return nil, errors.New("session field limit")
		}
	}
	return v.Roles, nil
}
func webReadFile(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return nil, errors.New("input must be a bounded regular file")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(b)) > limit {
		return nil, errors.New("input limit")
	}
	return b, e
}
func webRoleHeaders(r webSessionRole) (http.Header, error) {
	out := http.Header{}
	for k, v := range r.HeadersEnv {
		value, ok := os.LookupEnv(v)
		if !ok || value == "" || strings.ContainsAny(k+value, "\r\n\x00") {
			return nil, errors.New("session header environment value missing or invalid")
		}
		out.Set(k, value)
	}
	if len(r.CookiesEnv) > 0 {
		cookies := []string{}
		for k, v := range r.CookiesEnv {
			value, ok := os.LookupEnv(v)
			if !ok || value == "" || strings.ContainsAny(k+value, "\r\n\x00;") {
				return nil, errors.New("session cookie environment value missing or invalid")
			}
			cookies = append(cookies, k+"="+value)
		}
		out.Set("Cookie", strings.Join(cookies, "; "))
	}
	return out, nil
}

type webJobBrowser struct {
	Driver     *webPlaywrightDriver
	Gate       *secgate.Gate
	Armed      webArmedFunc
	Collector  *webcollect.Service
	Role       webSessionRole
	Queue      []webObservation
	queueBytes int
	Assist     time.Duration
}

func webNewJobBrowser(g *secgate.Gate, armed webArmedFunc, collector *webcollect.Service, role webSessionRole, headed bool) (*webJobBrowser, error) {
	if headed && os.Getenv("BLKCHAIN_PLAYWRIGHT_HEADED") != "1" {
		return nil, errors.New("headed mode requires an operator-provisioned isolated headed container and BLKCHAIN_PLAYWRIGHT_HEADED=1")
	}
	d, e := newWebPlaywrightDriver()
	if e != nil {
		return nil, e
	}
	headers, e := webRoleHeaders(role)
	if e != nil {
		d.Close()
		return nil, e
	}
	d.sessionOrigin = strings.TrimRight(role.Origin, "/")
	d.sessionHeaders = headers.Clone()
	d.sessionHeaders.Del("Cookie")
	b := &webJobBrowser{Driver: d, Gate: g, Armed: armed, Collector: collector, Role: role}
	d.broker = collector.Broker
	d.role = role.Name
	d.redirectOK = webRedirectOK(g)
	d.observe = func(o webObservation) error {
		d.cdp.mu.Lock()
		defer d.cdp.mu.Unlock()
		if len(b.Queue) >= 500 || b.queueBytes+len(o.Body) > 64<<20 {
			d.cdp.Gap = true
			return errors.New("browser observation queue limit")
		}
		b.Queue = append(b.Queue, o)
		b.queueBytes += len(o.Body)
		return nil
	}
	return b, nil
}
func (b *webJobBrowser) drain(ctx context.Context) error {
	b.Driver.cdp.mu.Lock()
	queue := b.Queue
	b.Queue = nil
	b.queueBytes = 0
	b.Driver.cdp.mu.Unlock()
	for _, o := range queue {
		a, e := b.Collector.Accept(ctx, o.Artifact, o.Body, 0)
		if e != nil {
			return e
		}
		if o.Request.URL != "" {
			o.Request.Artifact = a.ID
			o.Request = b.Driver.cdpRequest(o.Request)
			if e = b.Collector.Observe(ctx, o.Request); e != nil {
				return e
			}
		}
	}
	return nil
}
func (b *webJobBrowser) prepare(ctx context.Context) error {
	d := b.Driver
	if e := d.ensureContext(); e != nil {
		return e
	}
	if b.Role.Origin != "" {
		if !webRedirectOK(b.Gate)(b.Role.Origin) {
			return errors.New("session origin outside scope")
		}
		u, _ := url.Parse(b.Role.Origin)
		for k, v := range b.Role.CookiesEnv {
			value, ok := os.LookupEnv(v)
			if !ok {
				return errors.New("session cookie environment value missing")
			}
			if e := d.context.AddCookies([]playwright.OptionalCookie{{Name: k, Value: value, URL: playwright.String(u.String()), Secure: playwright.Bool(u.Scheme == "https")}}); e != nil {
				return errors.New("session cookies rejected")
			}
		}
		if len(b.Role.Storage) > 0 {
			values := map[string]string{}
			for k, v := range b.Role.Storage {
				value, ok := os.LookupEnv(v)
				if !ok {
					return errors.New("session storage environment value missing")
				}
				values[k] = value
			}
			data, _ := json.Marshal(struct {
				Origin string
				Values map[string]string
			}{u.Scheme + "://" + u.Host, values})
			script := "(() => {const s=" + string(data) + ";if(location.origin===s.Origin){for(const [k,v] of Object.entries(s.Values))localStorage.setItem(k,v)}})()"
			if e := d.context.AddInitScript(playwright.Script{Content: playwright.String(script)}); e != nil {
				return errors.New("session storage rejected")
			}
		}
	}
	if b.Role.Login != nil {
		login := *b.Role.Login
		if login.Op != "submit" || login.Payload != "" {
			return errors.New("session login requires structured form submission")
		}
		fields := map[string]string{}
		for selector, ref := range login.Fields {
			if !strings.HasPrefix(ref, "${") || !strings.HasSuffix(ref, "}") {
				return errors.New("login fields require environment references")
			}
			value, ok := os.LookupEnv(ref[2 : len(ref)-1])
			if !ok {
				return errors.New("login environment value missing")
			}
			fields[selector] = value
		}
		login.Fields = fields
		data, e := json.Marshal(login)
		if e != nil {
			return e
		}
		action, e := webParseBrowserAction(string(data))
		if e != nil {
			return e
		}
		decision := b.Gate.AuthorizeBrowser(ctx, secgate.BrowserAction{URL: action.URL, Active: true, Armed: webArmedOrFalse(b.Armed)})
		if !decision.Allowed {
			return errors.New("session login denied by engagement policy")
		}
		if _, e = d.DoBrowser(ctx, action, webRedirectOK(b.Gate)); e != nil {
			return e
		}
		if e = b.drain(ctx); e != nil {
			return e
		}
	}
	return nil
}
func (b *webJobBrowser) Visit(ctx context.Context, raw, role string) error {
	if b.Assist < 0 || b.Assist > 120*time.Second {
		return errors.New("operator assistance window exceeds limit")
	}
	if !b.Gate.AuthorizeBrowser(ctx, secgate.BrowserAction{URL: raw, Armed: webArmedOrFalse(b.Armed)}).Allowed {
		return errors.New("navigation denied")
	}
	d := b.Driver
	d.stateMu.Lock()
	d.actionCtx = ctx
	d.stateMu.Unlock()
	if d.context == nil {
		if e := b.prepare(ctx); e != nil {
			return e
		}
	}
	_, e := d.DoBrowser(ctx, webBrowserAction{Op: webBrowserNavigate, URL: raw}, webRedirectOK(b.Gate))
	if e == nil && b.Assist > 0 {
		d.stateMu.Lock()
		d.actionCtx = ctx
		d.stateMu.Unlock()
		window := b.Assist
		b.Assist = 0
		var closeOnce sync.Once
		closeContext := func() { closeOnce.Do(func() { _ = d.context.Close() }) }
		stop := context.AfterFunc(ctx, closeContext)
		defer func() {
			if ctx.Err() != nil {
				closeContext()
			}
			stop()
		}()
		timer := time.NewTimer(window)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		d.mu.Lock()
		_, err := d.captureDOM("assisted-browser-dom")
		d.mu.Unlock()
		if err != nil {
			return err
		}
		b.Collector.Gap("assistance", d.page.URL(), "Operator assistance window ended; challenge completion requires captured response or state evidence")
		if err := d.cdpDrain(ctx); err != nil {
			return err
		}
	}
	if de := b.drain(ctx); de != nil {
		return de
	}
	return e
}
func (b *webJobBrowser) Interact(ctx context.Context, raw, action string) error {
	d := b.Driver
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	active := strings.HasPrefix(action, "click:")
	if action != "scroll" && !active {
		return errors.New("supported interactions: scroll or click:<selector>")
	}
	if !b.Gate.AuthorizeBrowser(ctx, secgate.BrowserAction{URL: raw, Active: active, Armed: webArmedOrFalse(b.Armed)}).Allowed {
		return errors.New("interaction denied")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stateMu.Lock()
	d.actionCtx = ctx
	d.stateMu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = d.context.Close() })
	defer stop()
	var e error
	if action == "scroll" {
		_, e = d.page.Evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
	} else {
		selector := strings.TrimPrefix(action, "click:")
		if len(selector) > 1000 || strings.ContainsAny(selector, "\x00\r\n") {
			return errors.New("invalid interaction selector")
		}
		e = d.page.Locator(selector).Click()
	}
	if e != nil {
		return errors.New("interaction failed")
	}
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	if e = d.cdpDrain(ctx); e != nil {
		return e
	}
	return b.drain(ctx)
}
func (b *webJobBrowser) Close() error {
	err := b.Driver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if e := b.drain(ctx); err == nil {
		err = e
	}
	return err
}

func webRoleStateAvailable(r webSessionRole) error {
	for _, ref := range r.Storage {
		if value, ok := os.LookupEnv(ref); !ok || value == "" {
			return errors.New("session storage environment value missing")
		}
	}
	if r.Login != nil {
		for _, ref := range r.Login.Fields {
			if !strings.HasPrefix(ref, "${") || !strings.HasSuffix(ref, "}") {
				return errors.New("login fields require environment references")
			}
			if value, ok := os.LookupEnv(ref[2 : len(ref)-1]); !ok || value == "" {
				return errors.New("login environment value missing")
			}
		}
	}
	return nil
}
