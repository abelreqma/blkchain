package webacquire

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// characterize.go reads an origin's headers, cookies, CORS policy, methods and metadata paths from responses the broker fetched, each census alongside random same-host controls.

// MetadataPaths are the well-known paths swept for; the list is fixed rather than guessed.
func MetadataPaths() []string {
	return []string{
		"/robots.txt",
		"/sitemap.xml",
		"/.well-known/security.txt",
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
		"/.well-known/change-password",
		"/.well-known/assetlinks.json",
		"/.well-known/apple-app-site-association",
		"/openapi.json",
		"/swagger.json",
		"/graphql",
		"/service-worker.js",
		"/manifest.json",
		"/crossdomain.xml",
		"/clientaccesspolicy.xml",
		"/humans.txt",
		"/ads.txt",
		"/.well-known/dnt-policy.txt",
	}
}

// securityHeaders are the response headers whose presence and value describe the origin's browser-side posture.
func securityHeaders() []string {
	return []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"Content-Security-Policy-Report-Only",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Embedder-Policy",
		"Cross-Origin-Resource-Policy",
		"Cache-Control",
	}
}

// disclosureHeaders are the response headers that name the software behind the origin.
func disclosureHeaders() []string {
	return []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "Via", "X-Generator"}
}

// HeaderProfile is the header posture of one URL.
type HeaderProfile struct {
	URL      string            `json:"url"`
	Status   int               `json:"status"`
	Security map[string]string `json:"security,omitempty"`
	Missing  []string          `json:"missing,omitempty"`
	Exposed  map[string]string `json:"exposed,omitempty"`
	Gap      string            `json:"gap,omitempty"`
}

// CookieFlags is how one Set-Cookie attribute set is marked; the cookie's value is not recorded.
type CookieFlags struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Session  bool   `json:"session"`
	Prefix   string `json:"prefix,omitempty"`
}

// CORSProfile is what an origin granted a request that carried a foreign origin.
type CORSProfile struct {
	URL              string   `json:"url"`
	ProbedOrigin     string   `json:"probed_origin"`
	ReflectsOrigin   bool     `json:"reflects_origin"`
	AllowOrigin      string   `json:"allow_origin,omitempty"`
	AllowCredentials bool     `json:"allow_credentials"`
	AllowsNullOrigin bool     `json:"allows_null_origin"`
	NullCredentials  bool     `json:"null_credentials"`
	Wildcard         bool     `json:"wildcard"`
	AllowMethods     []string `json:"allow_methods,omitempty"`
	AllowHeaders     []string `json:"allow_headers,omitempty"`
	ExposeHeaders    []string `json:"expose_headers,omitempty"`
	Gap              string   `json:"gap,omitempty"`
}

// Credentialed reports whether the policy lets a foreign origin read a response sent with credentials.
func (c CORSProfile) Credentialed() bool {
	return c.ReflectsOrigin && c.AllowCredentials || c.AllowsNullOrigin && c.NullCredentials
}

// MethodInventory is the method surface of one URL; Reached is false when neither request got a response.
type MethodInventory struct {
	URL              string   `json:"url"`
	Reached          bool     `json:"reached"`
	OptionsStatus    int      `json:"options_status"`
	Allow            []string `json:"allow,omitempty"`
	CORSAllowMethods []string `json:"cors_allow_methods,omitempty"`
	TraceStatus      int      `json:"trace_status"`
	TraceEchoes      bool     `json:"trace_echoes"`
	Gap              string   `json:"gap,omitempty"`
}

// PathObservation is one path's response; Length is body bytes read, so a HEAD census reports zero.
type PathObservation struct {
	Path        string `json:"path"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Length      int    `json:"length"`
	Location    string `json:"location,omitempty"`
	Control     bool   `json:"control"`
	Gap         string `json:"gap,omitempty"`
}

// PathCensus is a set of path observations with the controls that say how to read them.
type PathCensus struct {
	Origin   string            `json:"origin"`
	Method   string            `json:"method"`
	Paths    []PathObservation `json:"paths,omitempty"`
	Controls []PathObservation `json:"controls,omitempty"`
	// SoftNotFound means a control path answered, so no status establishes that a path exists.
	SoftNotFound bool   `json:"soft_not_found"`
	Gap          string `json:"gap,omitempty"`
}

// Present reports the paths whose response distinguishes them from the controls, and nothing without usable controls.
func (c PathCensus) Present() []string {
	if c.SoftNotFound || len(c.Controls) == 0 {
		return nil
	}
	var out []string
	for _, p := range c.Paths {
		if p.Status >= 200 && p.Status < 400 {
			out = append(out, p.Path)
		}
	}
	return out
}

// controlPaths returns n random paths, which the census records so the comparison can be re-read.
func controlPaths(n int) ([]string, error) {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		out = append(out, "/"+hex.EncodeToString(b))
	}
	return out, nil
}

// originOf returns scheme://host for a URL.
func originOf(u *url.URL) string { return u.Scheme + "://" + u.Host }

// ProfileHeaders records which security headers an origin sets on one URL and which are absent.
func (b *Broker) ProfileHeaders(ctx context.Context, rawURL string) (HeaderProfile, error) {
	u, err := URL(rawURL)
	if err != nil {
		return HeaderProfile{}, err
	}
	out := HeaderProfile{URL: u.String(), Security: map[string]string{}, Exposed: map[string]string{}}
	resp, err := b.Fetch(ctx, Request{Method: "GET", URL: u.String()})
	if err != nil {
		out.Gap = "baseline request failed"
		return out, err
	}
	out.Status = resp.Status
	for _, name := range securityHeaders() {
		if v := resp.Headers.Get(name); v != "" {
			out.Security[name] = boundedName(v)
			continue
		}
		out.Missing = append(out.Missing, name)
	}
	for _, name := range disclosureHeaders() {
		if v := resp.Headers.Get(name); v != "" {
			out.Exposed[name] = boundedName(v)
		}
	}
	if resp.Gap != "" {
		out.Gap = resp.Gap
	}
	return out, nil
}

// ProfileCookies describes how an origin marks the cookies it sets on one URL.
func (b *Broker) ProfileCookies(ctx context.Context, rawURL string) ([]CookieFlags, error) {
	u, err := URL(rawURL)
	if err != nil {
		return nil, err
	}
	resp, err := b.Fetch(ctx, Request{Method: "GET", URL: u.String()})
	if err != nil {
		return nil, err
	}
	return cookieFlags(resp.Headers), nil
}

// cookieFlags reads the attributes of every Set-Cookie header, never the value.
func cookieFlags(h http.Header) []CookieFlags {
	var out []CookieFlags
	for _, raw := range h.Values("Set-Cookie") {
		parts := strings.Split(raw, ";")
		name, _, found := strings.Cut(strings.TrimSpace(parts[0]), "=")
		name = strings.TrimSpace(name)
		if !found || name == "" {
			continue
		}
		c := CookieFlags{Name: boundedName(name), Session: true}
		switch {
		case strings.HasPrefix(name, "__Host-"):
			c.Prefix = "__Host-"
		case strings.HasPrefix(name, "__Secure-"):
			c.Prefix = "__Secure-"
		}
		for _, attr := range parts[1:] {
			key, value, _ := strings.Cut(strings.TrimSpace(attr), "=")
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "secure":
				c.Secure = true
			case "httponly":
				c.HTTPOnly = true
			case "samesite":
				c.SameSite = boundedName(strings.TrimSpace(value))
			case "path":
				c.Path = boundedName(strings.TrimSpace(value))
			case "domain":
				c.Domain = boundedName(strings.TrimSpace(value))
			case "expires", "max-age":
				c.Session = false
			}
		}
		out = append(out, c)
	}
	return out
}

// ProfileCORS sends one request carrying a random unownable origin and one carrying the null origin.
func (b *Broker) ProfileCORS(ctx context.Context, rawURL string) (CORSProfile, error) {
	u, err := URL(rawURL)
	if err != nil {
		return CORSProfile{}, err
	}
	probe, err := controlPaths(1)
	if err != nil {
		return CORSProfile{}, err
	}
	// A random label under the reserved .invalid TLD cannot be an allowed origin, so naming it back is a reflection.
	foreign := "https://" + strings.TrimPrefix(probe[0], "/") + ".invalid"
	out := CORSProfile{URL: u.String(), ProbedOrigin: foreign}

	resp, err := b.Fetch(ctx, Request{Method: "GET", URL: u.String(),
		Headers: http.Header{"Origin": []string{foreign}}})
	if err != nil {
		out.Gap = "origin-reflection request failed"
		return out, err
	}
	allow := resp.Headers.Get("Access-Control-Allow-Origin")
	out.AllowOrigin = boundedName(allow)
	out.Wildcard = allow == "*"
	out.ReflectsOrigin = allow != "" && strings.EqualFold(allow, foreign)
	out.AllowCredentials = strings.EqualFold(resp.Headers.Get("Access-Control-Allow-Credentials"), "true")
	out.AllowMethods = headerList(resp.Headers, "Access-Control-Allow-Methods")
	out.AllowHeaders = headerList(resp.Headers, "Access-Control-Allow-Headers")
	out.ExposeHeaders = headerList(resp.Headers, "Access-Control-Expose-Headers")

	nullResp, err := b.Fetch(ctx, Request{Method: "GET", URL: u.String(),
		Headers: http.Header{"Origin": []string{"null"}}})
	if err != nil {
		out.Gap = "the null-origin request failed, so that case is unknown"
		return out, nil
	}
	nullAllow := nullResp.Headers.Get("Access-Control-Allow-Origin")
	out.AllowsNullOrigin = strings.EqualFold(nullAllow, "null")
	out.NullCredentials = strings.EqualFold(nullResp.Headers.Get("Access-Control-Allow-Credentials"), "true")
	return out, nil
}

// headerList splits a comma-separated header into its trimmed, sorted values.
func headerList(h http.Header, name string) []string {
	raw := h.Get(name)
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, boundedName(v))
		}
	}
	sort.Strings(out)
	return out
}

// InventoryMethods records the Allow header OPTIONS returns and whether TRACE answers with an echo.
func (b *Broker) InventoryMethods(ctx context.Context, rawURL string) (MethodInventory, error) {
	u, err := URL(rawURL)
	if err != nil {
		return MethodInventory{}, err
	}
	out := MethodInventory{URL: u.String()}
	options, err := b.Once(ctx, Request{Method: "OPTIONS", URL: u.String()})
	if err != nil {
		out.Gap = "the OPTIONS request failed, so the admitted methods are unknown"
	} else {
		out.OptionsStatus = options.Status
		out.Allow = headerList(options.Headers, "Allow")
		out.CORSAllowMethods = headerList(options.Headers, "Access-Control-Allow-Methods")
		if len(out.Allow) == 0 && len(out.CORSAllowMethods) == 0 {
			out.Gap = joinGap(out.Gap, "OPTIONS named no methods")
		}
	}
	// TRACE is not passive, so Once sends it and a redirect is recorded rather than followed.
	trace, err := b.Once(ctx, Request{Method: "TRACE", URL: u.String()})
	if err != nil {
		out.Gap = joinGap(out.Gap, "the TRACE request failed, so cross-site tracing is unknown")
	} else {
		out.TraceStatus = trace.Status
		out.TraceEchoes = traceEchoed(trace, u)
	}
	out.Reached = out.OptionsStatus > 0 || out.TraceStatus > 0
	return out, nil
}

// traceEchoed reports whether the body plays this request back, read from the request line and Host it already carried.
func traceEchoed(resp Response, u *url.URL) bool {
	if resp.Status != 200 {
		return false
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	body := string(resp.Body)
	return strings.Contains(body, "TRACE "+path) && strings.Contains(strings.ToLower(body), "host: "+strings.ToLower(u.Host))
}

// joinGap appends one gap to another.
func joinGap(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}

// SweepPaths fetches each path under origin with method, alongside random same-host controls.
func (b *Broker) SweepPaths(ctx context.Context, origin, method string, paths []string) (PathCensus, error) {
	u, err := URL(origin)
	if err != nil {
		return PathCensus{}, err
	}
	if method == "" {
		method = "HEAD"
	}
	method = strings.ToUpper(method)
	if !Passive(method) {
		return PathCensus{}, errors.New("a path sweep uses a passive method")
	}
	base := originOf(u)
	out := PathCensus{Origin: base, Method: method}
	controls, err := controlPaths(3)
	if err != nil {
		return out, err
	}
	for _, p := range paths {
		obs, err := b.observePath(ctx, base, method, p)
		if err != nil {
			out.Gap = joinGap(out.Gap, "sweep stopped at "+p+": "+err.Error())
			break
		}
		out.Paths = append(out.Paths, obs)
	}
	for _, p := range controls {
		obs, err := b.observePath(ctx, base, method, p)
		if err != nil {
			out.Gap = joinGap(out.Gap, "a control path was not fetched, so the census cannot be read")
			return out, nil
		}
		obs.Control = true
		out.Controls = append(out.Controls, obs)
		if obs.Status >= 200 && obs.Status < 400 {
			out.SoftNotFound = true
		}
	}
	return out, nil
}

// observePath fetches one path and records the facts of its response.
func (b *Broker) observePath(ctx context.Context, origin, method, path string) (PathObservation, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	obs := PathObservation{Path: path}
	// Once rather than Fetch: a redirect is a fact about the path, so it is recorded instead of followed.
	resp, err := b.Once(ctx, Request{Method: method, URL: origin + path})
	if err != nil {
		return obs, err
	}
	obs.Status = resp.Status
	obs.ContentType = boundedName(resp.Headers.Get("Content-Type"))
	obs.Location = boundedName(resp.Headers.Get("Location"))
	obs.Length = len(resp.Body)
	obs.Gap = resp.Gap
	return obs, nil
}
