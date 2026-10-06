package webcollect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/webacquire"
	"blkchain/cli/internal/webanalysis"
)

type Parser func(context.Context, webanalysis.Input) (webanalysis.Result, error)
type Browser interface {
	Visit(context.Context, string, string) error
	Interact(context.Context, string, string) error
	Close() error
}
type Options struct {
	Historical       bool
	Role             string
	Headers          http.Header
	CredentialOrigin string
	Browser          Browser
	Interactions     []string
	MaxDepth         int
	MaxStates        int
}
type frontier struct {
	URL, Kind, Parent, Timestamp, DocumentURL string
	Depth                                     int
	MapLine, MapColumn                        int
}
type Service struct {
	Archive              *Archive
	Store                *engagement.Store
	Broker               *webacquire.Broker
	Parse                Parser
	DiscoveryAllowed     func(string) bool
	MaxArtifactBytes     int
	AccountArtifactBytes func(int) error
	mu                   sync.Mutex
	pending              []frontier
	seen                 map[string]bool
	coverage             webanalysis.Coverage
	task                 string
}

func New(st *engagement.Store, b *webacquire.Broker, p Parser) *Service {
	if p == nil {
		p = webanalysis.Analyze
	}
	limit := 0
	if b != nil {
		limit = b.Policy.MaxBodyBytes
	}
	return &Service{Store: st, Broker: b, Parse: p, seen: map[string]bool{}, MaxArtifactBytes: limit}
}
func (s *Service) enqueue(ctx context.Context, f frontier) {
	if f.Parent != "" {
		r := webanalysis.Relationship{ID: webanalysis.ID(f.Parent, f.URL, f.Timestamp, "discovered-asset"), From: f.Parent, To: webanalysis.ID(f.URL, f.Timestamp), Kind: "discovered-asset", Expression: f.URL}
		if err := s.Store.PutWeb(ctx, "relationship", r.ID, s.task, r); err != nil {
			s.gap("storage", f.URL, err.Error())
			return
		}
	}
	if f.URL == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := f.URL + "\x00" + f.Timestamp + "\x00" + f.DocumentURL
	if s.seen[key] {
		return
	}
	if len(s.seen) >= 500 {
		s.coverage.Gaps = append(s.coverage.Gaps, webanalysis.Gap{Stage: "frontier", Reason: "discovery limit"})
		return
	}
	s.seen[key] = true
	s.pending = append(s.pending, f)
}
func (s *Service) gap(stage, u, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.coverage.Gaps) < 500 {
		s.coverage.Gaps = append(s.coverage.Gaps, webanalysis.Gap{Stage: stage, URL: u, Reason: reason})
	}
}
func (s *Service) Collect(ctx context.Context, targets []string, o Options) (webanalysis.Coverage, error) {
	if s.Store == nil || s.Broker == nil {
		return webanalysis.Coverage{}, errors.New("web collection dependencies missing")
	}
	if len(targets) == 0 || len(targets) > 100 {
		return webanalysis.Coverage{}, errors.New("provide 1 to 100 targets")
	}
	if o.Role == "" {
		o.Role = "anonymous"
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 3
	}
	if o.MaxDepth > 8 {
		return webanalysis.Coverage{}, errors.New("depth exceeds limit")
	}
	if o.MaxStates <= 0 {
		o.MaxStates = 30
	}
	if o.MaxStates > 100 || len(o.Interactions) > 20 {
		return webanalysis.Coverage{}, errors.New("state or interaction limit")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	initialGaps := s.coverage.Gaps
	s.coverage = webanalysis.Coverage{Targets: append([]string(nil), targets...), ID: webanalysis.ID(webanalysis.Now(), o.Role), Role: o.Role, Started: webanalysis.Now(), State: "running", Routes: []string{}, Interactions: []string{}, Downloaded: []string{}, Stages: []string{"collection"}, Gaps: initialGaps}
	s.gap("state", "", "Only supplied roles and visited states are covered; unavailable roles, credentials and runtime values are not inferred")
	if o.Browser != nil {
		s.gap("browser", "", "worker cache responses may not reach the network; stream capture is bounded by page dwell and job lifetime")
	}
	defer func() {
		if o.Browser != nil {
			_ = o.Browser.Close()
		}
	}()
	if o.Historical {
		s.archiveSeeds(ctx, targets)
	} else {
		for _, t := range targets {
			s.enqueue(ctx, frontier{URL: t, Kind: "page"})
		}
	}
	count, states := 0, 0
	for {
		s.mu.Lock()
		if len(s.pending) == 0 {
			s.mu.Unlock()
			break
		}
		f := s.pending[0]
		s.pending = s.pending[1:]
		s.mu.Unlock()
		if ctx.Err() != nil {
			s.gap("job", f.URL, "cancelled or time budget exhausted")
			break
		}
		if count >= 200 {
			s.gap("frontier", f.URL, "asset limit exhausted")
			break
		}
		count++
		if f.Depth > o.MaxDepth {
			s.gap("frontier", f.URL, "depth limit exhausted")
			continue
		}
		if s.DiscoveryAllowed != nil && !s.DiscoveryAllowed(f.URL) {
			s.gap("scope", f.URL, "discovery denied")
			continue
		}
		if (f.Kind == "page" || f.Kind == "frame") && o.Browser != nil && f.Timestamp == "" {
			if states >= o.MaxStates {
				s.gap("browser", f.URL, "state limit exhausted")
				continue
			}
			states++
			if err := o.Browser.Visit(ctx, f.URL, o.Role); err != nil {
				s.gap("browser", f.URL, "navigation failed")
			}
			s.mu.Lock()
			s.coverage.Routes = webanalysis.AddUnique(s.coverage.Routes, f.URL)
			s.mu.Unlock()
			for _, interaction := range o.Interactions {
				if len(s.coverage.Interactions) >= 20 {
					break
				}
				if err := o.Browser.Interact(ctx, f.URL, interaction); err != nil {
					s.gap("interaction", f.URL, "interaction denied or failed")
				} else {
					s.coverage.Interactions = append(s.coverage.Interactions, interaction)
				}
			}
			continue
		}
		var out webacquire.Response
		var err error
		stamp := f.Timestamp
		if stamp != "" {
			out, stamp, err = s.archiveResponse(ctx, f)
		} else {
			headers := o.Headers
			headerOrigin := o.CredentialOrigin
			if headerOrigin == "" && len(targets) > 0 {
				headerOrigin = targets[0]
			}
			if !sameOrigin(headerOrigin, f.URL) {
				headers = nil
			}
			out, err = s.Broker.Fetch(ctx, webacquire.Request{Method: "GET", URL: f.URL, Headers: headers})
		}
		a := webanalysis.Artifact{DocumentURL: f.DocumentURL, MapLine: f.MapLine, MapColumn: f.MapColumn, CapturedAt: stamp, Kind: f.Kind, URL: f.URL, FinalURL: out.FinalURL, Role: o.Role, Status: out.Status, Headers: out.Headers, MIME: out.Headers.Get("Content-Type"), Complete: out.Complete, Parents: []string{f.Parent}, Gap: out.Gap}
		if err != nil {
			reason := "request denied or acquisition failed"
			if f.Timestamp != "" {
				reason = err.Error()
			}
			s.gap("fetch", f.URL, reason)
			a.Gap = reason
		}
		if _, e := s.Accept(ctx, a, out.Body, f.Depth); e != nil {
			s.gap("storage", f.URL, e.Error())
		}
		if err == nil && (strings.Contains(a.MIME, "html") || f.Kind == "page") {
			s.mu.Lock()
			s.coverage.Routes = webanalysis.AddUnique(s.coverage.Routes, f.URL)
			s.mu.Unlock()
		}
	}
	if o.Browser != nil {
		if err := o.Browser.Close(); err != nil {
			s.gap("browser", "", "browser shutdown or final evidence persistence failed")
		}
		o.Browser = nil
	}
	s.mu.Lock()
	s.coverage.Ended = webanalysis.Now()
	s.coverage.State = "complete"
	if ctx.Err() != nil {
		s.coverage.State = "interrupted"
	}
	s.coverage.Stages = webanalysis.AddUnique(s.coverage.Stages, "analysis")
	s.coverage.Requests, s.coverage.Bytes = s.Broker.Usage()
	if err := s.Store.PutWeb(context.Background(), "coverage", s.coverage.ID, s.task, s.coverage); err != nil {
		s.mu.Unlock()
		return s.coverage, err
	}
	s.mu.Unlock()
	if e := s.Features(ctx); e != nil && ctx.Err() == nil {
		return s.coverage, e
	}
	return s.coverage, ctx.Err()
}
func (s *Service) Accept(ctx context.Context, a webanalysis.Artifact, body []byte, depth int) (webanalysis.Artifact, error) {
	if s.MaxArtifactBytes > 0 && len(body) > s.MaxArtifactBytes {
		return a, webacquire.ErrLimit
	}
	if s.AccountArtifactBytes != nil {
		if err := s.AccountArtifactBytes(len(body)); err != nil {
			return a, err
		}
	}
	a.TaskID = s.task
	stored, err := s.Store.SaveWebArtifact(ctx, a, body)
	if err != nil {
		return a, err
	}
	a = stored
	if a.Gap != "" {
		s.gap("acquisition", a.URL, a.Gap)
	}
	for _, parent := range a.Parents {
		if parent != "" {
			r := webanalysis.Relationship{ID: webanalysis.ID(parent, a.ID, "discovered"), From: parent, To: a.ID, Kind: "discovered-artifact"}
			if e := s.Store.PutWeb(ctx, "relationship", r.ID, s.task, r); e != nil {
				return a, e
			}
		}
	}
	unit := webanalysis.SourceUnit{ID: webanalysis.ID(a.ID, "metadata"), Artifact: a.ID, Hash: a.Hash, URL: a.FinalURL, Kind: "response-metadata", Language: "metadata", Parse: "not-executable"}
	findings := webanalysis.Technology(unit, body, a.Headers)
	credentials, gaps := webanalysis.JSONCredentials(unit, a.Role, body)
	headerCredentials, headerGaps := webanalysis.HeaderCredentials(unit, a.Role, a.Headers)
	credentials = append(credentials, headerCredentials...)
	gaps = append(gaps, headerGaps...)
	if webanalysis.EnvironmentSource(unit) || !isScript(a) && !strings.Contains(a.MIME, "html") && a.Kind != "browser-dom" && a.Kind != "assisted-browser-dom" {
		textCredentials, textGaps := webanalysis.TextCredentials(unit, a.Role, body)
		credentials = append(credentials, textCredentials...)
		gaps = append(gaps, textGaps...)
	}
	if strings.Contains(a.MIME, "html") || a.Kind == "html" || a.Kind == "page" || a.Kind == "frame" || a.Kind == "browser-dom" || a.Kind == "assisted-browser-dom" {
		htmlCredentials, htmlGaps := webanalysis.HTMLCredentials(unit, a.Role, body)
		credentials = append(credentials, htmlCredentials...)
		gaps = append(gaps, htmlGaps...)
	}
	findings = append(findings, credentials...)
	for _, gap := range gaps {
		s.gap(gap.Stage, gap.URL, gap.Reason)
	}
	if len(findings) > 0 {
		if err := s.Store.PutWeb(ctx, "unit", unit.ID, s.task, unit); err != nil {
			return a, err
		}
		for _, f := range findings {
			if err := s.Store.PutWeb(ctx, "finding", f.ID, s.task, f); err != nil {
				return a, err
			}
		}
	}
	link := webanalysis.Relationship{ID: webanalysis.ID(a.ID, "captured-asset"), From: webanalysis.ID(a.URL, a.CapturedAt), To: a.ID, Kind: "captured-asset"}
	if err := s.Store.PutWeb(ctx, "relationship", link.ID, s.task, link); err != nil {
		return a, err
	}
	s.mu.Lock()
	s.coverage.Downloaded = webanalysis.AddUnique(s.coverage.Downloaded, a.ID)
	s.mu.Unlock()
	if a.Status == 429 {
		s.gap("challenge", a.URL, "rate-limit response; bounded HTTP retry did not resolve it")
	}
	preview := body
	if len(preview) > 64<<10 {
		preview = preview[:64<<10]
	}
	lower := strings.ToLower(string(preview))
	if strings.Contains(lower, "captcha") || strings.Contains(lower, "verify you are human") || strings.Contains(lower, "cf-chl-") {
		s.gap("challenge", a.URL, "browser challenge; use an isolated headed session for operator assistance")
	}
	if !a.Complete {
		return a, nil
	}
	if strings.Contains(a.MIME, "html") || a.Kind == "html" || a.Kind == "page" || a.Kind == "browser-dom" || a.Kind == "assisted-browser-dom" || a.Kind == "frame" {
		parsed := parseHTML(body, a.FinalURL)
		for _, g := range parsed.Gaps {
			s.gap(g.Stage, g.URL, g.Reason)
		}
		for _, in := range parsed.Inline {
			child := webanalysis.Artifact{DocumentURL: parsed.Base, Kind: in.Kind, URL: a.FinalURL, FinalURL: a.FinalURL, Role: a.Role, Parents: []string{a.ID}, Complete: true, CapturedAt: a.CapturedAt}
			ch, e := s.Store.SaveWebArtifact(ctx, child, in.Body)
			if e != nil {
				return a, e
			}
			if in.Language != "javascript" {
				unit := webanalysis.SourceUnit{ID: webanalysis.ID(ch.ID, fmt.Sprint(in.Offset), in.Name), Artifact: ch.ID, Hash: ch.Hash, URL: a.FinalURL, Name: in.Name, Language: in.Language, Kind: in.Kind, Offset: in.Offset, Parse: "not-executable"}
				if e := s.Store.PutWeb(ctx, "unit", unit.ID, s.task, unit); e != nil {
					return a, e
				}
				if in.Language == "json" {
					credentials, gaps := webanalysis.JSONCredentials(unit, a.Role, in.Body)
					for _, gap := range gaps {
						s.gap(gap.Stage, gap.URL, gap.Reason)
					}
					for _, finding := range credentials {
						if err := s.Store.PutWeb(ctx, "finding", finding.ID, s.task, finding); err != nil {
							return a, err
						}
					}
				}
			}
			if in.Language == "javascript" {
				if e = s.analyze(ctx, ch, in.Body, in.Offset, in.Name, in.Language, depth); e != nil {
					s.gap("parser", a.URL, e.Error())
				}
			}
		}
		for _, r := range parsed.Refs {
			s.enqueue(ctx, frontier{DocumentURL: parsed.Base, URL: r.URL, Kind: r.Kind, Parent: a.ID, Depth: depth + 1, Timestamp: a.CapturedAt})
		}
	} else if a.Kind == "manifest" || strings.Contains(a.MIME, "application/manifest+json") {
		s.manifest(ctx, a, body, depth)
	} else if isScript(a) {
		if e := s.analyze(ctx, a, body, 0, "", "", depth); e != nil {
			s.gap("parser", a.URL, e.Error())
		}
	}
	if isScript(a) {
		mapSource := body
		if strings.HasPrefix(a.SourceMap, "data:") {
			mapSource = append(append([]byte(nil), body...), []byte("\n//# sourceMappingURL="+a.SourceMap)...)
		}
		embedded, err := embeddedMaps(mapSource)
		if err != nil {
			s.gap("sourcemap", a.URL, err.Error())
		}
		for _, data := range embedded {
			mapArtifact := webanalysis.Artifact{DocumentURL: a.DocumentURL, Kind: "sourcemap", URL: a.FinalURL, FinalURL: a.FinalURL, Role: a.Role, Complete: true, Parents: []string{a.ID}, CapturedAt: a.CapturedAt}
			ma, e := s.Store.SaveWebArtifact(ctx, mapArtifact, data)
			if e != nil {
				return a, e
			}
			if e = s.sourceMap(ctx, ma, data, depth); e != nil {
				s.gap("sourcemap", a.URL, e.Error())
			}
		}
		for _, r := range mapReferences(a, body) {
			s.enqueue(ctx, frontier{DocumentURL: a.DocumentURL, URL: r, Kind: "sourcemap", Parent: a.ID, Depth: depth + 1, Timestamp: a.CapturedAt})
		}
	}
	if a.Kind == "sourcemap" {
		if err := s.sourceMap(ctx, a, body, depth); err != nil {
			s.gap("sourcemap", a.URL, err.Error())
		}
	}
	return a, nil
}
func isScript(a webanalysis.Artifact) bool {
	return a.Kind == "script" || a.Kind == "module" || a.Kind == "original-source" || a.Kind == "cdp-script" || strings.Contains(a.MIME, "javascript") || strings.Contains(a.MIME, "ecmascript")
}
func (s *Service) analyze(ctx context.Context, a webanalysis.Artifact, body []byte, offset int, name, lang string, depth int) error {
	if lang == "" {
		lang = "javascript"
		if strings.HasSuffix(a.URL, ".tsx") {
			lang = "tsx"
		} else if strings.HasSuffix(a.URL, ".ts") {
			lang = "typescript"
		} else if strings.HasSuffix(a.URL, ".jsx") {
			lang = "jsx"
		}
	}
	unit := webanalysis.SourceUnit{ID: webanalysis.ID(a.ID, fmt.Sprint(offset), name), Artifact: a.ID, Hash: a.Hash, DocumentURL: a.DocumentURL, URL: a.FinalURL, Name: name, Language: lang, Kind: a.Kind, Offset: offset}
	result, err := s.Parse(ctx, webanalysis.Input{Unit: unit, Source: body, Role: a.Role, Historical: a.CapturedAt != ""})
	if err != nil {
		unit.Parse = "failed"
		_ = s.Store.PutWeb(ctx, "unit", unit.ID, s.task, unit)
		return err
	}
	if err = s.persist(ctx, result); err != nil {
		return err
	}
	if len(result.Formatted) > 0 {
		_, err = s.Store.SaveWebArtifact(ctx, webanalysis.Artifact{Kind: "formatted-source", URL: a.URL, Role: a.Role, Complete: true, Parents: []string{a.ID}, CapturedAt: a.CapturedAt}, result.Formatted)
		if err != nil {
			return err
		}
	}
	for _, g := range result.Gaps {
		s.gap(g.Stage, g.URL, g.Reason)
	}
	for _, d := range result.Dependencies {
		if d.Expression != "" && d.URL == "" {
			s.gap("dependency", a.URL, "unresolved expression: "+webanalysis.RedactText(d.Expression))
			continue
		}
		if d.Kind == "url-lead" && !strings.HasSuffix(strings.Split(d.URL, "?")[0], ".js") {
			continue
		}
		u := resolve(a.FinalURL, d.URL)
		if u != "" {
			s.enqueue(ctx, frontier{DocumentURL: a.DocumentURL, URL: u, Kind: "script", Parent: a.ID, Depth: depth + 1, Timestamp: a.CapturedAt})
		}
	}
	return nil
}
func (s *Service) persist(ctx context.Context, r webanalysis.Result) error {
	records := []struct {
		k, id string
		v     any
	}{}
	for _, v := range r.Units {
		records = append(records, struct {
			k, id string
			v     any
		}{"unit", v.ID, v})
	}
	for _, v := range r.Functions {
		records = append(records, struct {
			k, id string
			v     any
		}{"function", v.ID, v})
	}
	for _, v := range r.Calls {
		records = append(records, struct {
			k, id string
			v     any
		}{"call", v.ID, v})
	}
	for _, v := range r.Operations {
		records = append(records, struct {
			k, id string
			v     any
		}{"operation", v.ID, v})
	}
	for _, v := range r.Relationships {
		records = append(records, struct {
			k, id string
			v     any
		}{"relationship", v.ID, v})
	}
	for _, v := range r.Findings {
		records = append(records, struct {
			k, id string
			v     any
		}{"finding", v.ID, v})
	}
	for _, v := range records {
		if err := s.Store.PutWeb(ctx, v.k, v.id, s.task, v.v); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) AnalyzeStored(ctx context.Context) error {
	snap, err := s.Store.WebSnapshot(ctx)
	if err != nil {
		return err
	}
	artifacts := map[string]webanalysis.Artifact{}
	analyzed := map[string]bool{}
	for _, a := range snap.Artifacts {
		artifacts[a.ID] = a
	}
	for _, u := range snap.Units {
		a := artifacts[u.Artifact]
		if !a.Complete || u.Parse == "not-executable" {
			continue
		}
		analyzed[a.ID] = true
		b, e := s.Store.WebBlob(u.Hash)
		if e != nil {
			return e
		}
		result, e := s.Parse(ctx, webanalysis.Input{Unit: u, Source: b, Role: a.Role, Historical: a.CapturedAt != ""})
		if e != nil {
			s.gap("parser", a.URL, e.Error())
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if e = s.persist(ctx, result); e != nil {
			return e
		}
		for _, gap := range result.Gaps {
			s.gap(gap.Stage, gap.URL, gap.Reason)
		}
	}
	for _, a := range snap.Artifacts {
		if ctx.Err() != nil {
			break
		}
		if analyzed[a.ID] || !a.Complete || !isScript(a) {
			continue
		}
		b, e := s.Store.WebBlob(a.Hash)
		if e != nil {
			return e
		}
		if e = s.analyze(ctx, a, b, 0, "", "", 0); e != nil {
			s.gap("parser", a.URL, e.Error())
		}
	}
	if err := s.RecordStage(context.Background(), "analysis"); err != nil {
		return err
	}
	return s.Features(ctx)
}
func (s *Service) Features(ctx context.Context) error {
	snap, err := s.Store.WebSnapshot(ctx)
	if err != nil {
		return err
	}
	features := map[string]webanalysis.Feature{}
	for _, o := range snap.Operations {
		for _, tag := range o.Features {
			f := features[tag]
			f.ID = webanalysis.ID("feature", tag)
			f.Name = tag
			f.Operations = webanalysis.AddUnique(f.Operations, o.ID)
			for _, c := range o.Calls {
				f.Calls = webanalysis.AddUnique(f.Calls, c)
			}
			for _, r := range o.Roles {
				f.Roles = webanalysis.AddUnique(f.Roles, r)
			}
			for _, c := range snap.Calls {
				for _, id := range o.Calls {
					if c.ID == id {
						for _, condition := range c.Conditions {
							f.Conditions = webanalysis.AddUnique(f.Conditions, condition)
						}
					}
				}
			}
			for _, coverage := range snap.Coverage {
				for _, route := range coverage.Routes {
					for _, rtag := range webanalysis.FeatureTags(route) {
						if rtag == tag {
							f.Routes = webanalysis.AddUnique(f.Routes, route)
						}
					}
				}
			}
			features[tag] = f
		}
	}
	keys := make([]string, 0, len(features))
	for k := range features {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		f := features[k]
		if e := s.Store.PutWeb(ctx, "feature", f.ID, s.task, f); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) Observe(ctx context.Context, e webanalysis.RequestExample) error {
	if err := s.Store.PutWeb(ctx, "request", webanalysis.RecordID(e), s.task, e); err != nil {
		return err
	}
	if e.ResourceType != "" && e.ResourceType != "xhr" && e.ResourceType != "fetch" && e.ResourceType != "websocket" {
		r := webanalysis.Relationship{ID: webanalysis.RecordID(e), From: e.Artifact, To: webanalysis.ID(e.URL, e.Method), Kind: "observed-resource", Expression: webanalysis.RedactURL(e.URL)}
		return s.Store.PutWeb(ctx, "relationship", r.ID, s.task, r)
	}
	o, err := webanalysis.FromObserved(e)
	if err != nil {
		return err
	}
	snap, err := s.Store.WebSnapshot(ctx)
	if err != nil {
		return err
	}
	for _, static := range snap.Operations {
		if webanalysis.MatchesObserved(static, o) {
			joined := webanalysis.MergeOperation(static, o)
			joined.ID = static.ID
			if err = s.Store.PutWeb(ctx, "operation", joined.ID, s.task, joined); err != nil {
				return err
			}
		}
	}
	return s.Store.PutWeb(ctx, "operation", o.ID, s.task, o)
}
func (s *Service) manifest(ctx context.Context, a webanalysis.Artifact, b []byte, depth int) {
	var v any
	if json.Unmarshal(b, &v) != nil {
		s.gap("manifest", a.URL, "invalid manifest")
		return
	}
	count := 0
	var walk func(any, int)
	walk = func(v any, d int) {
		if d > 12 || count > 2000 {
			return
		}
		count++
		switch x := v.(type) {
		case map[string]any:
			for _, n := range x {
				walk(n, d+1)
			}
		case []any:
			for _, n := range x {
				walk(n, d+1)
			}
		case string:
			if strings.HasSuffix(x, ".js") {
				s.enqueue(ctx, frontier{URL: resolve(a.FinalURL, x), Kind: "script", Parent: a.ID, Depth: depth + 1, Timestamp: a.CapturedAt})
			}
		}
	}
	walk(v, 0)
}

func sameOrigin(a, b string) bool {
	ua, e := webacquire.URL(a)
	ub, f := webacquire.URL(b)
	return e == nil && f == nil && ua.Scheme == ub.Scheme && ua.Host == ub.Host
}
func (s *Service) Gap(stage, url, reason string) { s.gap(stage, url, reason) }
func (s *Service) SetTask(id string)             { s.task = id }

func (s *Service) RecordStage(ctx context.Context, stage string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.coverage
	c.ID = webanalysis.ID(stage, webanalysis.Now())
	c.State = "complete"
	if ctx.Err() != nil {
		c.State = "interrupted"
	}
	c.Started = webanalysis.Now()
	c.Ended = c.Started
	c.Stages = []string{stage}
	if c.Role == "" {
		c.Role = "workspace"
	}
	return s.Store.PutWeb(ctx, "coverage", c.ID, s.task, c)
}

func (s *Service) RecordGap(ctx context.Context, role, stage, raw, reason string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	now := webanalysis.Now()
	c := webanalysis.Coverage{ID: webanalysis.ID("gap", role, stage, raw, reason, now), Role: role, Started: now, Ended: now, State: "blocked", Stages: []string{stage}, Gaps: []webanalysis.Gap{{Stage: stage, URL: raw, Reason: reason}}}
	if raw != "" {
		c.Targets = []string{raw}
	}
	return s.Store.PutWeb(ctx, "coverage", c.ID, s.task, c)
}
