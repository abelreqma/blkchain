package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"

	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/webacquire"
	"blkchain/cli/internal/webanalysis"
)

// extsurface.go runs the code-owned probes of one origin through the web broker and stores each result as a surface record bound to the output it came from.

// surfaceProbe names one stage of the sweep.
type surfaceProbe string

const (
	probeTLS       surfaceProbe = "tls"
	probeHeaders   surfaceProbe = "headers"
	probeCookies   surfaceProbe = "cookies"
	probeCORS      surfaceProbe = "cors"
	probeMethods   surfaceProbe = "methods"
	probeMetadata  surfaceProbe = "metadata"
	probeSubdomain surfaceProbe = "subdomains"
)

// allSurfaceProbes is the default sweep in run order, TLS first because its certificate names feed the derivation.
func allSurfaceProbes() []surfaceProbe {
	return []surfaceProbe{
		probeTLS, probeHeaders, probeCookies, probeCORS,
		probeMethods, probeMetadata, probeSubdomain,
	}
}

func knownSurfaceProbe(p surfaceProbe) bool {
	for _, v := range allSurfaceProbes() {
		if v == p {
			return true
		}
	}
	return false
}

// surfaceSweepRequest is one origin to enumerate.
type surfaceSweepRequest struct {
	// Origin is the absolute HTTP URL whose surface is enumerated.
	Origin string
	// TaskID and Surface attribute every record produced.
	TaskID  string
	Surface eng.Surface
	// Root bounds the passive subdomain derivation; empty uses the origin's host.
	Root string
	// Probes selects the stages. Empty runs them all.
	Probes []surfaceProbe
	// SchemeAssumed marks an origin whose scheme the caller supplied because the target named none, so the HTTP stages may fall back to http when no TLS version is reachable.
	SchemeAssumed bool
}

// surfaceSweepResult reports what the sweep stored and what it could not do.
type surfaceSweepResult struct {
	Origin  string          `json:"origin"`
	Stored  int             `json:"stored"`
	Ran     []surfaceProbe  `json:"ran,omitempty"`
	Gaps    []string        `json:"gaps,omitempty"`
	Records []string        `json:"records,omitempty"`
	TLS     json.RawMessage `json:"tls,omitempty"`
}

// surfaceSweepDeps are the broker that applies scope and bounds and the store that holds the records.
type surfaceSweepDeps struct {
	Broker *webacquire.Broker
	Store  *eng.Store
}

// surfaceRecordID derives the stable row id of one observation, so re-probing updates in place.
func surfaceRecordID(asset, kind, name string) string {
	return "surf:" + webanalysis.ID(asset, kind, name)[:40]
}

// recordEvidence stores a probe result's own JSON as an exact-quote evidence row and returns its id.
func (d surfaceSweepDeps) recordEvidence(taskID, label string, result any) (int64, error) {
	body, err := json.MarshalIndent(result, "", " ")
	if err != nil {
		return 0, err
	}
	return d.Store.RecordEvidence(taskID, label+"\n"+string(body))
}

// save persists one observation and returns its id.
func (d surfaceSweepDeps) save(ctx context.Context, req surfaceSweepRequest, ev int64,
	asset, kind, name, value, source, gap string, detail any) (string, error) {
	var raw json.RawMessage
	if detail != nil {
		b, err := json.Marshal(detail)
		if err != nil {
			return "", err
		}
		raw = b
	}
	quote := fmt.Sprintf("%s observation of %s\nkind=%s\nname=%s\nvalue=%s\nsource_evidence=%d",
		source, asset, kind, name, value, ev)
	observationID, err := d.Store.RecordEvidence(req.TaskID, quote)
	if err != nil {
		return "", err
	}
	r, err := d.Store.SaveSurface(ctx, eng.SurfaceRecord{
		ID: surfaceRecordID(asset, kind, name), TaskID: req.TaskID, Surface: req.Surface,
		Asset: asset, Kind: kind, Name: name, Value: value, Detail: raw,
		Source: source, Gap: gap, EvidenceID: observationID,
	})
	if err != nil {
		return "", err
	}
	return r.ID, nil
}

// sweepExternalSurface enumerates one origin and stores what it observed, recording a failed stage as a gap and continuing.
func sweepExternalSurface(ctx context.Context, d surfaceSweepDeps, req surfaceSweepRequest) (surfaceSweepResult, error) {
	if d.Broker == nil || d.Store == nil {
		return surfaceSweepResult{}, fmt.Errorf("external surface sweep needs a broker and a store")
	}
	u, err := webacquire.URL(req.Origin)
	if err != nil {
		return surfaceSweepResult{}, err
	}
	if req.TaskID == "" {
		return surfaceSweepResult{}, fmt.Errorf("external surface sweep needs a task")
	}
	asset := u.Hostname()
	origin := u.Scheme + "://" + u.Host
	out := surfaceSweepResult{Origin: origin}

	probes := req.Probes
	if len(probes) == 0 {
		probes = allSurfaceProbes()
	}
	for _, p := range probes {
		if !knownSurfaceProbe(p) {
			return surfaceSweepResult{}, fmt.Errorf("unknown surface probe %q", p)
		}
	}
	selected := map[surfaceProbe]bool{}
	for _, p := range probes {
		selected[p] = true
	}

	root := req.Root
	if root == "" {
		root = asset
	}
	tlsReached := false
	// The passive derivation reads only material the earlier probes captured.
	var sources []webanalysis.SubdomainSource

	for _, p := range allSurfaceProbes() {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if !selected[p] {
			continue
		}
		var ids []string
		var gap string
		switch p {
		case probeTLS:
			ids, gap, err = d.sweepTLS(ctx, req, u, asset, &sources, &out)
			tlsReached = len(out.TLS) > 0 && !strings.Contains(gap, "no certificate observed")
			// A guessed https origin that reached no TLS version is retried over http, so a plain-http service is described rather than gapped out.
			if req.SchemeAssumed && !tlsReached && u.Scheme == "https" {
				origin = "http://" + u.Host
				out.Origin = origin
				out.Gaps = append(out.Gaps, "tls: no version reached on the assumed https origin; the remaining stages used "+origin)
			}
		case probeHeaders:
			ids, gap, err = d.sweepHeaders(ctx, req, origin, asset, &sources)
		case probeCookies:
			ids, gap, err = d.sweepCookies(ctx, req, origin, asset)
		case probeCORS:
			ids, gap, err = d.sweepCORS(ctx, req, origin, asset)
		case probeMethods:
			ids, gap, err = d.sweepMethods(ctx, req, origin, asset)
		case probeMetadata:
			ids, gap, err = d.sweepMetadata(ctx, req, origin, asset)
		case probeSubdomain:
			ids, gap, err = d.sweepSubdomains(ctx, req, asset, root, sources)
		}
		if err != nil {
			return out, err
		}
		out.Ran = append(out.Ran, p)
		out.Records = append(out.Records, ids...)
		if gap != "" {
			out.Gaps = append(out.Gaps, string(p)+": "+gap)
		}
	}
	out.Stored = len(out.Records)
	return out, nil
}

// sweepTLS records each probed version and the certificate facts, and adds its names to the subdomain material.
func (d surfaceSweepDeps) sweepTLS(ctx context.Context, req surfaceSweepRequest, u *url.URL,
	asset string, sources *[]webanalysis.SubdomainSource, out *surfaceSweepResult) ([]string, string, error) {
	if u.Scheme != "https" {
		return nil, "the origin is not https, so no TLS configuration was probed", nil
	}
	obs, err := d.Broker.ProbeTLS(ctx, u.Hostname(), u.Port())
	if err != nil {
		return nil, "the TLS probe did not run: " + err.Error(), nil
	}
	if raw, mErr := json.Marshal(obs); mErr == nil {
		out.TLS = raw
	}
	ev, err := d.recordEvidence(req.TaskID, "tls probe of "+asset, obs)
	if err != nil {
		return nil, "", err
	}
	var ids []string
	for _, version := range []string{"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"} {
		value := "not determined"
		switch {
		case obs.Negotiated(version):
			value = "negotiated"
		case slices.Contains(obs.Refused, version):
			value = "refused"
		}
		id, err := d.save(ctx, req, ev, asset, "tls-protocol", version, value,
			"tls-probe", obs.Gap, map[string]string{"cipher": obs.Ciphers[version]})
		if err != nil {
			return ids, "", err
		}
		ids = append(ids, id)
	}
	if obs.Subject != "" {
		value := "valid"
		switch {
		case obs.Expired:
			value = "expired"
		case obs.NotYetValid:
			value = "not yet valid"
		case !obs.HostnameMatches:
			value = "name mismatch"
		case obs.SelfSigned:
			value = "self-signed"
		case !obs.ChainTrusted:
			value = "chain not trusted"
		}
		id, err := d.save(ctx, req, ev, asset, "tls-certificate", obs.Subject, value,
			"tls-probe", obs.ValidationError, obs)
		if err != nil {
			return ids, "", err
		}
		ids = append(ids, id)
		*sources = append(*sources, webanalysis.SubdomainSource{
			Kind: "certificate", Origin: asset, Values: obs.DNSNames, EvidenceID: ev,
		})
	}
	return ids, obs.Gap, nil
}

// sweepHeaders records the security headers set and absent, and adds the hosts they name to the subdomain material.
func (d surfaceSweepDeps) sweepHeaders(ctx context.Context, req surfaceSweepRequest,
	origin, asset string, sources *[]webanalysis.SubdomainSource) ([]string, string, error) {
	profile, err := d.Broker.ProfileHeaders(ctx, origin)
	if err != nil {
		return nil, "the header profile did not run: " + err.Error(), nil
	}
	ev, err := d.recordEvidence(req.TaskID, "header profile of "+origin, profile)
	if err != nil {
		return nil, "", err
	}
	var ids []string
	var values []string
	names := make([]string, 0, len(profile.Security))
	for name := range profile.Security {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		values = append(values, profile.Security[name])
		id, err := d.save(ctx, req, ev, asset, "http-header", name, profile.Security[name],
			"header-profile", "", nil)
		if err != nil {
			return ids, "", err
		}
		ids = append(ids, id)
	}
	for _, name := range profile.Missing {
		id, err := d.save(ctx, req, ev, asset, "http-header", name, "absent", "header-profile", "", nil)
		if err != nil {
			return ids, "", err
		}
		ids = append(ids, id)
	}
	exposed := make([]string, 0, len(profile.Exposed))
	for name := range profile.Exposed {
		exposed = append(exposed, name)
	}
	sort.Strings(exposed)
	for _, name := range exposed {
		values = append(values, profile.Exposed[name])
		id, err := d.save(ctx, req, ev, asset, "http-header", name, profile.Exposed[name],
			"header-profile", "names the software behind the origin", nil)
		if err != nil {
			return ids, "", err
		}
		ids = append(ids, id)
	}
	*sources = append(*sources, webanalysis.SubdomainSource{
		Kind: "header", Origin: asset, Values: values, EvidenceID: ev,
	})
	return ids, profile.Gap, nil
}

// sweepCookies records how the origin marks each cookie it sets.
func (d surfaceSweepDeps) sweepCookies(ctx context.Context, req surfaceSweepRequest,
	origin, asset string) ([]string, string, error) {
	cookies, err := d.Broker.ProfileCookies(ctx, origin)
	if err != nil {
		return nil, "the cookie profile did not run: " + err.Error(), nil
	}
	if len(cookies) == 0 {
		return nil, "the origin set no cookie on this request", nil
	}
	ev, err := d.recordEvidence(req.TaskID, "cookie profile of "+origin, cookies)
	if err != nil {
		return nil, "", err
	}
	var ids []string
	for _, c := range cookies {
		var missing []string
		if !c.Secure {
			missing = append(missing, "Secure")
		}
		if !c.HTTPOnly {
			missing = append(missing, "HttpOnly")
		}
		if c.SameSite == "" {
			missing = append(missing, "SameSite")
		}
		value := "Secure, HttpOnly, SameSite=" + c.SameSite
		if len(missing) > 0 {
			value = "missing " + strings.Join(missing, ", ")
		}
		id, err := d.save(ctx, req, ev, asset, "http-cookie", c.Name, value, "cookie-profile", "", c)
		if err != nil {
			return ids, "", err
		}
		ids = append(ids, id)
	}
	return ids, "", nil
}

// sweepCORS records what the origin grants a foreign origin.
func (d surfaceSweepDeps) sweepCORS(ctx context.Context, req surfaceSweepRequest,
	origin, asset string) ([]string, string, error) {
	profile, err := d.Broker.ProfileCORS(ctx, origin)
	if err != nil {
		return nil, "the CORS probe did not run: " + err.Error(), nil
	}
	ev, err := d.recordEvidence(req.TaskID, "cors probe of "+origin, profile)
	if err != nil {
		return nil, "", err
	}
	value := "no cross-origin access"
	switch {
	case profile.ReflectsOrigin && profile.AllowCredentials:
		value = "reflects a foreign origin with credentials"
	case profile.AllowsNullOrigin && profile.NullCredentials:
		value = "allows the null origin with credentials"
	case profile.ReflectsOrigin:
		value = "reflects a foreign origin"
	case profile.AllowsNullOrigin:
		value = "allows the null origin"
	case profile.Wildcard:
		value = "wildcard without credentials"
	case profile.AllowOrigin != "":
		value = "allows " + profile.AllowOrigin
	}
	id, err := d.save(ctx, req, ev, asset, "http-cors", "access-control-allow-origin", value,
		"cors-probe", profile.Gap, profile)
	if err != nil {
		return nil, "", err
	}
	return []string{id}, profile.Gap, nil
}

// sweepMethods records the methods the origin admits and whether TRACE echoes.
func (d surfaceSweepDeps) sweepMethods(ctx context.Context, req surfaceSweepRequest,
	origin, asset string) ([]string, string, error) {
	inv, err := d.Broker.InventoryMethods(ctx, origin)
	if err != nil {
		return nil, "the method inventory did not run: " + err.Error(), nil
	}
	if !inv.Reached {
		return nil, joinSurfaceGap("neither method request reached the origin", inv.Gap), nil
	}
	ev, err := d.recordEvidence(req.TaskID, "method inventory of "+origin, inv)
	if err != nil {
		return nil, "", err
	}
	var ids []string
	allowed := strings.Join(inv.Allow, ", ")
	if allowed == "" {
		allowed = "not stated"
	}
	id, err := d.save(ctx, req, ev, asset, "http-method", "OPTIONS", allowed, "method-inventory", inv.Gap, inv)
	if err != nil {
		return nil, "", err
	}
	ids = append(ids, id)
	trace := "not answered"
	if inv.TraceEchoes {
		trace = "echoes the request"
	} else if inv.TraceStatus > 0 {
		trace = fmt.Sprintf("status %d without an echo", inv.TraceStatus)
	}
	id, err = d.save(ctx, req, ev, asset, "http-method", "TRACE", trace, "method-inventory", inv.Gap, nil)
	if err != nil {
		return ids, "", err
	}
	return append(ids, id), inv.Gap, nil
}

// sweepMetadata records the metadata path census, carrying the controls' verdict as each record's gap.
func (d surfaceSweepDeps) sweepMetadata(ctx context.Context, req surfaceSweepRequest,
	origin, asset string) ([]string, string, error) {
	census, err := d.Broker.SweepPaths(ctx, origin, "HEAD", webacquire.MetadataPaths())
	if err != nil {
		return nil, "the metadata sweep did not run: " + err.Error(), nil
	}
	ev, err := d.recordEvidence(req.TaskID, "metadata path census of "+origin, census)
	if err != nil {
		return nil, "", err
	}
	gap := census.Gap
	if census.SoftNotFound {
		gap = joinSurfaceGap(gap, "a control path answered, so a status does not establish that a path exists")
	}
	var ids []string
	for _, p := range census.Paths {
		value := fmt.Sprintf("status %d", p.Status)
		if p.ContentType != "" {
			value += " " + p.ContentType
		}
		id, err := d.save(ctx, req, ev, asset, "http-path", p.Path, value, "metadata-census", gap, p)
		if err != nil {
			return ids, "", err
		}
		ids = append(ids, id)
	}
	return ids, gap, nil
}

// sweepSubdomains records the names under root that the earlier stages' captured material disclosed.
func (d surfaceSweepDeps) sweepSubdomains(ctx context.Context, req surfaceSweepRequest,
	asset, root string, sources []webanalysis.SubdomainSource) ([]string, string, error) {
	if len(sources) == 0 {
		return nil, "no captured material to derive names from; run the tls and headers probes first", nil
	}
	names := webanalysis.PassiveSubdomains(root, sources)
	if len(names) == 0 {
		return nil, "the captured material disclosed no name under " + root, nil
	}
	ev, err := d.recordEvidence(req.TaskID, "passive subdomain derivation under "+root, names)
	if err != nil {
		return nil, "", err
	}
	var ids []string
	for _, n := range names {
		value := n.Source
		if n.Wildcard {
			value = n.Source + " (wildcard)"
		}
		id, err := d.save(ctx, req, ev, asset, "dns-name", n.Name, value, "passive-derivation", "", n)
		if err != nil {
			return ids, "", err
		}
		ids = append(ids, id)
	}
	return ids, "", nil
}

func joinSurfaceGap(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}
