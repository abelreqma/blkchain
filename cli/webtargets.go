package main

import (
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/webacquire"
	"blkchain/cli/internal/webanalysis"
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type webTargets struct {
	URLs  []string
	Scope *secgate.Scope
	Gaps  []webanalysis.Gap
}

var webReverseLookup = net.DefaultResolver.LookupAddr

func webResolveTargets(ctx context.Context, inputs []string, rdns bool) (webTargets, error) {
	var out webTargets
	if len(inputs) > 100 {
		return out, errors.New("target input limit")
	}
	raw := []string{}
	for _, input := range inputs {
		input = strings.TrimPrefix(input, "@")
		if st, e := os.Stat(input); e == nil && st.Mode().IsRegular() {
			b, e := webReadFile(input, 1<<20)
			if e != nil {
				return out, e
			}
			if strings.EqualFold(filepath.Ext(input), ".md") {
				roe, e := ParseRoE(bytes.NewReader(b))
				if e != nil {
					return out, e
				}
				if out.Scope != nil {
					return out, errors.New("supply one engagement scope document")
				}
				out.Scope = roe.Scope
				raw = append(raw, roe.Targets...)
				if len(roe.Targets) == 0 {
					sc := bufio.NewScanner(bytes.NewReader(b))
					section := ""
					for sc.Scan() {
						line := strings.TrimSpace(sc.Text())
						if strings.HasPrefix(line, "## ") {
							section = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "## ")))
							continue
						}
						if section == "in scope" && line != "" && !strings.HasPrefix(line, "<!--") {
							raw = append(raw, strings.TrimSpace(strings.TrimLeft(line, "-*+ ")))
						}
					}
				}
			} else {
				sc := bufio.NewScanner(bytes.NewReader(b))
				for sc.Scan() {
					line := strings.TrimSpace(sc.Text())
					if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "allow ") {
						continue
					}
					raw = append(raw, strings.TrimSpace(strings.TrimPrefix(line, "- ")))
				}
				if sc.Err() != nil {
					return out, sc.Err()
				}
			}
		} else if strings.HasPrefix(input, "@") || strings.ContainsAny(input, "\\") || strings.HasSuffix(input, ".txt") || strings.HasSuffix(input, ".md") {
			return out, errors.New("target file not found")
		} else {
			raw = append(raw, strings.Split(input, ",")...)
		}
		if len(raw) > 100 {
			return out, errors.New("target list limit")
		}
	}
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, _, e := net.ParseCIDR(value); e == nil {
			out.Gaps = append(out.Gaps, webanalysis.Gap{Stage: "target", URL: value, Reason: "CIDR is scope; supply bounded individual web hosts"})
			continue
		}
		ip := net.ParseIP(strings.Trim(value, "[]"))
		if ip == nil && strings.Contains(value, "://") {
			if u, e := webacquire.URL(value); e == nil {
				ip = net.ParseIP(u.Hostname())
			}
		}
		if ip != nil && rdns {
			lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			names, e := webReverseLookup(lookupCtx, ip.String())
			cancel()
			if e != nil || len(names) == 0 {
				out.Gaps = append(out.Gaps, webanalysis.Gap{Stage: "reverse-dns", URL: ip.String(), Reason: "no reverse-DNS name available"})
			}
			for i, n := range names {
				if i >= 10 {
					out.Gaps = append(out.Gaps, webanalysis.Gap{Stage: "reverse-dns", URL: ip.String(), Reason: "reverse-DNS result limit"})
					break
				}
				n = strings.TrimSuffix(n, ".")
				if u, e := webacquire.URL("https://" + n); e == nil {
					out.URLs = webanalysis.AddUnique(out.URLs, u.String())
				}
			}
		}
		if !strings.Contains(value, "://") {
			if ip != nil && strings.Contains(value, ":") {
				value = "[" + ip.String() + "]"
			}
			value = "https://" + value
		}
		u, e := webacquire.URL(value)
		if e != nil {
			return out, e
		}
		u.Fragment = ""
		u.Host = strings.ToLower(u.Host)
		if ip == nil {
			host := u.Hostname()
			if _, e := secgate.BuildScope(secgate.ScopeSpec{In: []string{host}}); e != nil {
				return out, errors.New("invalid target hostname")
			}
		}
		out.URLs = webanalysis.AddUnique(out.URLs, u.String())
	}
	if len(out.URLs) > 100 {
		return out, errors.New("resolved target limit")
	}
	return out, nil
}
func webTargetMatches(raw string, targets []string) bool {
	if len(targets) == 0 {
		return true
	}
	u, e := url.Parse(raw)
	if e != nil {
		return false
	}
	for _, t := range targets {
		v, e := url.Parse(t)
		if e == nil && strings.EqualFold(v.Hostname(), u.Hostname()) {
			return true
		}
	}
	return false
}
func webFilter(s webanalysis.Snapshot, targets []string) webanalysis.Snapshot {
	if len(targets) == 0 {
		return s
	}
	out := webanalysis.Snapshot{}
	artifacts, units, calls, ops := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, a := range s.Artifacts {
		if webTargetMatches(a.URL, targets) || webTargetMatches(a.FinalURL, targets) || webTargetMatches(a.DocumentURL, targets) {
			out.Artifacts = append(out.Artifacts, a)
			artifacts[a.ID] = true
		}
	}
	for _, u := range s.Units {
		if artifacts[u.Artifact] {
			out.Units = append(out.Units, u)
			units[u.ID] = true
		}
	}
	for _, f := range s.Functions {
		if units[f.Location.Unit] {
			out.Functions = append(out.Functions, f)
		}
	}
	for _, c := range s.Calls {
		if units[c.Location.Unit] {
			out.Calls = append(out.Calls, c)
			calls[c.ID] = true
		}
	}
	for _, o := range s.Operations {
		match := webTargetMatches(o.Origin, targets)
		for _, c := range o.Calls {
			match = match || calls[c]
		}
		if match {
			out.Operations = append(out.Operations, o)
			ops[o.ID] = true
		}
	}
	for _, r := range s.Relationships {
		if artifacts[r.From] || artifacts[r.To] || units[r.From] || calls[r.From] || ops[r.To] {
			out.Relationships = append(out.Relationships, r)
		}
	}
	for _, f := range s.Findings {
		if units[f.Location.Unit] || artifacts[f.Location.Unit] {
			out.Findings = append(out.Findings, f)
		}
	}
	for _, f := range s.Features {
		for _, o := range f.Operations {
			if ops[o] {
				out.Features = append(out.Features, f)
				break
			}
		}
	}
	for _, c := range s.Coverage {
		match := len(c.Targets) == 0 && len(c.Routes) == 0 && len(c.Downloaded) == 0
		for _, target := range c.Targets {
			match = match || webTargetMatches(target, targets)
		}
		for _, a := range c.Downloaded {
			match = match || artifacts[a]
		}
		for _, r := range c.Routes {
			match = match || webTargetMatches(r, targets)
		}
		if match {
			out.Coverage = append(out.Coverage, c)
		}
	}
	for _, r := range s.Requests {
		if webTargetMatches(r.URL, targets) {
			out.Requests = append(out.Requests, r)
		}
	}
	for _, e := range s.Exports {
		if ops[e.Operation] {
			out.Exports = append(out.Exports, e)
		}
	}
	return out
}
