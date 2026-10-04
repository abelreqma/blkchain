package main

import (
	"blkchain/cli/internal/webanalysis"
	"fmt"
	"sort"
	"strings"
)

func webView(s webanalysis.Snapshot, view string, interactive bool, width int) string {
	s = webanalysis.Display(s)
	var b strings.Builder
	heading := func(icon, title string) {
		if interactive {
			fmt.Fprintf(&b, " %s %s\n", icon, H1.Render(title))
		} else {
			fmt.Fprintf(&b, "%s\n", title)
		}
	}
	if width < 30 {
		width = 80
	}
	line := func(v string) {
		if interactive {
			b.WriteString(wrapIndent(sanitizeTerminal(v), 3, width) + "\n")
		} else {
			b.WriteString(sanitizeTerminal(v) + "\n")
		}
	}
	heading("\U0001f310", "Web analysis")
	line(fmt.Sprintf("%d artifacts  %d source units  %d functions  %d API operations", len(s.Artifacts), len(s.Units), len(s.Functions), len(s.Operations)))
	line("Discovery and validation remain independent. Findings are analysis leads.")
	show := func(v string) bool { return view == "all" || view == v }
	if show("apis") {
		heading("\U0001f517", "API operations")
		for _, o := range s.Operations {
			line(fmt.Sprintf("%s %s%s%s  %s  [%s]  role %s", o.Method, o.Origin, o.Path, func() string {
				if o.Query != "" {
					return "?" + o.Query
				}
				return ""
			}(), o.Protocol, o.Validation, strings.Join(o.Roles, ",")))
			line("  discovery " + strings.Join(o.Discoveries, ",") + "  features " + strings.Join(o.Features, ",") + "  id " + o.ID)
			for _, p := range o.Parameters {
				line("  " + p.Field + " <- " + p.Expression + "  type " + p.Type)
			}
			for _, example := range o.Examples {
				if example.Direction != "" {
					line(fmt.Sprintf("  WebSocket %s  opcode %d  sequence %d  encoding %s  denied %t", example.Direction, example.Opcode, example.Sequence, example.Encoding, example.Denied))
				}
				if example.Worker != "" {
					line("  worker " + example.Worker)
				}
				line(fmt.Sprintf("  request %s %s  status %d  role %s", example.Method, example.URL, example.Status, example.Role))
				keys := []string{}
				for key := range example.Headers {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					line("  " + key + ": " + strings.Join(example.Headers[key], ", "))
				}
				if example.Body != "" {
					line("  body " + example.Body)
				}
			}
			if o.GraphQL != "" {
				line("  GraphQL " + o.GraphQL)
			}
			for _, u := range o.Unresolved {
				line("  unresolved " + u)
			}
		}
	}
	if show("artifacts") {
		heading("\U0001f4e6", "Artifacts")
		for _, a := range s.Artifacts {
			state := "complete"
			if !a.Complete {
				state = "incomplete"
			}
			line(fmt.Sprintf("%s %s  %d bytes  %s  role %s", a.Kind, a.URL, a.Size, state, a.Role))
			line("  sha256 " + a.Hash + "  capture " + a.CapturedAt + "  retrieved " + a.RetrievedAt)
			if a.Gap != "" {
				line("  gap " + a.Gap)
			}
		}
	}
	if show("functions") {
		heading("\U0001f9e9", "Functions and calls")
		for _, f := range s.Functions {
			line(fmt.Sprintf("%s  unit %s:%d:%d  enclosing %s", f.Name, f.Location.Unit, f.Location.Line, f.Location.Column, f.Enclosing))
			for _, p := range f.Parameters {
				line("  parameter " + p.Name + " default " + p.Default)
			}
		}
		for _, c := range s.Calls {
			line(fmt.Sprintf("%s(%s)  line %d  function %s", c.Callee, strings.Join(c.Arguments, ", "), c.Location.Line, c.Function))
		}
	}
	if show("features") {
		heading("\U0001f5c2", "Features")
		for _, f := range s.Features {
			line(fmt.Sprintf("%s  %d operations  %d calls  roles %s", f.Name, len(f.Operations), len(f.Calls), strings.Join(f.Roles, ",")))
			line("  routes " + strings.Join(f.Routes, ", ") + " conditions " + strings.Join(f.Conditions, ", "))
		}
	}
	if show("findings") {
		heading("\U0001f50e", "Findings")
		for _, f := range s.Findings {
			line(fmt.Sprintf("%s [%s]  %s:%d  %s  %s", f.Kind, f.Confidence, f.Location.Unit, f.Location.Line, f.Detector, f.Preview))
			if f.Library != "" {
				line("  library " + f.Library + " version " + f.LibraryVersion + " advisory " + f.Advisory + " snapshot " + f.Snapshot)
			}
		}
	}
	if show("coverage") || view == "summary" {
		heading("\U0001f4cb", "Coverage")
		for _, c := range s.Coverage {
			role := c.Role
			if role == "" {
				role = "workspace"
			}
			line(fmt.Sprintf("role %s  %s  %d routes  %d interactions  %d requests  %d bytes", role, c.State, len(c.Routes), len(c.Interactions), c.Requests, c.Bytes))
			line("  stages " + strings.Join(c.Stages, ", "))
			if show("coverage") {
				for _, target := range c.Targets {
					line("  target " + target)
				}
				for _, route := range c.Routes {
					line("  visited " + route)
				}
				for _, action := range c.Interactions {
					line("  interaction " + action)
				}
				for _, artifact := range c.Downloaded {
					line("  downloaded " + artifact)
				}
			}
			for _, g := range c.Gaps {
				line("gap: " + g.Stage + " " + g.URL + " " + g.Reason)
			}
		}
	}
	if show("exports") {
		heading("\U0001f4e4", "Exports")
		for _, e := range s.Exports {
			line(e.Command)
			line("  " + strings.Join(e.Gaps, "; "))
		}
	}
	if view == "summary" {
		line("Use --view apis, artifacts, functions, features, findings, coverage, exports, or all.")
	}
	return b.String()
}
