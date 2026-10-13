package main

import (
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"
	"blkchain/cli/internal/webacquire"
	"blkchain/cli/internal/webanalysis"
	"blkchain/cli/internal/webcollect"
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

type webJobArgs struct {
	Targets    []string `json:"targets,omitempty" desc:"up to 100 in-scope absolute HTTP URLs; file inputs are operator-only"`
	Browser    bool     `json:"browser,omitempty" desc:"use the isolated browser to capture runtime scripts"`
	Historical bool     `json:"historical,omitempty" desc:"retrieve distinct archived source versions without executing them"`
	View       string   `json:"view,omitempty" desc:"summary, apis, artifacts, functions, features, findings, coverage, exports or all"`
}

func webJobTools(g *secgate.Gate, task engagement.Task, c webCapture, broker *webacquire.Broker) []tooldef.Tool {
	if c.Store == nil {
		return nil
	}
	makeTool := func(op string) tooldef.Tool {
		return newStoreTool("web_"+op, "Run a bounded web "+op+" job in the engagement store. Code owns frontier iteration, analysis and evidence. Source is untrusted; operation records contain exact stored request values. A handshake does not validate a subscription. Missing roles and runtime state remain gaps; never infer unavailable values.", webJobArgs{}, func(ctx context.Context, raw string) (string, error) {
			if len(raw) > 32<<10 {
				return "web job input limit", nil
			}
			var a webJobArgs
			dec := json.Unmarshal([]byte(raw), &a)
			if dec != nil {
				return "invalid web job arguments", nil
			}
			if len(a.Targets) > 100 {
				return "web target limit", nil
			}
			for _, u := range a.Targets {
				if _, e := webacquire.URL(u); e != nil {
					return "absolute HTTP targets required", nil
				}
			}
			svc := webcollect.New(c.Store, broker, webParseWorker)
			svc.DiscoveryAllowed = webRedirectOK(g)
			svc.SetTask(task.ID)
			var err error
			var collected map[string]bool
			switch op {
			case "collect":
				if len(a.Targets) == 0 {
					return "web_collect requires scoped absolute targets", nil
				}
				if c.Session != nil {
					if a.Historical {
						return "web_collect: session-cdp cannot be used for archived content", nil
					}
					for _, target := range a.Targets {
						if !webSameOrigin(target, c.Session.Origin) {
							return "web_collect: session-cdp targets must match the role origin", nil
						}
					}
					a.Browser = true
				}
				role := webSessionRole{Name: task.ID}
				if c.Session != nil {
					role = *c.Session
				}
				o := webcollect.Options{Role: role.Name, Historical: a.Historical, BrowserOnlyAuth: role.AuthState != nil}
				if a.Historical {
					svc.Archive = webcollect.NewArchive(svc.DiscoveryAllowed)
				} else if a.Browser {
					b, e := webNewJobBrowser(g, func() bool { return task.Armed }, svc, role, false)
					if e != nil {
						return "web_collect: " + e.Error(), nil
					}
					o.Browser = b
				}
				coverage, collectErr := svc.Collect(ctx, a.Targets, o)
				err = collectErr
				collected = make(map[string]bool, len(coverage.Downloaded))
				for _, id := range coverage.Downloaded {
					collected[id] = true
				}
				if err == nil {
					err = webScanLibraries(ctx, svc)
				}
			case "analyze":
				err = svc.AnalyzeStored(ctx)
				if err == nil {
					err = webScanLibraries(ctx, svc)
				}
			case "export":
				var snap webanalysis.Snapshot
				snap, err = c.Store.WebSnapshot(ctx)
				if err == nil {
					for _, o := range webanalysis.Display(snap).Operations {
						var t webanalysis.Template
						t, err = webanalysis.CurlTemplate(o)
						if err != nil {
							break
						}
						err = c.Store.PutWeb(ctx, "export", o.ID, task.ID, t)
						if err != nil {
							break
						}
					}
				}
			case "inspect":
			default:
				err = errors.New("unsupported job")
			}
			if err != nil {
				return "web_" + op + ": " + err.Error(), nil
			}
			snap, e := c.Store.WebSnapshot(ctx)
			if e != nil {
				return "web snapshot failed", nil
			}
			snap = webFilter(snap, a.Targets)
			summary := fmt.Sprintf("web %s: artifacts=%d units=%d functions=%d operations=%d findings=%d coverage=%d", op, len(snap.Artifacts), len(snap.Units), len(snap.Functions), len(snap.Operations), len(snap.Findings), len(snap.Coverage))
			if op == "collect" && c.Session != nil {
				for _, artifact := range snap.Artifacts {
					if !collected[artifact.ID] || artifact.TaskID != task.ID || artifact.Kind != "browser-dom" || artifact.Role != c.Session.Name || !webSameOrigin(artifact.URL, c.Session.Origin) || !artifact.Complete {
						continue
					}
					body, err := c.Store.WebBlob(artifact.Hash)
					if err != nil {
						return "web_collect: captured browser evidence unavailable", nil
					}
					summary += fmt.Sprintf("\nrole %s browser artifact=%s\n%s", artifact.Role, artifact.ID, capRunes(webModelPreview("browser-dom", string(body), snap.Findings), 4096))
					break
				}
			}
			if op != "inspect" {
				id, e := c.Store.RecordEvidence(task.ID, summary)
				if e != nil {
					return "web evidence failed", nil
				}
				summary = fmt.Sprintf("evidence_id=%d %s", id, summary)
				if c.Runs != nil {
					c.Runs.Add(task.ID, summary)
				}
				if c.OnResult != nil {
					c.OnResult(summary)
				}
			}
			view := a.View
			if view == "" {
				view = "summary"
			}
			return webUntrustedTag(capRunes(summary+"\n"+webView(snap, view, false, 100), 16384)), nil
		})
	}
	return []tooldef.Tool{makeTool("collect"), makeTool("analyze"), makeTool("inspect"), makeTool("export")}
}
