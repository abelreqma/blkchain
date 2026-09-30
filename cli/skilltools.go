package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/skillcat"
	"blkchain/cli/internal/tooldef"
)

const routeSkillBodyCap = 8000

type routeSkillArgs struct {
	Domain string `json:"domain" desc:"an engagement domain (generic, recon, web, ad, cloud, k8s, wifi, exploit-dev) or a kind/vuln-class keyword such as kerberos, xss, or adcs, to route a skill for"`
}

// resolveDomain maps a domain or kind/vuln-class keyword to a domain bucket
// name. It is the single source of truth for route_skill resolution. An exact
// domain name (case and space insensitive) wins; otherwise skillcat.DeriveDomain
// keyword-matches the input, and no keyword yields generic. It returns only a
// bucket name, never a skill name, and touches no file.
func resolveDomain(domain string) string {
	name := domainFor(domain).Name
	if name == "generic" && strings.TrimSpace(strings.ToLower(domain)) != "generic" {
		if d := skillcat.DeriveDomain(domain, ""); d != "generic" {
			return d
		}
	}
	return name
}

// routeSkillFor is the single deterministic domain->skill selection used by
// both the tooldef route_skill tool and the blk mcp route_skill tool. It maps
// domain through resolveDomain (exact domain name, else a keyword match, else
// generic) then returns the name-sorted first skill in that catalog bucket, so
// a caller can never pin a skill by name. cat may be nil. It records no receipt
// and opens no file. The returned bool is false when no skill is available for
// the resolved domain.
func routeSkillFor(cat *skillcat.Catalog, domain string) (skillcat.Skill, bool) {
	name := resolveDomain(domain)
	if cat == nil {
		return skillcat.Skill{}, false
	}
	skills := cat.ForDomain(name)
	if len(skills) == 0 {
		return skillcat.Skill{}, false
	}
	return skills[0], true
}

// newRouteSkillTool builds the deterministic route_skill tool. See the doc.
func newRouteSkillTool(cat *skillcat.Catalog, st *engagement.Store, activeTask func() string) tooldef.Tool {
	return newStoreTool("route_skill",
		"Get the playbook for an engagement domain. Provide one domain (generic, recon, web, ad, cloud, k8s, wifi, exploit-dev) or a kind/vuln-class keyword (for example kerberos, xss, adcs); the harness selects the skill deterministically and returns its playbook. You cannot choose a specific skill by name; an unrecognized domain returns the generic playbook or a clear no-skill message.",
		routeSkillArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			var a routeSkillArgs
			if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
				return "route_skill: invalid arguments: " + err.Error(), nil
			}
			sk, ok := routeSkillFor(cat, a.Domain)
			if !ok {
				return "route_skill: no skill available for domain " + resolveDomain(a.Domain), nil
			}
			if st != nil && activeTask != nil {
				if tid := activeTask(); tid != "" {
					_, _ = st.RecordReceipt(tid, sk.Name, sk.Digest)
				}
			}
			body := sk.Body
			if r := []rune(body); len(r) > routeSkillBodyCap {
				body = string(r[:routeSkillBodyCap]) + "\n...[truncated]"
			}
			var b strings.Builder
			fmt.Fprintf(&b, "skill: %s (domain %s)\n%s\n\n%s", sk.Name, sk.Domain, sk.Description, strings.TrimSpace(body))
			return b.String(), nil
		})
}
