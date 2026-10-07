package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"blkchain/cli/internal/secgate"
)

// roeTemplate is the pre-formatted ROE.md written into an engagement workspace
// when none is detected. HTML comments carry the fill-in guidance so the empty
// template still parses as a valid (empty-scope) RoE. Out of scope always wins.
const roeTemplate = `# Rules of Engagement
<!-- Authorized engagement scope. Fill in each section below. -->

## Summary
Describe the authorized engagement here.

## Targets
<!-- domains, systems, users, or accounts in the engagement, one per line -->

## In Scope
<!-- hosts, IPs, or CIDRs allowed, one per line, e.g. 10.0.0.0/24

     An internal address - loopback, RFC1918 private, or link-local - is allowed
     only by its own explicit IP or CIDR line here, e.g. 127.0.0.1 or 10.0.0.0/8.
     A hostname line does NOT authorize the address it resolves to, so listing
     "localhost" leaves 127.0.0.1 out of scope. This is deliberate: a name that
     resolves inward must not reach an internal service by accident. -->

## Out of Scope
<!-- hosts, IPs, or CIDRs explicitly forbidden; out of scope always wins -->

## Rate
10/s

## Foothold
<!-- Optional. One host you already control, through which tasks on the covered
     surfaces run instead of in the isolated runner. The host must also be listed
     In Scope by name. Omit this section for an entirely external engagement.

     transport=ssh (the default) needs user= and key=; key= is a path, or $NAME
     naming an environment variable that holds the path. Add knownhosts= to pin
     the host key and refuse an unverified one.

     env=A,B forwards named environment variables to the carrier: each name's
     value from this process reaches the worker and the environment of every
     command it starts, so a carrier can authenticate. Nothing else from this
     environment crosses. PATH, HOME, and LANG are fixed by the worker and cannot
     be redirected by a declaration, and a name that is unset here contributes
     nothing. At most 64 names.

       10.0.0.9 user=svc-deploy key=$BLKCHAIN_FOOTHOLD_KEY

     transport=command carries commands with an argv prefix of your own, for
     access ssh cannot reach. exec= takes the rest of the line. Add quote=shell
     when the carrier hands the command to a shell rather than exec'ing argv.

       10.0.0.9 transport=command exec=kubectl exec -i web-0 --

     surfaces= selects which surfaces pivot; the default is local. Commands run
     on the foothold are outside the runner's network guard, so scope is enforced
     by the command gate alone and every such action records its destination.

     On a pivoted surface this host's PATH and symlinks no longer describe the file
     a command names, so a target-analysis task must name its inspection tool by
     absolute path (/usr/bin/file, not file). A bare name that matches the analysis
     target's own base name is refused, because on the foothold it could resolve to
     the target the task exists to inspect rather than execute. -->

## Allowed Actions
<!-- All actions below are enabled. Wrap an entire entry in an HTML comment to disable it. -->
- command
- local
- api-read
- api-write
- browser-read
- browser-write

## Autonomous Actions
<!-- One "phase/surface target" per line, naming an action class this engagement may
     arm without asking. Accepted classes are exploit/<surface>, post-ex/<surface>,
     and recon/local; any other phase, recon/network among them, is rejected,
     because reconnaissance needs no arming outside the local surface.

     <surface> is one of local, network, web, ad, cloud (or cloud-aws, cloud-gcp,
     cloud-azure), container, ai-security. target must also be In Scope.

       exploit/network 192.0.2.1
       recon/local local

     Leave this section empty to arm nothing automatically. -->
`

// writeRoETemplate writes roeTemplate to <dir>/ROE.md when that file does not
// already exist. It never overwrites an existing ROE.md (idempotent); it returns
// whether it wrote the file.
func writeRoETemplate(dir string) (bool, error) {
	path := filepath.Join(dir, "ROE.md")
	// O_EXCL makes the create atomic: an existing file is left untouched.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	if _, err := f.WriteString(roeTemplate); err != nil {
		return false, err
	}
	return true, nil
}

// roe.go parses an optional ROE.md (Rules of Engagement) into the extended
// secgate.Scope. ROE.md is the primary scope source for an engagement; the
// older line-based --scope file remains for back-compat. Parsing fails closed:
// a malformed scope entry or rate yields an error, never a silent permissive
// scope. The ctrl+g RoE editor UI is a separate session; this file is parse and
// template only.

// RoE is a parsed ROE.md. Summary and Targets are informational (for the
// report); Scope carries the enforced In/Out matchers and the optional Rate.
type RoE struct {
	Summary     string
	Targets     []string
	Scope       *secgate.Scope
	AutoActions *autoActionPolicy
	Policy      *secgate.Policy
}

// ParseRoE reads an ROE.md. The recognized level-2+ sections are the ones
// roeSections names (heading match is case-insensitive). Within a
// section, bullet lines (- / * / +) and bare non-empty lines are entries. An
// UNRECOGNIZED level-2+ heading is a parse error (fail closed): silently dropping
// a typo'd or synonym heading would discard an operator's exclusions and defeat
// the gate. A level-1 heading is treated as a document title (ignored). An empty
// file yields an RoE with an empty scope (the no-RoE floor applies downstream).
func ParseRoE(r io.Reader) (*RoE, error) {
	data, err := io.ReadAll(io.LimitReader(r, (256<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 256<<10 {
		return nil, fmt.Errorf("ROE.md exceeds 256 KiB")
	}
	r = strings.NewReader(string(data))
	policy := secgate.DefaultPolicy()
	seen := map[string]bool{}
	keys := map[string]bool{}
	var summary []string
	var spec secgate.ScopeSpec
	var autoEntries []string
	var foothold *secgate.Foothold
	section := ""
	inComment := false

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if inComment {
			if strings.Contains(line, "-->") {
				inComment = false
			}
			continue
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "<!--") {
			if !strings.Contains(line, "-->") {
				inComment = true // multi-line comment; skip until its close
			}
			continue // template guidance
		}
		if h, level, ok := headingText(line); ok {
			if level == 1 {
				section = "" // document title, not a section
				continue
			}
			key := normalizeSection(h)
			if !isKnownSection(key) {
				return nil, fmt.Errorf("ROE.md: unrecognized section heading %q (expected: %s)", h, strings.Join(roeSections, ", "))
			}
			if seen[key] {
				return nil, fmt.Errorf("ROE.md: duplicate section %q", h)
			}
			seen[key] = true
			if key == "allowed actions" {
				policy.Allowed = nil
			}
			section = key
			continue
		}
		entry := stripBullet(line)
		if entry == "" {
			continue
		}
		switch section {
		case "summary":
			summary = append(summary, entry)
		case "targets":
			spec.Targets = append(spec.Targets, entry)
		case "in scope":
			if strings.EqualFold(entry, "local") {
				spec.Local = true
			} else {
				spec.In = append(spec.In, entry)
			}
		case "out of scope":
			spec.Out = append(spec.Out, entry)
		case "rate":
			if spec.Rate != "" {
				return nil, fmt.Errorf("ROE.md: duplicate rate")
			}
			spec.Rate = entry
		case "allowed actions", "denied actions":
			if !secgate.KnownAction(entry) {
				return nil, fmt.Errorf("ROE.md: unknown action %q", entry)
			}
			if section == "allowed actions" {
				policy.Allowed = append(policy.Allowed, entry)
			} else {
				policy.Denied = append(policy.Denied, entry)
			}
		case "denied commands":
			if err := addRoEDenial(policy, entry); err != nil {
				return nil, err
			}
		case "resource caps", "runner":
			if err := setRoEValue(policy, section, entry, keys); err != nil {
				return nil, err
			}
		case "autonomous actions":
			autoEntries = append(autoEntries, entry)
		case "foothold":
			if foothold != nil {
				return nil, fmt.Errorf("ROE.md: Foothold takes one entry")
			}
			f, err := secgate.ParseFoothold(entry)
			if err != nil {
				return nil, fmt.Errorf("ROE.md: %w", err)
			}
			foothold = f
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	scope, err := secgate.BuildScope(spec)
	if err != nil {
		return nil, err
	}
	autoActions, err := buildAutoActionPolicy(autoEntries, scope)
	if err != nil {
		return nil, err
	}
	// The foothold is sealed with the rest of the policy, so a resume with a
	// different foothold is a different policy and is refused.
	if foothold != nil {
		if err := secgate.FootholdInScope(scope, foothold); err != nil {
			return nil, fmt.Errorf("ROE.md: %w", err)
		}
		policy.Foothold = foothold
	}
	if err := policy.Seal(strings.Join(summary, "\n"), spec.Targets, scope); err != nil {
		return nil, fmt.Errorf("ROE.md: %w", err)
	}
	return &RoE{
		Summary:     strings.Join(summary, "\n"),
		Targets:     spec.Targets,
		Scope:       scope,
		AutoActions: autoActions,
		Policy:      policy,
	}, nil
}

// headingText returns the text and level of a markdown ATX heading (one or more
// leading '#' then whitespace), and whether the line is a heading.
func headingText(line string) (text string, level int, ok bool) {
	if !strings.HasPrefix(line, "#") {
		return "", 0, false
	}
	t := strings.TrimLeft(line, "#")
	level = len(line) - len(t)
	if t == "" || (t[0] != ' ' && t[0] != '\t') {
		return "", 0, false // "###" alone or "#notaheading" is not a usable heading
	}
	return strings.TrimSpace(t), level, true
}

// isKnownSection reports whether a normalized heading is one of the recognized
// ROE.md sections.
// roeSections is the one list of sections ParseRoE accepts, in the order the
// unrecognized-heading error names them. isKnownSection and that error message both
// read it, so the two cannot disagree: the message previously listed seven of the
// twelve and told an operator that Allowed Actions, which the template itself
// emits, was not expected.
var roeSections = []string{
	"Summary", "Targets", "In Scope", "Out of Scope", "Rate", "Foothold",
	"Allowed Actions", "Denied Actions", "Denied Commands", "Autonomous Actions",
	"Resource Caps", "Runner",
}

func isKnownSection(key string) bool {
	for _, name := range roeSections {
		if normalizeSection(name) == key {
			return true
		}
	}
	return false
}

// normalizeSection lowercases and collapses internal whitespace of a heading so
// "In  Scope" and "in scope" match the same section key.
func normalizeSection(h string) string {
	return strings.Join(strings.Fields(strings.ToLower(h)), " ")
}

// stripBullet removes a single leading markdown bullet marker (-, *, +) and the
// following space from an entry line.
func stripBullet(line string) string {
	if len(line) >= 2 && (line[0] == '-' || line[0] == '*' || line[0] == '+') && (line[1] == ' ' || line[1] == '\t') {
		return strings.TrimSpace(line[1:])
	}
	return strings.TrimSpace(line)
}
