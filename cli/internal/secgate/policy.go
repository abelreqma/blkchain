package secgate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"
)

type CommandDenial struct {
	Binary string `json:"binary"`
	Arg    string `json:"argument,omitempty"`
}

type Policy struct {
	Allowed        []string        `json:"allowed_actions"`
	Denied         []string        `json:"denied_actions,omitempty"`
	Commands       []CommandDenial `json:"denied_commands,omitempty"`
	MaxCommands    int             `json:"max_commands"`
	MaxActions     int             `json:"max_actions"`
	WallSeconds    int             `json:"wall_seconds"`
	CommandSeconds int             `json:"command_seconds"`
	OutputBytes    int             `json:"output_bytes"`
	TotalBytes     int             `json:"total_bytes"`
	Parallel       int             `json:"parallel"`
	RunnerImage    string          `json:"runner_image,omitempty"`
	RunnerID       string          `json:"runner_id"`
	Canonical      string          `json:"-"`
	Hash           string          `json:"-"`
	CommandIPs     *Scope          `json:"-"`
}

func DefaultPolicy() *Policy {
	return &Policy{Allowed: []string{"command", "api-read", "browser-read"}, MaxCommands: 500, MaxActions: 500,
		WallSeconds: 7200, CommandSeconds: 300, OutputBytes: 4 << 20, TotalBytes: 64 << 20, Parallel: 1, RunnerID: "isolated-worker"}
}

func KnownAction(action string) bool {
	switch action {
	case "command", "local", "api-read", "api-write", "browser-read", "browser-write":
		return true
	}
	return false
}

func (p *Policy) Allows(action string) bool {
	if p == nil || !KnownAction(action) {
		return false
	}
	for _, a := range p.Denied {
		if a == action {
			return false
		}
	}
	for _, a := range p.Allowed {
		if a == action {
			return true
		}
	}
	return false
}

func (p *Policy) Denies(c Command) bool {
	bin := strings.ToLower(filepath.Base(c.Binary))
	for _, rule := range p.Commands {
		if bin != strings.ToLower(rule.Binary) {
			continue
		}
		if rule.Arg == "" {
			return true
		}
		for _, arg := range c.Args {
			if arg == rule.Arg || strings.HasPrefix(arg, rule.Arg+"=") {
				return true
			}
		}
	}
	return false
}

func (p *Policy) Validate() error {
	if p == nil {
		return fmt.Errorf("ROE policy missing")
	}
	for _, list := range [][]string{p.Allowed, p.Denied} {
		seen := map[string]bool{}
		for _, action := range list {
			if !KnownAction(action) || seen[action] {
				return fmt.Errorf("invalid or duplicate action %q", action)
			}
			seen[action] = true
		}
	}
	for key, pair := range map[string][2]int{
		"max_commands": {p.MaxCommands, 10000}, "max_actions": {p.MaxActions, 10000}, "wall_seconds": {p.WallSeconds, 86400},
		"command_seconds": {p.CommandSeconds, 1800}, "output_bytes": {p.OutputBytes, 64 << 20}, "total_bytes": {p.TotalBytes, 1 << 30}, "parallel": {p.Parallel, 8},
	} {
		if pair[0] <= 0 || pair[0] > pair[1] {
			return fmt.Errorf("%s must be between 1 and %d", key, pair[1])
		}
	}
	if p.CommandSeconds > p.WallSeconds || p.OutputBytes > p.TotalBytes {
		return fmt.Errorf("per-command caps exceed engagement caps")
	}
	if p.RunnerID == "" || len(p.RunnerID) > 64 || strings.ContainsAny(p.RunnerID, "\n\r\x00") {
		return fmt.Errorf("invalid runner identity")
	}
	return nil
}

func (p *Policy) Timeout() time.Duration { return time.Duration(p.CommandSeconds) * time.Second }

func (p *Policy) Seal(summary string, targets []string, scope *Scope) error {
	if err := p.Validate(); err != nil {
		return err
	}
	in, out := scope.Entries()
	var numeric []string
	for _, entry := range in {
		if net.ParseIP(entry) != nil {
			numeric = append(numeric, entry)
		} else if _, _, err := net.ParseCIDR(entry); err == nil {
			numeric = append(numeric, entry)
		}
	}
	commandIPs, err := BuildScope(ScopeSpec{In: numeric, Out: out})
	if err != nil {
		return err
	}
	p.CommandIPs = commandIPs
	doc := struct {
		Summary string     `json:"summary"`
		Targets []string   `json:"targets"`
		In      []string   `json:"in_scope"`
		Out     []string   `json:"out_of_scope"`
		Local   bool       `json:"local"`
		Rate    *RateLimit `json:"rate,omitempty"`
		Policy  *Policy    `json:"policy"`
	}{summary, targets, in, out, scope.Local(), scope.rate, p}
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	p.Canonical = string(data)
	hash := sha256.Sum256(data)
	p.Hash = hex.EncodeToString(hash[:])
	return nil
}

func (s *Scope) Entries() (in, out []string) {
	if s == nil {
		return nil, nil
	}
	entry := func(m scopeMatcher) string {
		if m.cidr != nil {
			return m.cidr.String()
		}
		if m.ip != nil {
			return m.ip.String()
		}
		return m.host
	}
	for _, m := range s.in {
		in = append(in, entry(m))
	}
	for _, m := range s.out {
		out = append(out, entry(m))
	}
	return in, out
}
