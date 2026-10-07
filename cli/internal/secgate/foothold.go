package secgate

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Foothold is an operator-declared internal access point: a host the operator
// already controls, through which commands on the covered surfaces execute
// instead of in the isolated worker. It carries the transport identity and the
// non-secret connection parameters. Secret material is named, never held: a key
// or password is written as $NAME and resolved from the environment at execution
// time, so no secret value reaches this struct, the sealed policy text, or the
// model prompt that embeds it.
//
// The declaration is authorization data, not execution machinery. It is parsed
// and validated here and consumed by the transport registry in the CLI.
type Foothold struct {
	Host       string    `json:"host"`
	Transport  string    `json:"transport"`
	User       string    `json:"user,omitempty"`
	Port       int       `json:"port,omitempty"`
	Key        string    `json:"key,omitempty"`
	KnownHosts string    `json:"known_hosts,omitempty"`
	Env        []string  `json:"env,omitempty"`
	Exec       []string  `json:"exec,omitempty"`
	Quote      string    `json:"quote"`
	Surfaces   []Surface `json:"surfaces"`
}

// Quoting selects how a carrier receives the command.
//
//	argv  : the carrier execs the argument vector directly, as kubectl exec and
//	        docker exec do. Arguments are passed through untouched.
//	shell : the carrier hands the command to a remote shell that re-splits it,
//	        as ssh does. Each argument is shell-quoted so the remote argv equals
//	        the authorized argv.
//
// ssh is always shell; a command carrier declares which it is and defaults to
// argv, because passing argv untouched to a shell-reparsing carrier would let an
// argument containing a space or a metacharacter become several arguments.
const (
	QuoteArgv  = "argv"
	QuoteShell = "shell"
)

// FootholdTransports is the set of declarable carriers. A transport absent from
// this set is a parse error, so a typo fails the engagement closed rather than
// silently selecting a default carrier.
//
//	ssh     : an SSH client invocation, key or password authentication
//	command : an operator-supplied argv prefix that already reaches the
//	          foothold, such as "kubectl exec -i web-0 --" or
//	          "docker exec -i app". The carrier is whatever the operator's
//	          access actually is; its leading binary is still gate-checked.
func FootholdTransports() []string { return []string{"command", "ssh"} }

func knownFootholdTransport(name string) bool {
	for _, t := range FootholdTransports() {
		if t == name {
			return true
		}
	}
	return false
}

// footholdSurfaces is the set a foothold may cover. It is the surface set whose
// commands describe the machine they execute on, plus the surfaces whose
// in-cluster or on-host half needs a real foothold to mean anything.
var footholdSurfaces = []Surface{SurfaceLocal, SurfaceAD, SurfaceContainer, SurfaceNetwork}

func knownFootholdSurface(s Surface) bool {
	for _, k := range footholdSurfaces {
		if k == s {
			return true
		}
	}
	return false
}

// FootholdSurfaces returns the declarable surface names, for error text and the
// RoE template.
func FootholdSurfaces() []string {
	out := make([]string, 0, len(footholdSurfaces))
	for _, s := range footholdSurfaces {
		out = append(out, string(s))
	}
	sort.Strings(out)
	return out
}

// Covers reports whether commands on surface s execute on this foothold. A nil
// foothold covers nothing, so the sandbox worker remains the destination.
// execOffHost reports whether a command executes somewhere other than this host.
// A declared foothold carries commands on the surfaces it covers to that host, so
// this host's PATH and symlinks stop describing what a path in the command names.
func (g *Gate) execOffHost(c Command) bool {
	if g == nil || g.Policy == nil {
		return false
	}
	return g.Policy.Foothold.Covers(c.Surface)
}

func (f *Foothold) Covers(s Surface) bool {
	if f == nil {
		return false
	}
	for _, c := range f.Surfaces {
		if c == s {
			return true
		}
	}
	return false
}

// ParseFoothold parses one Foothold entry. The first field is the host; the rest
// are key=value settings. The exec key takes the remainder of the line as argv,
// so an argv prefix needs no quoting grammar, and it must therefore come last.
//
//	10.10.5.21 transport=ssh user=svc-deploy key=$BLKCHAIN_FOOTHOLD_KEY
//	web-0.cluster.internal transport=command exec=kubectl exec -i web-0 --
func ParseFoothold(entry string) (*Foothold, error) {
	fields := strings.Fields(strings.TrimSpace(entry))
	if len(fields) == 0 {
		return nil, fmt.Errorf("secgate: empty foothold entry")
	}
	f := &Foothold{Host: fields[0], Transport: "ssh"}
	if strings.Contains(f.Host, "=") {
		return nil, fmt.Errorf("secgate: foothold entry must begin with a host, got %q", f.Host)
	}
	if !isHostname(f.Host) && parseFootholdIP(f.Host) == "" {
		return nil, fmt.Errorf("secgate: foothold host %q is not an IP or hostname", f.Host)
	}
	var surfaces string
	for i := 1; i < len(fields); i++ {
		key, value, ok := strings.Cut(fields[i], "=")
		if !ok {
			return nil, fmt.Errorf("secgate: foothold setting %q is not key=value", fields[i])
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if value == "" && key != "exec" {
			return nil, fmt.Errorf("secgate: foothold setting %q has an empty value", key)
		}
		switch key {
		case "transport":
			f.Transport = strings.ToLower(value)
		case "user":
			f.User = value
		case "port":
			port, err := strconv.Atoi(value)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("secgate: foothold port %q is not 1-65535", value)
			}
			f.Port = port
		case "key":
			f.Key = value
		case "knownhosts":
			f.KnownHosts = value
		case "env":
			for _, name := range strings.Split(value, ",") {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				if !isEnvName(name) {
					return nil, fmt.Errorf("secgate: foothold env name %q is not a valid environment variable name", name)
				}
				f.Env = append(f.Env, name)
			}
		case "quote":
			f.Quote = strings.ToLower(value)
		case "surfaces":
			surfaces = value
		case "exec":
			f.Exec = append([]string{value}, fields[i+1:]...)
			if value == "" {
				f.Exec = fields[i+1:]
			}
			i = len(fields) // exec consumes the remainder; stop scanning settings
		default:
			return nil, fmt.Errorf("secgate: unknown foothold setting %q", key)
		}
	}
	if err := f.setSurfaces(surfaces); err != nil {
		return nil, err
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return f, nil
}

// parseFootholdIP returns the canonical text of an IP literal, or "" when the
// value is not one. It keeps the IP check in one place for the parser and the
// scope check.
func parseFootholdIP(host string) string {
	m, err := parseMatcher(host)
	if err != nil || m.ip == nil {
		return ""
	}
	return m.ip.String()
}

func (f *Foothold) setSurfaces(spec string) error {
	if strings.TrimSpace(spec) == "" {
		f.Surfaces = []Surface{SurfaceLocal}
		return nil
	}
	seen := map[Surface]bool{}
	for _, part := range strings.Split(spec, ",") {
		s := Surface(strings.ToLower(strings.TrimSpace(part)))
		if s == "" {
			continue
		}
		if !knownFootholdSurface(s) {
			return fmt.Errorf("secgate: foothold surface %q is not one of %s", s, strings.Join(FootholdSurfaces(), ", "))
		}
		if !seen[s] {
			seen[s] = true
			f.Surfaces = append(f.Surfaces, s)
		}
	}
	if len(f.Surfaces) == 0 {
		return fmt.Errorf("secgate: foothold surfaces is empty")
	}
	return nil
}

// validate enforces the per-transport requirements. It fails closed: a
// declaration that cannot produce a usable carrier is rejected at parse time,
// before any engagement begins.
func (f *Foothold) validate() error {
	if !knownFootholdTransport(f.Transport) {
		return fmt.Errorf("secgate: foothold transport %q is not one of %s", f.Transport, strings.Join(FootholdTransports(), ", "))
	}
	switch f.Transport {
	case "ssh":
		if f.User == "" {
			return fmt.Errorf("secgate: foothold transport ssh requires user=")
		}
		// No agent and no tty exist inside the worker, so key authentication is
		// the only form that can succeed unattended. A password-authenticated
		// foothold is declared as transport=command with the operator's own
		// carrier, which keeps password plumbing out of this package.
		if f.Key == "" {
			return fmt.Errorf("secgate: foothold transport ssh requires key=")
		}
		if len(f.Exec) > 0 {
			return fmt.Errorf("secgate: foothold transport ssh does not take exec=")
		}
		if f.Quote != "" && f.Quote != QuoteShell {
			return fmt.Errorf("secgate: foothold transport ssh is always quote=%s", QuoteShell)
		}
		f.Quote = QuoteShell
	case "command":
		if len(f.Exec) == 0 {
			return fmt.Errorf("secgate: foothold transport command requires exec=")
		}
		if f.Quote == "" {
			f.Quote = QuoteArgv
		}
		if f.Quote != QuoteArgv && f.Quote != QuoteShell {
			return fmt.Errorf("secgate: foothold quote %q is not %s or %s", f.Quote, QuoteArgv, QuoteShell)
		}
		if strings.ContainsAny(f.Exec[0], `/\`) {
			return fmt.Errorf("secgate: foothold exec must begin with a bare binary name, got %q", f.Exec[0])
		}
		if f.Key != "" || f.KnownHosts != "" || f.User != "" || f.Port != 0 {
			return fmt.Errorf("secgate: foothold transport command takes only exec=, env=, and surfaces=")
		}
	}
	return nil
}

// isEnvName reports whether s is a POSIX environment variable name. Only a
// declared name is forwarded into a worker, so a malformed entry is rejected
// rather than silently dropped.
func isEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_':
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// CarrierBinary is the binary the transport invokes inside the worker. It is
// gate-checked like any other command, so a declaration cannot turn the RoE into
// an arbitrary-execution channel.
func (f *Foothold) CarrierBinary() string {
	if f == nil {
		return ""
	}
	if f.Transport == "command" && len(f.Exec) > 0 {
		return f.Exec[0]
	}
	return "ssh"
}

// FootholdInScope reports whether the foothold's host is authorized by scope.
// The transport runs inside the guarded worker, so the connection to the
// foothold is filtered by the same allowlist as any other destination: an
// undeclared foothold host would be dropped at the network boundary. Checking it
// here turns that drop into a clear refusal at setup.
//
// A hostname foothold must additionally be an explicit in-scope entry, not only
// a wildcard match. The runner skips wildcard entries when it pins addresses, so
// a wildcard-only hostname has no /etc/hosts entry and no DNS to fall back on,
// and every pivoted command would stall until its timeout.
func FootholdInScope(scope *Scope, f *Foothold) error {
	if f == nil {
		return nil
	}
	if scope == nil {
		return fmt.Errorf("secgate: foothold %s requires a scope", f.Host)
	}
	if !scope.InScope(f.Host) {
		return fmt.Errorf("secgate: foothold host %s is not in scope", f.Host)
	}
	if parseFootholdIP(f.Host) != "" {
		return nil
	}
	in, _ := scope.Entries()
	for _, entry := range in {
		if strings.EqualFold(entry, f.Host) {
			return nil
		}
	}
	return fmt.Errorf("secgate: foothold host %s must be listed in In Scope by name, not only matched by a wildcard, so the runner can pin its address", f.Host)
}
