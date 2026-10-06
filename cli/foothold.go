package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"blkchain/cli/internal/secgate"
)

// foothold.go turns an operator-declared foothold into a carrier that runs an
// authorized command on that host instead of in the isolated worker.
//
// The carrier depends on how the operator's access was acquired, so the set is a
// registry rather than a fixed client: footholdBuilders maps a declared
// transport name to its constructor, and adding a carrier is one entry plus one
// builder. The carrier itself always runs INSIDE the worker, so the guard's
// firewall still filters the connection to the foothold and the foothold's
// address must be in scope. Commands the foothold then runs are outside that
// firewall; runIsolatedAction records the destination of every such action.

// footholdSecretDir is the per-worker tmpfs directory holding carrier secrets.
// Secrets are written into the worker over a docker exec rather than bind-mounted
// from the operator's filesystem, so their owner and mode are the worker's own
// and no operator path is exposed inside the container.
const footholdSecretDir = "/work/.foothold"

// footholdTransport is a constructed carrier: the argv prefix that reaches the
// foothold, how the carrier receives the command, the secret files the worker
// needs, and the environment names forwarded into it.
type footholdTransport struct {
	name    string
	carrier string
	prefix  []string
	quote   string
	secrets map[string][]byte
	env     []string
}

var footholdBuilders = map[string]func(*secgate.Foothold) (*footholdTransport, error){
	"ssh":     buildFootholdSSH,
	"command": buildFootholdCommand,
}

// newFootholdTransport constructs the carrier for a declaration, resolving every
// referenced path and reading every secret file now, so a missing key or an
// unset environment variable fails the engagement at setup rather than at the
// first pivoted action.
func newFootholdTransport(f *secgate.Foothold) (*footholdTransport, error) {
	if f == nil {
		return nil, nil
	}
	build, ok := footholdBuilders[f.Transport]
	if !ok {
		return nil, fmt.Errorf("foothold transport %q has no carrier", f.Transport)
	}
	t, err := build(f)
	if err != nil {
		return nil, err
	}
	for _, name := range f.Env {
		if _, set := os.LookupEnv(name); !set {
			return nil, fmt.Errorf("foothold env %s is not set", name)
		}
	}
	t.name = f.Transport
	t.env = append([]string(nil), f.Env...)
	return t, nil
}

func buildFootholdSSH(f *secgate.Foothold) (*footholdTransport, error) {
	key, err := readFootholdFile(f.Key, "key")
	if err != nil {
		return nil, err
	}
	keyPath := footholdSecretDir + "/key"
	secrets := map[string][]byte{keyPath: key}
	args := []string{"ssh",
		"-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "ConnectTimeout=10",
		// Carrier chatter would otherwise be captured as target evidence.
		"-o", "LogLevel=ERROR",
	}
	if f.KnownHosts != "" {
		known, err := readFootholdFile(f.KnownHosts, "knownhosts")
		if err != nil {
			return nil, err
		}
		knownPath := footholdSecretDir + "/known_hosts"
		secrets[knownPath] = known
		args = append(args, "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile="+knownPath)
	} else {
		args = append(args, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null")
	}
	if f.Port != 0 {
		args = append(args, "-p", strconv.Itoa(f.Port))
	}
	args = append(args, f.User+"@"+f.Host, "--")
	return &footholdTransport{carrier: "ssh", prefix: args, quote: secgate.QuoteShell, secrets: secrets}, nil
}

func buildFootholdCommand(f *secgate.Foothold) (*footholdTransport, error) {
	return &footholdTransport{
		carrier: f.Exec[0],
		prefix:  append([]string(nil), f.Exec...),
		quote:   f.Quote,
		secrets: map[string][]byte{},
	}, nil
}

// readFootholdFile reads a declared path. A value written as $NAME names an
// environment variable holding the path, which keeps the operator's filesystem
// layout out of the sealed policy text and out of the model prompt.
func readFootholdFile(value, label string) ([]byte, error) {
	path := value
	if strings.HasPrefix(value, "$") {
		name := value[1:]
		resolved, set := os.LookupEnv(name)
		if !set || strings.TrimSpace(resolved) == "" {
			return nil, fmt.Errorf("foothold %s names $%s, which is not set", label, name)
		}
		path = resolved
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("foothold %s path must be absolute, got %q", label, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("foothold %s: %w", label, err)
	}
	if info.IsDir() || info.Size() > 1<<20 {
		return nil, fmt.Errorf("foothold %s must be a file under 1 MiB", label)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("foothold %s: %w", label, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("foothold %s file is empty", label)
	}
	return data, nil
}

// Wrap returns the argv that runs argv on the foothold. A shell-quoting carrier
// receives one argument holding the quoted command line, so the remote shell
// reconstructs exactly the authorized argv; an argv carrier receives the
// arguments untouched.
func (t *footholdTransport) Wrap(argv []string) []string {
	out := append([]string(nil), t.prefix...)
	if t.quote == secgate.QuoteShell {
		return append(out, shellQuoteArgv(argv))
	}
	return append(out, argv...)
}

// shellQuoteArgv renders argv as a POSIX shell command line in which every
// argument is a single literal. Single-quoting makes every byte literal except
// the single quote itself, which is closed, escaped, and reopened. A remote
// shell parsing the result produces the identical argument vector, so no
// argument can split into several or expand.
func shellQuoteArgv(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		parts = append(parts, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
	}
	return strings.Join(parts, " ")
}

// authorizeFootholdCarrier authorizes the binary the carrier invokes inside the
// worker.
//
// An ssh carrier is built entirely by buildFootholdSSH: every option and the
// destination are code-owned, and the command the foothold runs is a single
// shell-quoted argument, so no declaration text reaches ssh's own option
// surface. ssh is therefore permitted as a carrier while staying absent from the
// gate's reachability allowlist, which keeps the model from invoking ssh as a
// command and reaching its proxy, forwarding, and local-command options.
//
// A command carrier's argv prefix is operator text, so its leading binary must
// clear the same reachability allowlist as any other command. Without that an
// RoE could nominate any binary in the image as its carrier.
func authorizeFootholdCarrier(g *secgate.Gate, t *footholdTransport) error {
	if t == nil {
		return nil
	}
	if t.name == "ssh" {
		return nil
	}
	if g == nil || g.Allow == nil {
		return fmt.Errorf("foothold carrier %s cannot be authorized without an allowlist", t.carrier)
	}
	if !g.Allow.Permits(t.carrier) {
		return fmt.Errorf("foothold carrier %s is not an allowed binary", t.carrier)
	}
	return nil
}

// footholdSecretWriter is the in-worker writer that stores a carrier secret with
// owner and mode set by the worker itself. It takes the destination path as its
// only argument and the content on stdin, so no secret appears in an argument
// vector or in the environment of any process.
const footholdSecretWriter = `import os,sys
dest = sys.argv[1]
os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
try:
    os.write(fd, sys.stdin.buffer.read())
finally:
    os.close(fd)
`

// secretPaths returns the destination paths in a stable order so provisioning is
// deterministic.
func (t *footholdTransport) secretPaths() []string {
	if t == nil {
		return nil
	}
	paths := make([]string, 0, len(t.secrets))
	for path := range t.secrets {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}
