package secgate

import (
	"context"
	"strings"
	"testing"
)

// Proxy and relay flags. curl -x/--proxy (and --preproxy, --socks4, --socks4a,
// --socks5, --socks5-hostname, --proxy1.0) and nmap --proxies name a host the
// tool connects THROUGH, so an out-of-scope value is a scope bypass even when
// the target is in scope. Each value must resolve to a host the scope check can
// see. A bare single-label value, and a short flag glued to its value, are
// invisible to the extractor and are denied or extracted by the audit.

func TestProxyTargetsDeniedByGate(t *testing.T) {
	g := newEnumGate(t, "curl", "nmap")
	const tgt = "http://10.0.0.5/"
	for _, c := range []Command{
		// curl -x: separate, glued, bundled, with and without a scheme
		{Binary: "curl", Args: []string{"-x", "http://evil.com:8080", tgt}},
		{Binary: "curl", Args: []string{"-xhttp://evil.com:8080", tgt}},
		{Binary: "curl", Args: []string{"-x", "evil.com:8080", tgt}},
		{Binary: "curl", Args: []string{"-xevil.com:8080", tgt}},
		{Binary: "curl", Args: []string{"-x8.8.8.8:8080", tgt}},
		{Binary: "curl", Args: []string{"-x", "proxy", tgt}},
		{Binary: "curl", Args: []string{"-xproxy", tgt}},
		{Binary: "curl", Args: []string{"-sxevil.com:3128", tgt}},
		{Binary: "curl", Args: []string{"-skx", "evil.com:3128", tgt}},
		{Binary: "curl", Args: []string{"-x", "socks5h://evil.com:1080", tgt}},
		{Binary: "curl", Args: []string{"-x", "", tgt}},
		{Binary: "curl", Args: []string{tgt, "-x"}},
		// curl --proxy
		{Binary: "curl", Args: []string{"--proxy", "http://evil.com", tgt}},
		{Binary: "curl", Args: []string{"--proxy=http://evil.com", tgt}},
		{Binary: "curl", Args: []string{"--proxy", "evil", tgt}},
		{Binary: "curl", Args: []string{"--proxy=evil", tgt}},
		{Binary: "curl", Args: []string{"--proxy", "dc01", tgt}},
		{Binary: "curl", Args: []string{"--proxy", "http://dc01:3128", tgt}},
		// the in-scope proxy does not excuse a second, out-of-scope one
		{Binary: "curl", Args: []string{"-x", "http://10.0.0.5:8080", "--preproxy", "evil", tgt}},
		{Binary: "curl", Args: []string{"-x", "http://10.0.0.5:8080", "-x", "evil", tgt}},
		// the other proxy-taking flags
		{Binary: "curl", Args: []string{"--preproxy", "socks5://evil.com:1080", tgt}},
		{Binary: "curl", Args: []string{"--preproxy=evil", tgt}},
		{Binary: "curl", Args: []string{"--socks4", "evil.com:1080", tgt}},
		{Binary: "curl", Args: []string{"--socks4", "evil", tgt}},
		{Binary: "curl", Args: []string{"--socks4a", "evil.com:1080", tgt}},
		{Binary: "curl", Args: []string{"--socks4a=evil", tgt}},
		{Binary: "curl", Args: []string{"--socks5", "evil.com:1080", tgt}},
		{Binary: "curl", Args: []string{"--socks5", "8.8.8.8:1080", tgt}},
		{Binary: "curl", Args: []string{"--socks5=evil", tgt}},
		{Binary: "curl", Args: []string{"--socks5-hostname", "evil.com:1080", tgt}},
		{Binary: "curl", Args: []string{"--socks5-hostname=proxy", tgt}},
		{Binary: "curl", Args: []string{"--proxy1.0", "evil.com:8080", tgt}},
		{Binary: "curl", Args: []string{"--proxy1.0", "evil", tgt}},
		// curl accepts an unambiguous prefix of a long option
		{Binary: "curl", Args: []string{"--prox", "evil", tgt}},
		{Binary: "curl", Args: []string{"--pre", "evil", tgt}},
		{Binary: "curl", Args: []string{"--socks5-h", "evil", tgt}},
		{Binary: "curl", Args: []string{"--sock", "evil.com:1080", tgt}},
		{Binary: "/usr/bin/curl", Args: []string{"--proxy", "http://evil.com", tgt}},
		// nmap --proxies: one option or two dashes, abbreviated, list or single
		{Binary: "nmap", Args: []string{"--proxies", "http://evil.com:8080", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"--proxies=http://evil.com:8080", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"-proxies", "http://evil.com:8080", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"-proxies=http://evil.com", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"--prox", "http://evil.com", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"--proxies", "socks4://evil.com:1080", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"--proxies", "http://10.0.0.6:8080,http://evil.com", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"--proxies", "http://evil.com,http://10.0.0.6:8080", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"--proxies=http://10.0.0.6:8080,socks4://evil.com:1080", "-p", "80", "10.0.0.5"}},
		// a list part with no scheme, or a single-label part, is unverifiable
		{Binary: "nmap", Args: []string{"--proxies", "http://10.0.0.6:8080,evil", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"--proxies", "evil", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"--proxies", "evil.com", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"--proxies", "http://dc01:8080", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"--proxies", "", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5", "--proxies"}},
	} {
		if d := g.Authorize(context.Background(), c); d.Allowed {
			t.Errorf("Authorize(%q %v) allowed an out-of-scope or unverifiable proxy", c.Binary, c.Args)
		}
	}
}

// A proxy value the scope check cannot verify is denied by the classifier
// itself, before the allowlist and scope layers.
func TestProxyUnverifiableValueDeniedByClassifier(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"curl", []string{"-xevil.com:8080", "http://10.0.0.5/"}, "glues"},
		{"curl", []string{"-x10.0.0.6:8080", "http://10.0.0.5/"}, "glues"},
		{"curl", []string{"-sx10.0.0.6:8080", "http://10.0.0.5/"}, "glues"},
		{"curl", []string{"-x=evil.com", "http://10.0.0.5/"}, "glues"},
		{"curl", []string{"-x", "proxy", "http://10.0.0.5/"}, "verify"},
		{"curl", []string{"-xproxy", "http://10.0.0.5/"}, "glues"},
		{"curl", []string{"--proxy=proxy", "http://10.0.0.5/"}, "verify"},
		{"curl", []string{"--proxy", "", "http://10.0.0.5/"}, "verify"},
		{"curl", []string{"--socks5-hostname", "proxy", "http://10.0.0.5/"}, "verify"},
		{"curl", []string{"--prox", "proxy", "http://10.0.0.5/"}, "verify"},
		{"nmap", []string{"--proxies", "http://10.0.0.6,evil", "-p", "80", "10.0.0.5"}, "scheme"},
		{"nmap", []string{"--proxies", "evil", "-p", "80", "10.0.0.5"}, "scheme"},
		{"nmap", []string{"-proxies", "evil", "-p", "80", "10.0.0.5"}, "scheme"},
		{"nmap", []string{"--proxies", "http://proxy", "-p", "80", "10.0.0.5"}, ""},
	} {
		d := Classify(Command{Binary: tc.name, Args: tc.args})
		if tc.want == "" {
			if !d.Allowed {
				t.Errorf("Classify(%q %v) denied a URL proxy the gate scope-checks: %q", tc.name, tc.args, d.Reason)
			}
			continue
		}
		if d.Allowed {
			t.Errorf("Classify(%q %v) allowed an unverifiable proxy", tc.name, tc.args)
		} else if !strings.Contains(d.Reason, tc.want) {
			t.Errorf("Classify(%q %v) denied for the wrong reason: %q (want %q)", tc.name, tc.args, d.Reason, tc.want)
		}
	}
}

// A header or a data payload is not a proxy: the proxy audit must not treat its
// value as a target, so the classifier and the file-access check still allow it.
// (The gate's shared extractor separately reads some such values as hosts, for
// example "X-Forwarded-For:" and "data.txt"; that behavior predates the proxy
// audit and is not changed here.)
func TestProxyAuditIgnoresHeadersAndData(t *testing.T) {
	for _, c := range []Command{
		{Binary: "curl", Args: []string{"-H", "X-Forwarded-For: evil.com", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"--header", "Via: 1.1 evil.com", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"-H", "X-Forwarded-For: 8.8.8.8", "-x", "http://10.0.0.6:8080", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"-d", "@data.txt", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"--data-binary", "@data.txt", "-X", "POST", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"-X", "POST", "-d", "@data.txt", "-x", "http://10.0.0.6:8080", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"-A", "x", "-e", "http://10.0.0.5/", "-u", "user:pw", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"-b", "sid=1", "-w", "%{http_code}", "http://10.0.0.5/"}},
		{Binary: "nmap", Args: []string{"-p", "80", "-sV", "-Pn", "--open", "10.0.0.5"}},
	} {
		if d := Classify(c); !d.Allowed {
			t.Errorf("Classify(%q %v) denied a header or data usage: %q", c.Binary, c.Args, d.Reason)
		}
		if arg, bad := FileAccessViolation(c); bad {
			t.Errorf("FileAccessViolation(%q %v) denied a header or data usage (%q)", c.Binary, c.Args, arg)
		}
	}
}

// Legitimate in-scope proxy usage stays allowed, and so does every command with
// no proxy at all.
func TestProxyInScopeUsageAllowedByGate(t *testing.T) {
	stubEnumFixtureResolver(t)
	g := newEnumGate(t, "curl", "nmap")
	for _, c := range []Command{
		{Binary: "curl", Args: []string{"http://10.0.0.5/path"}},
		{Binary: "curl", Args: []string{"-s", "-o", "out", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"-x", "http://10.0.0.5:8080", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"-x", "10.0.0.6:8080", "-k", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"-skx", "http://10.0.0.6:8080", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"--proxy", "http://corp.example:3128", "https://corp.example/"}},
		{Binary: "curl", Args: []string{"--proxy=http://corp.example:3128", "https://corp.example/"}},
		{Binary: "curl", Args: []string{"--preproxy", "socks5://10.0.0.6:1080", "-x", "http://10.0.0.7:3128", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"--socks5", "10.0.0.6:1080", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"--socks5-hostname", "10.0.0.6:1080", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"--socks4", "10.0.0.6:1080", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"--proxy1.0", "10.0.0.6:8080", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"-d", "a=b", "-x", "http://10.0.0.6:8080", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"-X", "POST", "-d", "a=b", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"--proto", "=https", "https://corp.example/"}},
		{Binary: "curl", Args: []string{"--proxy-insecure", "-x", "http://10.0.0.6:8080", "https://corp.example/"}},
		{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"-p", "80", "-sV", "-Pn", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"-p", "80,443", "-oN", "out", "corp.example"}},
		{Binary: "nmap", Args: []string{"--proxies", "http://10.0.0.6:8080", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"--proxies=http://10.0.0.6:8080,socks4://10.0.0.7:1080", "-p", "80", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"-p", "80", "--proxies", "http://corp.example:3128", "10.0.0.5"}},
	} {
		if d := g.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("Authorize(%q %v) denied a legitimate in-scope command: %q", c.Binary, c.Args, d.Reason)
		}
	}
}
