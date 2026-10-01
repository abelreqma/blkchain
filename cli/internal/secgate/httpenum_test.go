package secgate

import (
	"context"
	"strings"
	"testing"
)

// Audit for the HTTP discovery binaries gobuster, ffuf, and nikto. None of them
// is installed on the audit host, so each item below is recalled from the tool's
// source and documentation, not confirmed against a binary.
//
// gobuster 3.x (cobra and pflag: exact long names, shorthand may be glued, `=`
// and bundles work): no exec, plugin, or config-file option. Writes: -o/--output.
// Reads that are sent to the target: -w/--wordlist, -p/--pattern (pattern file),
// -X/--extensions-file, and the client certificate files --client-cert-file,
// --client-cert-key, --client-cert-pfx. Targets: -u/--url (dir, vhost, fuzz),
// -d/--domain and -r/--resolver (dns), --proxy, and -s/--server (tftp). The s3
// and gcs modes brute-force bucket names against AWS and GCP, and tftp names a
// server, so none of the three has a target the scope check can verify; all are
// denied. -d and -r are booleans in dir mode and take a value in dns mode.
//
// ffuf 2.x (Go flag package: one or two dashes, `=` works, no glued shorthand,
// no bundles, no abbreviation): -input-cmd runs a command through -input-shell
// (code execution); -config loads options from a file; -request reads a raw
// request file whose Host header is the target (a scope bypass); -o, -od, -of,
// and -debug-log write files; -w, -cc, -ck, and -scraperfile read files;
// -u, -x, and -replay-proxy are targets.
//
// nikto 2.x (Perl Getopt::Long: one or two dashes, unique-prefix abbreviation,
// no bundles): -config loads options from a file; -Option overrides any
// nikto.conf setting (PLUGINDIR points at Perl code that nikto loads); -Plugins
// selects plugins; -update downloads and writes the databases; -Format msf+
// sends results to a Metasploit host; -mutate-options reads a file; -o/-output
// and -Save write; -key and -RSAcert read certificate files. -h/-host/-url may
// name a file of targets, so the value must be an explicit scheme URL. Because
// abbreviation makes every denied name reachable, nikto accepts only an exact
// list of audited spellings.
//
// Each tool's default config (~/.ffufrc, /etc/nikto.conf) is outside argv and
// outside the model's writable scratch dir.

func TestHTTPEnumDeniedByClassifier(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string // substring the reason must contain
	}{
		// gobuster: modes with no verifiable target
		{"gobuster", []string{"s3", "-w", "wl"}, "s3"},
		{"gobuster", []string{"gcs", "-w", "wl"}, "gcs"},
		{"gobuster", []string{"tftp", "-s", "10.0.0.5", "-w", "wl"}, "tftp"},
		// gobuster: glued or bundled shorthand hides a value from the extractor
		{"gobuster", []string{"dir", "-u10.0.0.5", "-w", "wl"}, "glues or bundles"},
		{"gobuster", []string{"dir", "-uhttp://evil.com", "-w", "wl"}, "glues or bundles"},
		{"gobuster", []string{"dir", "-u", "http://10.0.0.5", "-wwl"}, "glues or bundles"},
		{"gobuster", []string{"dir", "-u", "http://10.0.0.5", "-w", "wl", "-t10"}, "glues or bundles"},
		{"gobuster", []string{"dir", "-u", "http://10.0.0.5", "-qz"}, "glues or bundles"},
		{"gobuster", []string{"dir", "-u=http://10.0.0.5"}, "glues or bundles"},
		{"gobuster", []string{"dns", "-dcorp.example", "-w", "wl"}, "glues or bundles"},
		{"gobuster", []string{"dns", "-d", "corp.example", "-r8.8.8.8"}, "glues or bundles"},
		// gobuster: a target value the scope check cannot see
		{"gobuster", []string{"dir", "-u", "dc01", "-w", "wl"}, "verify"},
		{"gobuster", []string{"dir", "--url=dc01", "-w", "wl"}, "verify"},
		{"gobuster", []string{"dir", "-u"}, "verify"},
		{"gobuster", []string{"dns", "--domain", "corp", "-w", "wl"}, "verify"},
		{"gobuster", []string{"dns", "-d", "corp", "-w", "wl"}, "verify"},
		{"gobuster", []string{"dns", "-d", "corp.example", "--resolver", "dc01"}, "verify"},
		{"gobuster", []string{"dir", "-u", "http://10.0.0.5", "--proxy", "proxy"}, "verify"},
		{"gobuster", []string{"dir", "-u", "http://10.0.0.5", "-u", "dc01"}, "verify"},
		// ffuf: code execution
		{"ffuf", []string{"-u", "http://10.0.0.5/FUZZ", "-input-cmd", "seq 1 10", "-input-num", "10"}, "arbitrary code"},
		{"ffuf", []string{"-u", "http://10.0.0.5/FUZZ", "-input-cmd=seq"}, "arbitrary code"},
		{"ffuf", []string{"-u", "http://10.0.0.5/FUZZ", "--input-cmd", "seq"}, "arbitrary code"},
		{"ffuf", []string{"-u", "http://10.0.0.5/FUZZ", "--input-cmd=seq"}, "arbitrary code"},
		{"ffuf", []string{"-u", "http://10.0.0.5/FUZZ", "-input-shell", "bash"}, "arbitrary code"},
		{"ffuf", []string{"-u", "http://10.0.0.5/FUZZ", "--input-shell=bash"}, "arbitrary code"},
		{"ffuf", []string{"-u", "http://10.0.0.5/FUZZ", "-INPUT-CMD", "seq"}, "arbitrary code"},
		{"/usr/bin/ffuf", []string{"-u", "http://10.0.0.5/FUZZ", "-input-cmd", "seq"}, "arbitrary code"},
		// ffuf: glued target shorthand
		{"ffuf", []string{"-uhttp://evil.com/FUZZ", "-w", "wl"}, "glues or bundles"},
		{"ffuf", []string{"-uevil.com/FUZZ", "-w", "wl"}, "glues or bundles"},
		{"ffuf", []string{"-u", "http://10.0.0.5/FUZZ", "-xsocks5://evil.com:1080"}, "glues or bundles"},
		// ffuf: a target value the scope check cannot see
		{"ffuf", []string{"-u", "dc01", "-w", "wl"}, "verify"},
		{"ffuf", []string{"-u=dc01/FUZZ", "-w", "wl"}, "verify"},
		{"ffuf", []string{"--u", "dc01", "-w", "wl"}, "verify"},
		{"ffuf", []string{"-u"}, "verify"},
		{"ffuf", []string{"-u", "http://10.0.0.5/FUZZ", "-x", "proxy"}, "verify"},
		{"ffuf", []string{"-u", "http://10.0.0.5/FUZZ", "-replay-proxy", "proxy"}, "verify"},
		// nikto: abbreviated, unknown, config, and plugin options
		{"nikto", []string{"-h", "http://10.0.0.5", "-config", "x"}, "audited"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-config=x"}, "audited"},
		{"nikto", []string{"-h", "http://10.0.0.5", "--config=x"}, "audited"},
		{"nikto", []string{"-h", "http://10.0.0.5", "---config=x"}, "audited"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-Config", "x"}, "audited"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-conf", "x"}, "audited"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-Option", "PLUGINDIR=x"}, "arbitrary code"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-Option=PLUGINDIR=x"}, "arbitrary code"},
		{"nikto", []string{"-h", "http://10.0.0.5", "--Option", "PLUGINDIR=x"}, "arbitrary code"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-Opt", "PLUGINDIR=x"}, "arbitrary code"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-Plugins", "x"}, "arbitrary code"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-Plug", "x"}, "arbitrary code"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-plugins=x"}, "arbitrary code"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-update"}, "audited"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-Format", "msf+"}, "audited"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-F", "csv"}, "audited"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-mutate-options", "f"}, "audited"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-Sav", "x"}, "audited"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-outp", "x"}, "audited"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-vh", "x"}, "audited"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-p80"}, "audited"},
		{"nikto", []string{"-hhttp://evil.com"}, "audited"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-o/tmp/x"}, "audited"},
		{"/usr/bin/nikto", []string{"-h", "http://10.0.0.5", "-config", "x"}, "audited"},
		// nikto: a target value the scope check cannot see, or that may be a file
		{"nikto", []string{"-h", "10.0.0.5"}, "scheme"},
		{"nikto", []string{"-host", "10.0.0.5"}, "scheme"},
		{"nikto", []string{"-url", "corp.example"}, "scheme"},
		{"nikto", []string{"--host=corp.example"}, "scheme"},
		{"nikto", []string{"-h", "targets"}, "scheme"},
		{"nikto", []string{"-h"}, "scheme"},
		{"nikto", []string{"-h", "http://10.0.0.5", "-h", "corp.example"}, "scheme"},
	} {
		d := Classify(Command{Binary: tc.name, Args: tc.args})
		if d.Allowed {
			t.Errorf("Classify(%q %v) allowed a denied form", tc.name, tc.args)
		} else if !strings.Contains(d.Reason, tc.want) {
			t.Errorf("Classify(%q %v) denied for the wrong reason: %q (want %q)", tc.name, tc.args, d.Reason, tc.want)
		}
	}
}

func TestHTTPEnumBenignInvocationsAllowed(t *testing.T) {
	benign := []Command{
		{Binary: "gobuster", Args: []string{"dir", "-u", "http://10.0.0.5", "-w", "wl", "-o", "out", "-t", "10", "-q"}},
		{Binary: "gobuster", Args: []string{"dir", "--url", "https://corp.example:8443/", "--wordlist", "wl", "--output", "out", "-x", "php,txt", "-r", "-k"}},
		{Binary: "gobuster", Args: []string{"dir", "--url=http://10.0.0.5", "--wordlist=lists/wl", "--output=out", "-s", "200,301"}},
		{Binary: "gobuster", Args: []string{"dir", "-u", "http://10.0.0.5", "-w", "wl", "-d", "-q", "-r"}},
		{Binary: "gobuster", Args: []string{"dir", "-u", "http://10.0.0.5", "-w", "wl", "-r"}},
		{Binary: "gobuster", Args: []string{"dns", "-d", "corp.example", "-w", "wl", "-i"}},
		{Binary: "gobuster", Args: []string{"dns", "--domain", "corp.example", "-r", "10.0.0.5", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"vhost", "-u", "http://10.0.0.5", "--domain", "corp.example", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"fuzz", "-u", "http://10.0.0.5/FUZZ", "-w", "wl"}},
		{Binary: "ffuf", Args: []string{"-u", "http://10.0.0.5/FUZZ", "-w", "wl", "-o", "out", "-of", "json", "-mc", "200", "-t", "40"}},
		{Binary: "ffuf", Args: []string{"-u", "http://corp.example/FUZZ", "-w", "wl:FUZZ", "-s", "-recursion", "-recursion-depth", "2"}},
		{Binary: "ffuf", Args: []string{"--u", "http://10.0.0.5/FUZZ", "--w", "wl"}},
		{Binary: "ffuf", Args: []string{"-u=http://10.0.0.5/FUZZ", "-w=wl", "-od", "matches", "-debug-log", "dbg"}},
		{Binary: "ffuf", Args: []string{"-u", "http://10.0.0.5/FUZZ", "-w", "wl", "-e", ".php,.txt", "-fs", "0", "-X", "POST", "-d", "a=b"}},
		{Binary: "ffuf", Args: []string{"-u", "http://10.0.0.5/FUZZ", "-w", "wl", "-x", "http://10.0.0.6:8080"}},
		{Binary: "nikto", Args: []string{"-h", "http://10.0.0.5", "-p", "80", "-Tuning", "123", "-o", "out", "-nointeractive"}},
		{Binary: "nikto", Args: []string{"-host", "https://corp.example", "-ssl", "-maxtime", "600s", "-Display", "1"}},
		{Binary: "nikto", Args: []string{"--host=http://10.0.0.5:8080", "--output=out", "-Save", "evidence", "-timeout", "5"}},
		{Binary: "nikto", Args: []string{"-url", "http://10.0.0.5", "-vhost", "corp.example", "-useragent", "x", "-Version"}},
	}
	for _, c := range benign {
		if d := Classify(c); !d.Allowed {
			t.Errorf("Classify(%q %v) denied a benign command: %q", c.Binary, c.Args, d.Reason)
		}
		if arg, bad := FileAccessViolation(c); bad {
			t.Errorf("FileAccessViolation(%q %v) denied a benign command (%q)", c.Binary, c.Args, arg)
		}
	}
}

// Every write, read, and config flag, in every spelling the tool's parser
// accepts, is denied for an absolute path or a ".." segment.
func TestHTTPEnumFilePathsBounded(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		// gobuster (pflag: -o file, -ofile, -o=file, --output file, --output=file, bundles)
		{"gobuster", []string{"dir", "-o", "/tmp/x"}},
		{"gobuster", []string{"dir", "-o/tmp/x"}},
		{"gobuster", []string{"dir", "-o=/tmp/x"}},
		{"gobuster", []string{"dir", "-o", "../x"}},
		{"gobuster", []string{"dir", "-qzo", "/x"}},
		{"gobuster", []string{"dir", "--output", "/x"}},
		{"gobuster", []string{"dir", "--output=/x"}},
		{"gobuster", []string{"dir", "--output", "../x"}},
		{"gobuster", []string{"dir", "-w", "/etc/passwd"}},
		{"gobuster", []string{"dir", "-w/etc/passwd"}},
		{"gobuster", []string{"dir", "-w", "../x"}},
		{"gobuster", []string{"dir", "-zw", "/etc/passwd"}},
		{"gobuster", []string{"dir", "--wordlist", "/etc/passwd"}},
		{"gobuster", []string{"dir", "--wordlist=/etc/passwd"}},
		{"gobuster", []string{"dir", "--wordlist=../x"}},
		{"gobuster", []string{"dir", "-p", "/x"}},
		{"gobuster", []string{"dir", "--pattern=/x"}},
		{"gobuster", []string{"dir", "-X", "/x"}},
		{"gobuster", []string{"dir", "--extensions-file", "../x"}},
		{"gobuster", []string{"dir", "--client-cert-file", "/x"}},
		{"gobuster", []string{"dir", "--client-cert-key=/x"}},
		{"gobuster", []string{"dir", "--client-cert-pfx", "../x"}},
		// ffuf (Go flag: one or two dashes, -f value or -f=value)
		{"ffuf", []string{"-o", "/tmp/x"}},
		{"ffuf", []string{"--o", "/tmp/x"}},
		{"ffuf", []string{"-o=/tmp/x"}},
		{"ffuf", []string{"--o=/tmp/x"}},
		{"ffuf", []string{"-o", "../x"}},
		{"ffuf", []string{"-od", "/x"}},
		{"ffuf", []string{"--od=/x"}},
		{"ffuf", []string{"-of", "/x"}},
		{"ffuf", []string{"-debug-log", "/x"}},
		{"ffuf", []string{"--debug-log=/x"}},
		{"ffuf", []string{"-debug-log", "../x"}},
		{"ffuf", []string{"-w", "/etc/passwd"}},
		{"ffuf", []string{"-w", "/etc/passwd:FUZZ"}},
		{"ffuf", []string{"--w=/etc/passwd"}},
		{"ffuf", []string{"-w", "../x:FUZZ"}},
		{"ffuf", []string{"-cc", "/x"}},
		{"ffuf", []string{"-ck", "../x"}},
		{"ffuf", []string{"-scraperfile", "/x"}},
		// ffuf: config and request files are denied outright, even relative
		{"ffuf", []string{"-config", "ffuf.yml"}},
		{"ffuf", []string{"-config=ffuf.yml"}},
		{"ffuf", []string{"--config", "ffuf.yml"}},
		{"ffuf", []string{"--config=ffuf.yml"}},
		{"ffuf", []string{"-request", "req"}},
		{"ffuf", []string{"-request=req"}},
		{"ffuf", []string{"--request", "req"}},
		// nikto (Getopt::Long: -o file, -o=file, --o file; no glued values)
		{"nikto", []string{"-o", "/tmp/x"}},
		{"nikto", []string{"--o", "/tmp/x"}},
		{"nikto", []string{"-o=/tmp/x"}},
		{"nikto", []string{"-output", "/x"}},
		{"nikto", []string{"--output=../x"}},
		{"nikto", []string{"-Save", "/x"}},
		{"nikto", []string{"--Save=../x"}},
		{"nikto", []string{"-key", "/x"}},
		{"nikto", []string{"-RSAcert", "../x"}},
	} {
		if arg, bad := FileAccessViolation(Command{Binary: tc.name, Args: tc.args}); !bad {
			t.Errorf("FileAccessViolation(%q %v) allowed a path escape", tc.name, tc.args)
		} else if arg == "" {
			t.Errorf("FileAccessViolation(%q %v) must report the offending arg", tc.name, tc.args)
		}
	}
}

// A glued or bundled value, a value the extractor cannot resolve to a host, and
// an out-of-scope URL are all denied by the gate, in the form and the spelling
// each tool accepts.
func TestHTTPEnumOutOfScopeTargetsDeniedByGate(t *testing.T) {
	g := newEnumGate(t, "gobuster", "ffuf", "nikto")
	for _, c := range []Command{
		{Binary: "gobuster", Args: []string{"dir", "-u", "http://evil.com", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"dir", "-u", "evil.com", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"dir", "-u", "8.8.8.8", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"dir", "-u", "http://8.8.8.8:8080/", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"dir", "--url", "http://dc01", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"dir", "--url=http://evil.com", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"dir", "-u", "dc01", "-w", "wl", "-H", "Host: 10.0.0.5"}},
		{Binary: "gobuster", Args: []string{"dir", "-u", "http://10.0.0.5", "-u", "http://evil.com", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"dir", "-uevil.com", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"dir", "-uhttp://evil.com", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"dir", "-u", "http://10.0.0.5", "--proxy", "http://8.8.8.8:8080", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"dns", "-d", "evil.com", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"dns", "-dcorp.example", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"dns", "--domain", "evil", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"dns", "-d", "corp.example", "-r", "8.8.8.8", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"dns", "-d", "corp.example", "--resolver", "evil.com", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"vhost", "-u", "http://10.0.0.5", "--domain", "evil.com", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"s3", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"tftp", "-s", "10.0.0.5", "-w", "wl"}},
		{Binary: "ffuf", Args: []string{"-u", "http://evil.com/FUZZ", "-w", "wl"}},
		{Binary: "ffuf", Args: []string{"-u", "evil.com/FUZZ", "-w", "wl"}},
		{Binary: "ffuf", Args: []string{"-u", "http://dc01/FUZZ", "-w", "wl"}},
		{Binary: "ffuf", Args: []string{"-u", "dc01", "-w", "wl", "-H", "Host: 10.0.0.5"}},
		{Binary: "ffuf", Args: []string{"-u=http://evil.com/FUZZ", "-w", "wl"}},
		{Binary: "ffuf", Args: []string{"--u", "http://evil.com/FUZZ", "-w", "wl"}},
		{Binary: "ffuf", Args: []string{"--u=http://evil.com/FUZZ", "-w", "wl"}},
		{Binary: "ffuf", Args: []string{"-uhttp://evil.com/FUZZ", "-w", "wl"}},
		{Binary: "ffuf", Args: []string{"-u", "http://10.0.0.5/FUZZ", "-u", "http://evil.com/FUZZ", "-w", "wl"}},
		{Binary: "ffuf", Args: []string{"-u", "http://10.0.0.5/FUZZ", "-x", "http://8.8.8.8:8080", "-w", "wl"}},
		{Binary: "ffuf", Args: []string{"-u", "http://10.0.0.5/FUZZ", "-x", "socks5://evil.com:1080", "-w", "wl"}},
		{Binary: "ffuf", Args: []string{"-u", "http://10.0.0.5/FUZZ", "-replay-proxy", "http://8.8.8.8", "-w", "wl"}},
		{Binary: "ffuf", Args: []string{"-request", "req", "-request-proto", "http", "-w", "wl"}},
		{Binary: "nikto", Args: []string{"-h", "http://evil.com"}},
		{Binary: "nikto", Args: []string{"-h", "evil.com"}},
		{Binary: "nikto", Args: []string{"-h", "10.0.0.5"}},
		{Binary: "nikto", Args: []string{"-h", "targets"}},
		{Binary: "nikto", Args: []string{"-host", "http://evil.com"}},
		{Binary: "nikto", Args: []string{"--host=http://evil.com"}},
		{Binary: "nikto", Args: []string{"-host=http://evil.com"}},
		{Binary: "nikto", Args: []string{"-url", "http://evil.com"}},
		{Binary: "nikto", Args: []string{"-h", "http://dc01"}},
		{Binary: "nikto", Args: []string{"-hhttp://evil.com"}},
		{Binary: "nikto", Args: []string{"-h", "http://10.0.0.5", "-h", "http://evil.com"}},
		{Binary: "nikto", Args: []string{"-h", "http://10.0.0.5", "-useproxy", "http://8.8.8.8:3128"}},
		{Binary: "nikto", Args: []string{"-h", "http://10.0.0.5", "-useproxy", "attacker"}},
		{Binary: "nikto", Args: []string{"-h", "http://10.0.0.5", "-useproxy", "http://attacker:3128"}},
		{Binary: "nikto", Args: []string{"-h", "http://10.0.0.5", "-useproxy"}},
		{Binary: "nikto", Args: []string{"-h", "http://10.0.0.5", "-vhost", "evil.com"}},
		{Binary: "nikto", Args: []string{"-h", "http://10.0.0.5", "-config", "x"}},
		{Binary: "nikto", Args: []string{"-h", "http://10.0.0.5", "-Option", "PLUGINDIR=x"}},
	} {
		if d := g.Authorize(context.Background(), c); d.Allowed {
			t.Errorf("Authorize(%q %v) allowed an out-of-scope or unverifiable target", c.Binary, c.Args)
		}
	}
}

func TestHTTPEnumGateAllowsBenignInScope(t *testing.T) {
	stubEnumFixtureResolver(t)
	g := newEnumGate(t, "gobuster", "ffuf", "nikto")
	for _, c := range []Command{
		{Binary: "gobuster", Args: []string{"dir", "-u", "http://10.0.0.5", "-w", "wl", "-o", "out", "-t", "10", "-q"}},
		{Binary: "gobuster", Args: []string{"dir", "--url", "https://corp.example:8443/", "--wordlist", "wl", "--output", "out", "-x", "php,txt", "-r", "-k"}},
		{Binary: "gobuster", Args: []string{"dir", "-u", "http://10.0.0.5", "-w", "wl", "-d", "-q"}},
		{Binary: "gobuster", Args: []string{"dns", "-d", "corp.example", "-w", "wl", "-i"}},
		{Binary: "gobuster", Args: []string{"dns", "--domain", "corp.example", "-r", "10.0.0.5", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"vhost", "-u", "http://10.0.0.5", "--domain", "corp.example", "-w", "wl"}},
		{Binary: "gobuster", Args: []string{"fuzz", "-u", "http://10.0.0.5/FUZZ", "-w", "wl"}},
		{Binary: "ffuf", Args: []string{"-u", "http://10.0.0.5/FUZZ", "-w", "wl", "-o", "out", "-of", "json", "-mc", "200", "-t", "40"}},
		{Binary: "ffuf", Args: []string{"-u", "http://corp.example/FUZZ", "-w", "wl", "-s", "-recursion", "-recursion-depth", "2"}},
		{Binary: "ffuf", Args: []string{"--u", "http://10.0.0.5/FUZZ", "--w", "wl"}},
		{Binary: "ffuf", Args: []string{"-u=http://10.0.0.5/FUZZ", "-w=wl"}},
		{Binary: "ffuf", Args: []string{"-u", "http://10.0.0.5/FUZZ", "-w", "wl", "-e", ".php,.txt", "-fs", "0"}},
		{Binary: "nikto", Args: []string{"-h", "http://10.0.0.5", "-p", "80", "-Tuning", "123", "-o", "out", "-nointeractive"}},
		{Binary: "nikto", Args: []string{"-host", "https://corp.example", "-ssl", "-maxtime", "600s", "-Display", "1"}},
		{Binary: "nikto", Args: []string{"--host=http://10.0.0.5:8080", "--output=out", "-Save", "evidence"}},
		{Binary: "nikto", Args: []string{"-h", "http://10.0.0.5", "-useproxy", "http://10.0.0.5:3128"}},
	} {
		if d := g.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("Authorize(%q %v) denied a benign in-scope command: %q", c.Binary, c.Args, d.Reason)
		}
	}
}

// The audit rules are bounded to their own binaries.
func TestHTTPEnumRulesBounded(t *testing.T) {
	for _, c := range []Command{
		{Binary: "curl", Args: []string{"-u", "user:pw", "-x", "http://10.0.0.6:8080", "http://10.0.0.5/"}},
		{Binary: "curl", Args: []string{"-t10", "http://10.0.0.5/"}},
		{Binary: "nmap", Args: []string{"-p", "80", "-sV", "10.0.0.5"}},
		{Binary: "host", Args: []string{"-tmx", "corp.example"}},
	} {
		if d := Classify(c); !d.Allowed {
			t.Errorf("Classify(%q %v) denied: %q", c.Binary, c.Args, d.Reason)
		}
	}
	// wget -O and curl -o are unaffected by the ffuf and nikto normalization.
	if _, bad := FileAccessViolation(Command{Binary: "curl", Args: []string{"--o", "/x"}}); bad {
		t.Error("the double-dash normalization must not apply to curl")
	}
}
