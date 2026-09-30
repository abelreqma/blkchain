package secgate

import (
	"context"
	"strings"
	"testing"
)

// Audit for the LDAP and SNMP enumeration binaries ldapsearch, snmpwalk, and
// onesixtyone.
//
// ldapsearch (OpenLDAP 2.4, confirmed against the local binary): -y reads the
// bind password from a file (credential file); -f reads the search operations
// from a file; -t/-tt write retrieved values to files in a temp directory the
// caller does not choose, and -T names that directory; -C chases referrals to
// hosts the scope check never sees; -h names the server outside a URL and is
// deprecated in favor of -H (a bare single-label -h host would be skipped by
// the scope check); -H names the server as a URI, and a glued -Huri or a
// bundled -xHuri is hidden from the target extractor's flag handling. There is
// no exec or plugin option, and no long options (`--x` is an illegal option).
// -H and -h are mutually exclusive.
//
// snmpwalk (net-snmp 5.6.2.1, confirmed against the local binary): any
// `--name=value` long option is applied as an snmp.conf directive, so
// `--mibfile=/etc/hosts` reads a file and `--includeFile` includes one. -Lf FILE
// (also glued and bundled: -dLflog) creates and writes a log file. -m FILE and
// -M DIR load MIB files from arbitrary paths (a parse error prints the file
// contents' line, so -m /etc/hosts is a read primitive). -C is application
// options (p, i, I, c, t, E), not a config file. The agent is a positional; no
// host flag exists (-h is help).
//
// onesixtyone (source options -c -i -o -d -w -q): -i reads scan targets from a
// file, which the scope check never sees and which a scratch file planted with
// another tool could fill, so it is denied. -c reads the community strings
// from a file and sends them to the target, and -o writes a log, so both are
// bounded to the scratch dir. The host is a positional.
//
// Every dashed flag with a value takes it as a separate token in the benign
// cases, so ExtractTargets sees each target.

var netEnumDeniedSpellings = []struct {
	name string
	args []string
}{
	// ldapsearch -y (password file)
	{"ldapsearch", []string{"-x", "-y", "pw", "-H", "ldap://10.0.0.5"}},
	{"ldapsearch", []string{"-x", "-ypw", "-H", "ldap://10.0.0.5"}},
	{"ldapsearch", []string{"-xy", "pw", "-H", "ldap://10.0.0.5"}},
	{"ldapsearch", []string{"-LLLy", "pw", "-H", "ldap://10.0.0.5"}},
	{"ldapsearch", []string{"-y", "/etc/passwd", "-H", "ldap://10.0.0.5"}},
	// ldapsearch -h (server outside a URL)
	{"ldapsearch", []string{"-x", "-h", "10.0.0.5"}},
	{"ldapsearch", []string{"-x", "-h", "dc01"}},
	{"ldapsearch", []string{"-x", "-hevil.com"}},
	{"ldapsearch", []string{"-xh", "10.0.0.5"}},
	{"ldapsearch", []string{"-xhevil.com"}},
	{"ldapsearch", []string{"-x", "-h=evil.com"}},
	// ldapsearch -t / -tt (files in an uncontrolled temp dir)
	{"ldapsearch", []string{"-x", "-t", "-H", "ldap://10.0.0.5"}},
	{"ldapsearch", []string{"-x", "-tt", "-H", "ldap://10.0.0.5"}},
	{"ldapsearch", []string{"-xt", "-H", "ldap://10.0.0.5"}},
	{"ldapsearch", []string{"-LLLt", "-H", "ldap://10.0.0.5"}},
	// ldapsearch -C (referral chasing)
	{"ldapsearch", []string{"-x", "-C", "-H", "ldap://10.0.0.5"}},
	{"ldapsearch", []string{"-xC", "-H", "ldap://10.0.0.5"}},
	// ldapsearch glued or bundled -H
	{"ldapsearch", []string{"-x", "-Hldap://evil.com"}},
	{"ldapsearch", []string{"-xHldap://evil.com"}},
	{"ldapsearch", []string{"-LLLxHldap://10.0.0.5"}},
	{"ldapsearch", []string{"-x", "-H=ldap://evil.com"}},
	{"/usr/bin/ldapsearch", []string{"-x", "-y", "pw"}},
	// snmpwalk long options (arbitrary snmp.conf directives)
	{"snmpwalk", []string{"--includeFile=/etc/passwd", "10.0.0.5"}},
	{"snmpwalk", []string{"--mibfile=/etc/hosts", "10.0.0.5"}},
	{"snmpwalk", []string{"--persistentDir=x", "10.0.0.5"}},
	{"snmpwalk", []string{"--mibfile", "/etc/hosts", "10.0.0.5"}},
	{"snmpwalk", []string{"10.0.0.5", "--help"}},
	{"snmpwalk", []string{"10.0.0.5", "--x"}},
	// snmpwalk -L (log file, also glued and bundled)
	{"snmpwalk", []string{"-Lf", "log", "10.0.0.5"}},
	{"snmpwalk", []string{"-Lflog", "10.0.0.5"}},
	{"snmpwalk", []string{"-L", "f", "log", "10.0.0.5"}},
	{"snmpwalk", []string{"-dLf", "log", "10.0.0.5"}},
	{"snmpwalk", []string{"-dLflog", "10.0.0.5"}},
	{"snmpwalk", []string{"-Le", "10.0.0.5"}},
	{"snmpwalk", []string{"-LS", "0-7", "d", "10.0.0.5"}},
	// snmpwalk -m / -M (MIB files and directories)
	{"snmpwalk", []string{"-m", "/etc/hosts", "10.0.0.5"}},
	{"snmpwalk", []string{"-m+/etc/hosts", "10.0.0.5"}},
	{"snmpwalk", []string{"-mALL", "10.0.0.5"}},
	{"snmpwalk", []string{"-dm", "x", "10.0.0.5"}},
	{"snmpwalk", []string{"-M", "/etc", "10.0.0.5"}},
	{"snmpwalk", []string{"-M+/etc", "10.0.0.5"}},
	{"snmpwalk", []string{"-dM", "x", "10.0.0.5"}},
	{"/usr/bin/snmpwalk", []string{"-Lf", "log", "10.0.0.5"}},
	// onesixtyone -i (targets from a file)
	{"onesixtyone", []string{"-i", "hosts"}},
	{"onesixtyone", []string{"-ihosts"}},
	{"onesixtyone", []string{"-di", "hosts"}},
	{"onesixtyone", []string{"-qi", "hosts", "-o", "out"}},
	{"onesixtyone", []string{"-i", "-"}},
}

func TestNetEnumDeniedFlagsEverySpelling(t *testing.T) {
	for _, tc := range netEnumDeniedSpellings {
		d := Classify(Command{Binary: tc.name, Args: tc.args})
		if d.Allowed {
			t.Errorf("Classify(%q %v) allowed a denied flag", tc.name, tc.args)
		}
	}
}

func TestNetEnumBenignInvocationsAllowed(t *testing.T) {
	benign := []Command{
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldap://10.0.0.5", "-b", "dc=corp,dc=example", "-s", "base"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-LLL", "-H", "ldaps://corp.example:636", "(objectClass=*)", "cn"}},
		{Binary: "ldapsearch", Args: []string{"-xLLL", "-H", "ldap://10.0.0.5", "-D", "cn=admin,dc=corp,dc=example", "-w", "pw"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldap://10.0.0.5", "-ZZ", "-l", "10", "-z", "5"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldap://10.0.0.5", "-f", "queries", "-T", "out"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldap://10.0.0.5", "-E", "pr=100/noprompt", "-o", "ldif-wrap=no"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "10.0.0.5"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "10.0.0.5", ".1.3.6.1.2.1.1"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "-On", "-Cp", "10.0.0.5:161", "system"}},
		{Binary: "snmpwalk", Args: []string{"-v3", "-l", "authPriv", "-u", "bert", "-a", "SHA", "-A", "authpass", "-x", "AES", "-X", "privpass", "10.0.0.5"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "-r", "1", "-t", "2", "-Oqv", "corp.example", "sysDescr"}},
		{Binary: "onesixtyone", Args: []string{"10.0.0.5", "public"}},
		{Binary: "onesixtyone", Args: []string{"-c", "communities", "10.0.0.5"}},
		{Binary: "onesixtyone", Args: []string{"-c", "communities", "-o", "out", "-w", "50", "10.0.0.5"}},
		{Binary: "onesixtyone", Args: []string{"-dd", "-q", "-o", "out", "10.0.0.5", "public"}},
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

func TestNetEnumFilePathsBounded(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"ldapsearch", []string{"-f", "/tmp/x"}},
		{"ldapsearch", []string{"-f/tmp/x"}},
		{"ldapsearch", []string{"-f", "../x"}},
		{"ldapsearch", []string{"-xf", "/x"}},
		{"ldapsearch", []string{"-LLLf../x"}},
		{"ldapsearch", []string{"-T", "/tmp"}},
		{"ldapsearch", []string{"-T../x"}},
		{"ldapsearch", []string{"-xT", "/x"}},
		{"onesixtyone", []string{"-c", "/etc/passwd", "10.0.0.5"}},
		{"onesixtyone", []string{"-c/etc/passwd", "10.0.0.5"}},
		{"onesixtyone", []string{"-c", "../x", "10.0.0.5"}},
		{"onesixtyone", []string{"-dc", "/x", "10.0.0.5"}},
		{"onesixtyone", []string{"-o", "/tmp/x", "10.0.0.5"}},
		{"onesixtyone", []string{"-o../x", "10.0.0.5"}},
		{"onesixtyone", []string{"-qo", "/x", "10.0.0.5"}},
	} {
		if arg, bad := FileAccessViolation(Command{Binary: tc.name, Args: tc.args}); !bad {
			t.Errorf("FileAccessViolation(%q %v) allowed a path escape", tc.name, tc.args)
		} else if arg == "" {
			t.Errorf("FileAccessViolation(%q %v) must report the offending arg", tc.name, tc.args)
		}
	}
}

func newEnumGate(t *testing.T, bins ...string) *Gate {
	t.Helper()
	scope, err := ParseScope(strings.NewReader("10.0.0.0/24\ncorp.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Auto, Scope: scope, Allow: NewAllowlist(bins...)}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	return g
}

// A glued or bundled -H value is denied before the scope check, and the -h
// server flag is denied outright so a single-label host cannot skip the check.
func TestNetEnumGluedAndServerFlagsDeniedByGate(t *testing.T) {
	g := newEnumGate(t, "ldapsearch")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-x", "-Hldap://evil.com"}, "glues or bundles"},
		{[]string{"-x", "-Hldap://10.0.0.5"}, "glues or bundles"},
		{[]string{"-xHldap://evil.com"}, "glues or bundles"},
		{[]string{"-x", "-hevil.com"}, "not permitted"},
		{[]string{"-x", "-h", "dc01", "ldap://10.0.0.5"}, "not permitted"},
		{[]string{"-x", "-H", "ldap://10.0.0.5", "-h", "evil.com"}, "not permitted"},
	} {
		d := g.Authorize(context.Background(), Command{Binary: "ldapsearch", Args: tc.args})
		if d.Allowed {
			t.Errorf("Authorize(ldapsearch %v) allowed a hidden server", tc.args)
		} else if !strings.Contains(d.Reason, tc.want) {
			t.Errorf("Authorize(ldapsearch %v) denied for the wrong reason: %q", tc.args, d.Reason)
		}
	}
}

// Every target form is scope-checked: separate flag values, URIs, transport
// prefixes, single-label and unix-socket agents, and CIDR ranges.
func TestNetEnumOutOfScopeTargetsDeniedByGate(t *testing.T) {
	g := newEnumGate(t, "ldapsearch", "snmpwalk", "onesixtyone")
	for _, c := range []Command{
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldap://evil.com"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldaps://8.8.8.8:636"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldap://dc01"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldap://10.0.0.5", "-H", "ldap://evil.com"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldap://10.0.0.5 ldap://evil.com"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldap://10.0.0.5,ldap://evil.com"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldapi:///var/run/slapd/ldapi"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldapi://%2Fvar%2Frun%2Fldapi"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldap:///"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "dc01", "10.0.0.5"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-H"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-b", "dc=corp,dc=example"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "8.8.8.8"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "evil.com", "system"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "10.0.0.5", "evil.com"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "8.8.8.8:161"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "udp:8.8.8.8:161"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "unix:/tmp/sock"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "10.0.0.0/24"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "1.3.6.1.2.1"}},
		{Binary: "onesixtyone", Args: []string{"8.8.8.8", "public"}},
		{Binary: "onesixtyone", Args: []string{"evil.com", "public"}},
		{Binary: "onesixtyone", Args: []string{"-c", "communities", "8.8.8.8"}},
		{Binary: "onesixtyone", Args: []string{"10.0.0.0/24", "public"}},
		{Binary: "onesixtyone", Args: []string{"10.0.0.1-50", "public"}},
		{Binary: "onesixtyone", Args: []string{"-c", "communities"}},
	} {
		d := g.Authorize(context.Background(), c)
		if d.Allowed {
			t.Errorf("Authorize(%q %v) allowed an out-of-scope or unverifiable target", c.Binary, c.Args)
		}
	}
}

func TestNetEnumGateAllowsBenignInScope(t *testing.T) {
	g := newEnumGate(t, "ldapsearch", "snmpwalk", "onesixtyone")
	for _, c := range []Command{
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldap://10.0.0.5", "-b", "dc=corp,dc=example", "-s", "base"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-LLL", "-H", "ldaps://corp.example:636", "(objectClass=*)", "cn"}},
		{Binary: "ldapsearch", Args: []string{"-x", "-H", "ldap://10.0.0.5", "-f", "queries", "-T", "out"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "10.0.0.5"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "10.0.0.5:161", ".1.3.6.1.2.1.1"}},
		{Binary: "snmpwalk", Args: []string{"-v2c", "-c", "public", "-On", "corp.example", "system"}},
		{Binary: "onesixtyone", Args: []string{"10.0.0.5", "public"}},
		{Binary: "onesixtyone", Args: []string{"-c", "communities", "-o", "out", "10.0.0.5"}},
	} {
		if d := g.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("Authorize(%q %v) denied a benign in-scope command: %q", c.Binary, c.Args, d.Reason)
		}
	}
}

// The audit rules are bounded to their own binaries: another tool may use the
// same letters freely.
func TestNetEnumRulesBounded(t *testing.T) {
	for _, c := range []Command{
		{Binary: "nbtscan", Args: []string{"-v", "-t", "500", "10.0.0.5"}},
		{Binary: "curl", Args: []string{"-i", "-m", "5", "http://10.0.0.5/"}},
		{Binary: "host", Args: []string{"-t", "mx", "corp.example"}},
		{Binary: "nmap", Args: []string{"-p", "80", "-M", "10", "10.0.0.5"}},
	} {
		if d := Classify(c); !d.Allowed {
			t.Errorf("Classify(%q %v) denied: %q", c.Binary, c.Args, d.Reason)
		}
	}
}
